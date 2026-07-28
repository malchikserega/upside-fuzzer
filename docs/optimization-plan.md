# UpsideFuzz — Optimization & Modernization Plan

**Status:** living document for this optimization pass. Written before implementation; the companion
[`optimization-report.md`](optimization-report.md) records what was actually done, measured, and validated.

**Scope note, stated up front:** this is a ~22,000-line polyglot project (Go engine, two Python packages,
two C# tools) with real engineering maturity already behind it — see the baseline in §3. A "comprehensive
optimization of the entire project" at the scope a large team would do over weeks is not honestly
achievable in one pass without either (a) inventing problems to justify busywork, or (b) making large,
unverified changes to a security tool whose correctness matters more than almost anything else about it.
This plan therefore prioritizes **verified, evidence-backed changes** or a documented list of overreach
that was surfaced and correctly did not need fixing over a wide, shallow sweep. Every claim below is
either measured (baseline command + result) or explicitly marked as a recommendation for future work.

---

## 1. Architecture Summary

UpsideFuzz is a coverage-guided REST API fuzzer for .NET web APIs. Three loosely-joined subsystems,
each in the language best suited to it, communicating through files and HTTP rather than a shared
in-memory model:

1. **Prep / instrumentation** (`fuzz-prep-multi.py` → `fuzzprep/`, Python) — scans a .NET solution,
   adapts or generates its Dockerfile/compose files, and wires in zero-source-edit coverage
   instrumentation (`DOTNET_STARTUP_HOOKS` + an ASP.NET hosting-startup assembly) without modifying
   the target's own `Program.cs`/`Startup.cs`/`.csproj`.
2. **Grammar compilation** (`grammarc/`, Python stdlib-only + `dotnet/analyzer/`, C#/Roslyn) — parses
   the target's OpenAPI spec into a typed request grammar, optionally merges in real per-property C#
   validation constraints extracted via a Roslyn syntax-tree pass, and writes `templates.export.json`
   + `dict.json`.
3. **The fuzzing engine** (`void/go/`, Go) — the actual runtime: an epoch-scheduled, MOpt-style mutation
   engine, a stateful producer/consumer sequence engine, coverage-bitmap reading (SHM mmap or HTTP),
   vulnerability oracles (BOLA/IDOR, mass assignment, differential auth bypass, positive injection,
   schema conformance), and crash triage/clustering/reporting.

A fourth component, `dotnet/instrumentor/` (C#, Mono.Cecil), does the actual IL rewriting: injecting
SharpFuzz coverage probes, an optional CmpLog comparison-operand recorder, and a static constant
extractor into the target's compiled DLLs as a Docker build step.

Full internals: [`ARCHITECTURE.md`](ARCHITECTURE.md). Candid strengths/gaps roadmap:
[`ARCHITECTURE_REVIEW.md`](ARCHITECTURE_REVIEW.md). From-scratch explainer:
[`WHITEPAPER.md`](WHITEPAPER.md).

## 2. Component Map

| Component | Language | LOC | Role | Hot path? |
|---|---|---|---|---|
| `void/go/` | Go | ~15,600 | The fuzzing engine — scheduling, mutation, HTTP, coverage reading, oracles, triage | **Yes** — target is 1,000+ req/s |
| `grammarc/` | Python (stdlib) | ~2,700 | OpenAPI → typed grammar compiler | No — one-shot CLI, runs once per target |
| `fuzzprep/` (+ `fuzz-prep-multi.py`) | Python | ~3,000 | Solution scan, Dockerfile/compose generation, instrumentation wiring | No — one-shot CLI, runs once per target |
| `dotnet/analyzer/` | C# (net9.0) | ~1,100 | Roslyn syntax-tree constraint/route/auth extraction | No — one-shot CLI |
| `dotnet/instrumentor/` | C# (net8.0) | ~760 | Mono.Cecil IL rewriting (coverage probes, CmpLog, constant extraction) | Runs once per Docker build (build-time, not request-time), but does per-method/per-instruction work across the *entire* target assembly, so its own internal loops matter for large targets (e.g. Bitwarden) |
| `demo_app/` | C# | — | In-repo flagship demo/pedagogical target (26 endpoints, 24 planted bugs) | N/A — test fixture, not optimized for perf |
| `fixtures/planted-bug-api/` | C# | — | Minimal CI regression fixture | N/A — test fixture |

**Public/compatibility-sensitive interfaces** (changes here are compatibility risks, not just refactors):
- `templates.export.json` / `dict.json` schema (Python writes, Go reads)
- `roslyn-constraints.json` schema (C# analyzer writes, Python `roslyn_merge.py` reads)
- The `/shm/*` HTTP contract (`/shm/create`, `/shm/coverage`, `/shm/reset`, `/shm/health`, `/shm/cmplog`,
  `/shm/constants`) and the `X-Coverage-Delta`/`X-Exception-Type`/`X-Exception-Message`/`X-Fuzz-Request-Id`
  headers — generated C# runtime writes, Go engine reads
- `void`'s CLI flags (90+, documented in `void/README.md`) and its `unique-crashes-*.jsonl`/`summary.json`
  report schemas — consumed by CI (`scripts/e2e-test.sh`) and by users' own tooling
- `auth.identities.json` schema (user-authored, read by Go)
- `dict.custom.json` convention (user-authored, never overwritten, merged every run)

## 3. Critical Execution Paths

1. **Instrument → build**: `fuzz-prep-multi.py` scans the solution → generates/adapts Dockerfile+compose
   → `docker compose build` runs `dotnet/instrumentor/` as a build stage over every business-logic DLL.
2. **Grammar compile**: `compile-grammar.sh` → optional `dotnet/analyzer/` pass over `--src` → `grammarc/`
   parses the OpenAPI spec, merges constraints, writes the two JSON artifacts. One-shot, not
   performance-critical, but its *correctness* gates everything downstream.
3. **The fuzz loop** (the actual hot path): `void`'s worker pool renders a template → mutates it →
   sends the HTTP request → reads the coverage delta (mmap or header) → updates seed energy / mutation
   category weights → repeats, at target throughput of 1,000+ req/s and configurable concurrency
   (`-concurrency`, default 10, commonly raised to 32–64).
4. **Oracle replay**: on a qualifying successful request, `oracle.go` fires additional cross-identity/
   no-credential/mass-assignment/differential replay requests — a secondary hot path riding on top of
   the primary one.
5. **Crash triage/report**: on any 5xx, `crash.go`/`cluster.go`/`triage.go`/`minimize.go`/`poc.go` do
   dedup, clustering, scoring, minimization, and PoC generation — not in the per-request hot path, but
   triggered frequently enough during a productive run that its cost is non-trivial.

## 4. Baseline (measured before any change — see §8 for exact commands)

| Check | Result |
|---|---|
| `go build ./...` (void/go) | Clean |
| `go vet ./...` (void/go) | Clean |
| `go test ./... -race` | **Pass** — 151 test cases (subtests), 0 failures, race-clean |
| `go test ./... -cover` | 32.0% statement coverage |
| `gofmt -l .` (void/go) | 9 files flagged — cosmetic realignment only (verified via `gofmt -d`), no semantic diff |
| `python3 -m unittest` (grammarc, 8 suites) | **80/80 pass** |
| `python3 -m unittest test_fuzz_prep_multi` | **20/20 pass** |
| `./scripts/test-compile-grammar-cli.sh` | **All checks pass** |
| `dotnet test dotnet/instrumentor.Tests/` | **56/56 pass**; 2× `CS8632` nullable-context warnings in `Program.cs` |
| `dotnet test dotnet/analyzer.Tests/` | **44/44 pass**, no warnings |
| Lint/static-analysis config in repo | **None exists** (no `.golangci.yml`, no `pyproject.toml`/`ruff`/`mypy` config) — nothing pre-configured to run |

**Read on this baseline:** this is a healthy, well-tested codebase, not a neglected one. 351 total
test cases pass across three languages with zero failures and zero data races detected. This
materially changes the shape of a responsible "optimization pass" — the highest-value work here is
verified, narrow fixes (a real TFM inconsistency, dead code, a couple of nullable-warning sources,
targeted new tests for currently-0%-covered pure functions, missing benchmarks on the actual hot
path) rather than a wide rewrite.

## 5. Problems, Risks, and Proposed Changes

A parallel deep-dive investigation (four independent agents, one per Go/Python/C#/CI, each required
to back every finding with a file:line citation and forbidden from padding the list) surfaced the
following, all subsequently fixed and re-validated. Full before/after detail, measurements, and the
handful of findings that were investigated and deliberately **not** changed (with reasoning) are in
[`optimization-report.md`](optimization-report.md) — this section is the plan-level summary.

**Go (`void/go/`) — fixed:**
1. HTTP response bodies weren't drained to EOF before `Close()` when truncated at `maxBytes`, defeating
   the `Transport`'s connection-pool reuse at the project's own stated 1,000+ req/s target — **[HIGH,
   measurable performance]**.
2. `printFinalReport` silently swallowed `os.WriteFile` errors for the summary/report/SARIF files —
   a run could finish, print success, and never actually have written its findings — **[HIGH,
   reliability]**.
3. A single shared `chan WebUIStats` fanned updates out to *one* of several concurrently-connected Web
   UI clients instead of all of them (Go channel receive semantics) — **[MEDIUM-HIGH, correctness]**.
4. `RuntimeStore.customPayloadCandidates` recomputed `allIDLikeValues()` (a full map scan + rebuild)
   4 times per call where the result was identical each time — **[HIGH, measurable performance]**.
5. Four confirmed-dead functions (`mutateString`, `FenwickSampler.Len`, `extractCookieValue`,
   `contains`) — zero references anywhere, verified by grep and independently by `deadcode`.
6. A per-request identity-weight slice was reallocated every call instead of reusing a buffer, unlike
   the equivalent, already-buffer-reusing pattern for template selection.
7. A non-blocking select-with-`default` whose default branch fell through to an identical blocking
   select over the same four cases — fully redundant, simplified to one blocking select.
8. Two no-op `break` statements inside `select` cases (harmless but misleading).
9. The shutdown drain deadline (fixed 2s) was shorter than the default `-request-timeout` (5s), so
   legitimately-in-flight (not stuck) requests could be silently dropped from the final report.
10. `gofmt` realignment across 9 files (cosmetic only).

**C# (`dotnet/`) — fixed:**
11. `instrumentor.csproj` was missing `<Nullable>enable</Nullable>`, the sole cause of 2 `CS8632`
    warnings — verified fix produces 0 warnings.
12. `dotnet/analyzer/` targeted `net9.0` while `dotnet/instrumentor/` targeted `net8.0`, inconsistent
    with the project's own ".NET 8+" stated support and (per the CI investigation) a real risk once
    .NET 9 ages out of default CI runner images. Bumped analyzer + analyzer.Tests to `net8.0`, verified
    no net9-only API usage anywhere in either project. **Discovered and fixed in the same step**: this
    machine has no net8.0 runtime installed at all, so analyzer.Tests needed the same `RollForward:
    Major` setting `instrumentor.Tests` already carried, to actually run locally.
13. `Program.Generated.cs` — confirmed zero references anywhere in the repo (both code and docs already
    disclaimed it as dead); deleted.
14. `FlattenNestedTypes` was defined identically, twice, in `CmpLogInstrumentor` and `ConstantExtractor`;
    extracted to a shared `IlUtil` helper.
15. One instrumentation-metadata write used hand-rolled JSON string concatenation (correctly escaping
    only `"`, not backslashes/control characters) where every other write site in the same file already
    used `System.Text.Json.JsonSerializer.Serialize` — made consistent.

**Python (`grammarc/`, `fuzzprep/`) — fixed:**
16. `cli.py::_build_dict_pool` walked the same operation's request-schema fields twice (once filtered,
    once unfiltered) via `_collect_schema_fields`, a recursive `$ref`/`allOf`/`oneOf`/`anyOf`-resolving
    walk — computed once, reused.
17. `coverage_helper_gen.py::generate_multi_coverage_helper` re-derived and re-`.exists()`-stat'd the
    same two candidate directories a second time at the bottom of the function instead of reusing the
    decision already made at the top.
18. Two function-local `import` statements (in `body_serializer.py` and `oas.py`) for names already
    available at module scope — moved to the top-level import.
19. A silent `except Exception: continue` when reading a `.cs` file for namespace detection — now logs
    via `self.log(...)`, consistent with this module's own stated philosophy of never silently dropping
    a detection edge case.
20. `MultiProjectAnalyzer.exclude_namespaces` was only ever set via an ad-hoc external
    `analyzer.exclude_namespaces = [...]` attribute assignment from `cli.py`, requiring a defensive
    `getattr(self, 'exclude_namespaces', [])` fallback everywhere it was read — now a real, typed
    `__init__` field.
21. `merge_external_dict`'s JSON-parse-failure path was completely silent for both of its callers.
    Added an opt-in `warn_on_parse_error` parameter: stays silent for the always-on `dict.custom.json`
    convention merge (by design — that file may legitimately not exist yet), now warns for an explicit,
    user-supplied `--dict <path>` that fails to parse.
22. Two genuinely dead functions (`grammarc/oas.py::all_fields`, `grammarc/common.py::canonicalize_payload_key`)
    — zero callers anywhere in the repo — deleted.

**CI/tooling — fixed:**
23. `actions/setup-go@v5`'s default cache-dependency lookup expects `go.sum` at the repo root; this
    repo's lives at `void/go/go.sum`. Added an explicit `cache-dependency-path`.
24. (Side effect of #12) CI's `dotnet-version: '8.0.x'` pin, which only worked because analyzer's
    `net9.0` requirement happened to be satisfiable from the runner's toolcache, is no longer running on
    borrowed time now that analyzer itself targets `net8.0`.

**Investigated and deliberately left unchanged** (with reasoning — see the report for detail): adding a
NuGet package-cache step to CI (would require lock files that don't exist yet and currently isn't safe
to add blindly); `TypeResolver.Resolve`'s O(N) short-name fallback in `dotnet/analyzer/` (real but
conditional on target codebase size/naming, and a fix risks subtly changing disambiguation
tie-breaking — flagged as recommended future work instead); full `context.Context` cancellation
plumbing through the Go engine's request path (the deeper, correct fix behind finding #9 — the shutdown
drain deadline fix is the safe, minimal version of this); Docker layer caching in `void/Dockerfile.go`/
`Dockerfile.cli` (already correct); `demo_app/Dockerfile`'s `COPY`-before-`restore` ordering (deliberately
simple/pedagogical, not a build-speed target).

## 6. Compatibility Considerations

- The three cross-language file contracts (`templates.export.json`, `dict.json`, `roslyn-constraints.json`)
  and the `/shm/*` HTTP contract are treated as frozen interfaces for this pass — no field renames,
  no removed fields, unless a genuine bug requires it (in which case: documented, with a migration
  note, per the task's own compatibility rules).
- `void`'s CLI flags are treated as a frozen public interface — no flag removed or renamed without a
  documented deprecation path.
- Any dead-code removal is preceded by a repo-wide grep confirming zero references, not a visual
  read alone.

## 7. Validation Strategy

For every change: re-run the specific baseline check(s) it touches (the relevant `go test`/`dotnet test`/
`python3 -m unittest` invocation), plus the full baseline suite once at the end of the pass, and diff
the final state against §4 to catch regressions. Any new benchmark is run at least 3 times and reported
with the sampling method, per the task's own benchmark-honesty requirement. See `optimization-report.md`
for the actual final numbers.

## 8. Baseline Commands (for reproducibility)

```bash
# Go
cd void/go && go build ./... && go vet ./... && gofmt -l .
go test ./... -race
go test ./... -cover

# Python
python3 -m unittest grammarc.test_oas grammarc.test_boundary grammarc.test_body_serializer \
  grammarc.test_dependencies grammarc.test_emit_dict grammarc.test_multipart \
  grammarc.test_response_schemas grammarc.test_roslyn_merge -v
python3 -m unittest test_fuzz_prep_multi -v
./scripts/test-compile-grammar-cli.sh

# C#
dotnet test dotnet/instrumentor.Tests/instrumentor.Tests.csproj
dotnet test dotnet/analyzer.Tests/analyzer.Tests.csproj
```
