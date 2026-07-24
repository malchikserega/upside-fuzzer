# UpsideFuzz: AI Context & Architecture Guidelines

**Welcome, fellow AI Assistant!**
If you are reading this, you are helping develop or debug the **UpsideFuzz** repository. This document contains the critical architectural context, constraints, and project rules you need to know to avoid breaking the system. It is kept current deliberately — if you notice it drifting from the code (check `git log` for anything after the date below), fix this file in the same change, don't just work around the drift.

*Last verified against the codebase: 2026-07-24 (post RESTler retirement, post constraint-aware mutation / CMPLOG-lite / E2E CI, post self-verifying fail-closed instrumentation, post single-CLI orchestrator).*

---

## 1. Project Identity & Purpose

UpsideFuzz is a **coverage-guided, grey-box REST API fuzzer for .NET**, built to find real, exploitable bugs — not just crashes. It instruments a target .NET web API with SharpFuzz IL rewriting (real basic-block edge coverage, not black-box guessing), compiles a request grammar directly from the target's OpenAPI spec plus (optionally) real per-field C# validation constraints extracted by a Roslyn syntax-tree analyzer, then drives the target with a Go engine that mutates requests using live coverage feedback and runs positive vulnerability oracles (BOLA/IDOR, broken auth, mass assignment, injection) on top of ordinary crash detection.

For the reader-facing version of this explanation (why this approach, what problem it solves, aimed at humans not AI agents), see `docs/HOW_IT_WORKS.md`. This file is the terse, AI-agent-facing operational summary.

**RESTler is not part of this project anymore.** It was the original grammar compiler (external, black-box, Docker-packaged) and has been fully retired and replaced by first-party components (`grammarc/` + `analyzer/`, see §3). If you see RESTler mentioned in older docs, campaign reports, or code comments, treat it as historical unless the file explicitly says otherwise — do not reintroduce a RESTler dependency, and do not "fix" code to call `enhance-grammar.py` or `sanitize-swagger-for-restler.sh`: **both files were deleted**; they no longer exist in this repo.

---

## 2. Core Components & Tech Stack

The project is polyglot by design. Do not try to unify the languages. Each language serves a specific purpose:

| Directory / Component | Language | Purpose | Rules & Constraints |
|-----------------------|----------|---------|---------------------|
| `void/go/` | **Go** (1.22+) | The core execution engine. High-concurrency worker pool, coverage polling, seed mutations, crash triage, vulnerability oracles. | Keep it fast. Do NOT use heavy ORMs or blocking I/O in the main worker loop. Rely on `sync.RWMutex` sparingly. |
| `fuzz-prep-multi.py` | **Python** | Docker build-time instrumentation. Injects `SharpFuzz` into .NET target images via `instrumentor/`. Also generates the zero-edit `DOTNET_STARTUP_HOOKS` coverage-hook assembly. | Must support arbitrary .NET `csproj` layouts (single-project and multi-project solutions). Do not hardcode project names. |
| `analyzer/` | **C#** (.NET, `Microsoft.CodeAnalysis.CSharp`) | The **real** Roslyn syntax-tree analyzer. Parses the target's `.cs` files and extracts per-*type-and-property*-scoped validation constraints (`[StringLength]`, `[Range]`, `[RegularExpression]`, FluentValidation chains, enum declarations) plus `[Authorize]`/route metadata. Syntax-tree only — no `MSBuildWorkspace`/NuGet-restore semantic model, a deliberate scoping choice for reliability across arbitrary target repos, not an oversight. | Constraints must stay keyed by `(fully-qualified type, property)`, never a bare property name — that was the exact bug the old regex-based `enhance-grammar.py` had (see §4). |
| `grammarc/` | **Python** (stdlib-only) | The first-party OpenAPI → typed-grammar compiler. Parses the OpenAPI/Swagger spec directly, merges in `analyzer/`'s Roslyn constraints (Roslyn wins per-field on a scoped match), infers producer/consumer id relationships by path/name convention, synthesizes boundary values, and writes `templates.export.json` + `dict.json` **directly** — no intermediate `grammar.py`, no RESTler, no Docker for this step. | Keep it stdlib-only (matches the rest of the repo's zero-third-party-dependency convention for this pipeline) unless there's a strong reason not to. |
| `instrumentor/` | **C#** (.NET 8) | The generic SharpFuzz IL byte-code rewriter. | Supports two modes: a `namespaces.json` allowlist (substring match via `fullName.Contains`) OR `--instrument-all-user-code` (rewrite every non-framework/non-generated type). **Prefer `--instrument-all-user-code`** — the allowlist silently drops any namespace not listed (this is how Bitwarden's `Bit.Commercial.*` Secrets Manager code fell out of coverage before). `fuzz-prep-multi.py` now auto-selects it whenever no root namespace collides with the hardcoded framework-prefix denylist. Always run `verify-hook.sh` (root) or `verify_coverage.sh` (per-target) after bring-up to confirm edges are actually recorded — never assume instrumentation worked just because the build succeeded. |
| `upsidefuzz.py` | **Python** | Single CLI orchestrator (Top-20 #19): subcommands `instrument`/`build`/`up`/`down`/`verify`/`grammar`/`fuzz`/`run`/`doctor` wrapping the pipeline above behind one tool. `Dockerfile.cli` + the `upsidefuzz` launcher script give a zero-install (Docker-only) way to run it. | Thin `subprocess` wrapper only — see §4's "never a reimplementation" rule. |

---

## 3. How the Pieces Fit Together (The Pipeline)

When a user targets a new API, the exact flow is:

1. `fuzz-prep-multi.py` creates an instrumented copy of the target repository (zero source edits by default, via `DOTNET_STARTUP_HOOKS`) and builds it via Docker.
2. `compile-grammar.sh <swagger.json> [--src <source_dir>] [--out <dir>]` — **one command**, no Docker involved in this step:
   - if `--src` is given, runs `analyzer/` over the source tree, producing `roslyn-constraints.json`;
   - then runs `grammarc/` (`python3 -m grammarc.cli`), which parses the OpenAPI spec, merges in the Roslyn constraints, infers dependencies, and writes `templates.export.json` + `dict.json` straight into `--out`.
3. `void` (the Go engine) loads `templates.export.json`/`dict.json` directly (JSON, not a Python module — `template.go` just `json.Unmarshal`s it), starts the fuzzing loop (Baseline → Deterministic → Havoc → Splicing), and polls the SHM bitmap for coverage.

There is **no manual `cp` step and no separate template-export step** in the current pipeline — `compile-grammar.sh` writes the final artifacts directly. (`void/export-templates.py`, which used to convert an old-format `grammar.py` into JSON, still exists but only as a legacy fallback Void auto-invokes if it ever finds a `grammar.py` with no matching `templates.export.json` next to it — i.e., only for grammar directories generated before this migration and not yet regenerated. Don't route new work through it.)

---

## 4. Critical Architectural Decisions (DO NOT REVERT)

- **RESTler is gone, not "a dependency."** The grammar compiler is entirely first-party now (`grammarc/` + `analyzer/`). Do not reintroduce RESTler, Docker-based grammar compilation, or a `grammar.py` Python-module intermediate as the primary path. If you're tempted to "just call RESTler for this one edge case," don't — extend `grammarc/oas.py`/`body_serializer.py` instead.
- **Grammar constraints are type/property-scoped, not global-name-scoped.** This was a real, previously-shipped bug: the old regex-based `enhance-grammar.py::SourceExtractor` merged constraints by a *globally canonicalized property name*, so `[StringLength(50)] Name` on one DTO would silently constrain every `name`-shaped field in the entire app — confirmed for real on eShopOnWeb, which has two unrelated classes both named `CreateCatalogItemRequest` (one real API DTO with no constraints, one unrelated UI model with real `[Required]`/`[Range]`). `analyzer/` fixes this by construction: constraints are keyed by `(fully-qualified type, property)`. If you touch `analyzer/ConstraintWalker.cs`/`roslyn_merge.py`, do not regress this back to a bare-name lookup.
- **`payload_key`, not `name`, is the JSON field for `custom_payload` segments.** Another real, previously-shipped bug: `export-templates.py`'s old emitter wrote JSON key `"name"` for `custom_payload` segments, but `void/go/types.go`'s `Segment` struct and `template.go`'s rendering switch read only `PayloadKey` (JSON key `"payload_key"`) — meaning producer→consumer value substitution (harvested IDs, correlated values, dictionary lookups) silently never worked for the entire lifetime of the RESTler-based pipeline. `grammarc/emit_templates.py` emits `"payload_key"` directly now. If you ever add a new segment-emission path, use `"payload_key"`, never `"name"`.
- **Two Coverage Modes:** SHM coverage is collected either via a direct file-backed mmap (`/coverage_shm/bitmap` — fastest, requires Docker volume, `-direct-shm`) or via an injected HTTP endpoint (`/shm/coverage`) within the target's ASP.NET middleware (host mode, no Docker volume needed). Void supports both.
- **Coverage is AFL-style bucketed, not binary edge-presence.** `coverage.go::countClass`/`GetEdges` and `CoverageExtensions.cs::CountClass`/`MergeAndCountNovel` classify each edge's hit count into log-scale buckets (1, 2, 3, 4-7, 8-15, ...), so a loop executing 1 vs. 5000 times produces different, novel coverage. Attribution is single-scan, first-observer-wins per request (no double-counting under concurrency, no double full-bitmap scan).
- **Structure-aware, constraint-blended mutation.** `Segment` (`types.go`) carries optional per-field constraint metadata (`min_length/max_length/minimum/maximum/pattern/enum_values`), sourced from `grammarc/oas.py::FieldHint` (OpenAPI + Roslyn-merged) and emitted by `grammarc/body_serializer.py`. `mutation_engine.go`'s `mutateAny`/`mutateHavoc`/`mutateInt`/`mutateNumber`/`mutateStringCategorized` all take an optional `*Segment` hint and blend field-derived boundary candidates (`{min-1,min,min+1,max-1,max,max+1}`, exact-length strings, enum near-misses) into the existing generic pools — **additive, never a replacement**: a nil hint (old grammars, or fields with no declared constraint) behaves exactly as before. Don't make hint-handling required/non-nilable anywhere in this chain.
- **400-body responses feed the runtime dictionary automatically (CMPLOG-lite).** `worker.go::mineClientErrorFields` parses ASP.NET's `{"errors":{"Field":["msg"]}}` ValidationProblemDetails/ModelState shape (plus free-text `"must be one of [...]"` phrasing) out of every 4xx response body and feeds extracted field→value pairs into `RuntimeStore.addValue` — the same pool `custom_payload` rendering already draws from. This used to be write-only data (only fed the human-readable `client_error_samples` report field); now it closes the loop. If you touch `recordClientErrorSample`, keep this call.
- **Stateful Dependencies:** Void tracks dynamic identifiers (like IDs created by POSTs to be used in GETs) two ways simultaneously: (1) the grammar's own `reads`/`writes` per template (from `grammarc/dependencies.py`'s path/name-convention inference), and (2) `sequence.go`'s own independent runtime re-derivation from path templates (`inferResourceIDKeyFromPath`, `extractEntityIDs`) — the latter means even a wrong/missing grammar-level inference degrades gracefully to same-path-family sequencing, not silence.
- **Bug oracles are not just 500s:** A reproducible HTTP 500 is a *robustness* signal, not proof of a vulnerability. `oracle.go` adds real security oracles that reuse existing machinery: (1) **access control** — after any successful resource-scoped request under an authenticated identity, the identical request is replayed under every *other* identity and with *no* credentials; a 2xx from a different/anonymous principal is a BOLA/IDOR or broken-authentication finding; (2) **mass assignment** — successful writes are re-sent with privileged fields over-posted (`isAdmin`, `role:"SuperAdmin"`, `permissions:["*"]`); a reflected injected field is a finding; (3) **positive injection** — time-based SQLi (latency delta on sleep payloads), evaluated SSTI (rare arithmetic markers like `{{1337*1337}}`→`1787569`), and reflected XSS. The mutation registry also has a `dotnet_deser` category (Json.NET `$type` gadgets). These findings are labeled `likely_vuln[_high]`; a bare 500 is only ever `confirmed_unhandled_exception` (see `triage.go`). See `docs/HOW_IT_WORKS.md` for a plain-language explanation of why this matters.
  - **Each oracle is independently flag-gated** (`-probe-bola`, `-probe-auth-bypass`, `-probe-mass-assign`) under the `-access-probe` master toggle. **Auth-bypass has a precondition**: it only fires on endpoints already observed rejecting unauthenticated access (401/403), tracked in `authRequiredEndpoints` (strength 2 = rejected an unauth caller → `likely_vuln_high`; strength 1 = rejected someone → `likely_vuln` + `needs_manual_verification`). This is what removes the public-endpoint false positive — do NOT remove it. `markAuthRequired` (worker.go 401/403 path) populates the map.
- **Production-mode exception capture:** The coverage middleware (generated by `fuzz-prep-multi.py`) short-circuits *fuzz-request* 500s (identified by `X-Fuzz-Request-Id`) and emits `X-Exception-Type` + `X-Exception-Message`, because the app's exception handler otherwise clears those headers before the middleware `finally` runs. Real traffic is unaffected. The Go engine reads both headers and feeds the message into `cluster.go`.
- **`upsidefuzz.py` is a thin orchestration layer, never a reimplementation.** Every subcommand (`instrument`/`build`/`up`/`down`/`verify`/`grammar`/`fuzz`/`run`) shells out to the existing, unmodified tool (`fuzz-prep-multi.py`, `docker compose`, `verify-hook.sh`, `compile-grammar.sh`, the `void` binary) via `subprocess.run` — it must never duplicate their logic. This is a hard requirement from how it was scoped: the native, manual, script-by-script workflow documented in `INSTRUCTIONS.md`/`QUICKSTART_*.md` must keep working byte-for-byte unchanged whether or not the CLI exists. If you extend a subcommand, extend the flag pass-through, don't inline new behavior into `upsidefuzz.py` itself. `Dockerfile.cli` + the `./upsidefuzz` launcher are a second, independent additive layer (zero-install via Docker) on top of the same script — don't couple `upsidefuzz.py`'s logic to running inside a container except via the one documented seam, `UPSIDEFUZZ_IN_CONTAINER`/`_containerize_url` (see below).
- **`_containerize_url` (`upsidefuzz.py`) is the one place `localhost` gets rewritten to `host.docker.internal`.** The CLI container and a target's instrumented containers are Docker *siblings* (both mounted via the host socket), not parent/child, so `localhost` inside the CLI container is never the host's `localhost`. This bit multiple real bugs while building it (see `docs/CLI.md` Troubleshooting) — if you add a new subcommand or flag that carries a URL the CLI itself will connect to (directly, or via an env var handed to a subprocess like `void`), route it through `_containerize_url` too, or it will silently fail (or silently succeed against the wrong thing) only in Docker mode, not natively — the kind of bug that's easy to miss because native mode always works.
- **`compile-grammar.sh`'s relative-path handling must stay caller-cwd-relative, not script-location-relative.** Real bug, found via the CLI's own Docker-mode smoke test (2026-07-24): the script's `python3 -m grammarc.cli` invocation runs `cd "$ROOT_DIR"` first (needed so `-m grammarc.cli` resolves the package) — before this fix, relative `--out`/`--swagger`/`--dict`/`--src` were left unresolved and silently re-interpreted against `$ROOT_DIR` (the script's own directory), which only ever matched the caller's cwd by coincidence (true for every native invocation before this, since people ran it from the repo root). It now absolutizes all user-supplied paths against the caller's cwd *before* that `cd`. If you touch this script, keep that ordering.
- **Self-verifying, fail-closed instrumentation — `/shm/health` reports facts, not a verdict.** `GET /shm/health` (both `--inject-mode hook` and `source`) returns `{shm_bound, mode, total_classes, linked_assemblies, app_assemblies}` and deliberately does **not** compute an ok/degraded status on the .NET side. Do not "fix" this by adding per-assembly `linked` tracking there — it was tried and is a structural false-negative: SharpFuzz's `Trace.SharedMem` type lives only in `SharpFuzz.Common.dll`, never in the app's own IL-rewritten assemblies, so "does this app assembly define the Trace type" is always false even when instrumentation is perfectly healthy (caught live by `fixtures/planted-bug-api/`'s E2E run before it shipped). The real fail-closed decision lives engine-side: `void/go/coverage.go::checkCoverageHealth`, called from `fuzzer.go::Run` right after templates load, sends a few real unmutated warm-up requests (`renderTemplate(tid, "none", 0, -1)` + `sendOne`) and checks whether `coverage.GetEdges()` actually moved. Refuses to start by default; `-allow-degraded-coverage` overrides. If you touch either `/shm/health` endpoint or `checkCoverageHealth`, keep this split — verdict computation belongs in Go, not C#.
- **Profiles vs flags:** `-profile fast|deep|security` sets curated defaults, but only for flags the user did NOT explicitly pass (via `flag.Visit`). Never remove individual flags in favor of a profile — both must coexist.

### Dictionaries are per-target
Each fuzzed application has its OWN dictionary under `grammars/<target>/dict.json` (bitwarden, btcpay, eshop, simplcommerce) — a flat `{fieldName: [values...]}` map (`grammarc/emit_dict.py` writes it; `void/go/store.go::loadDict` reads it; a legacy one-level-nested `restler_custom_payload*`-keyed shape is still accepted for backward compatibility, but never emitted). **Target-specific values** (table names like `Core_User`, tenant IDs like `Vendor-0001`, specific field names) belong in that per-target dict, NOT in the Go engine. Only **generic, cross-target attack payloads** (SQLi, XSS, `$type` gadgets, generic mass-assignment fields) belong in `mutations.go`.
- **Honest classification:** `likely_vuln` REQUIRES a concrete exploitation signal. Unhandled-exception 500s are `confirmed_unhandled_exception` (robustness); DI/service-resolution failures are `target_misconfiguration` (build artifact, excluded from the vuln count); malformed-input parse exceptions (bad GUID/base64) are down-ranked to `needs_review`.

---

## 5. Development Guidelines for AI

- **Bug Fixing in Void (Go):** Pay extreme attention to data races. Void runs up to 16–64 concurrent HTTP workers. Always use `sync.RWMutex` protecting shared maps (like `endpointStats` or `globalCorpus`).
- **Modifying the grammar pipeline:** If you add a new C# validation constraint kind (e.g., a new FluentValidation rule format), update `analyzer/ConstraintWalker.cs` or `FluentValidationWalker.cs` (real Roslyn syntax-node matching, not regex) **and** `grammarc/roslyn_merge.py`'s merge logic if the new constraint needs special handling beyond min/max/pattern/enum. Output must stay JSON-serializable and keyed by `(type, property)`, never a bare name.
- **Performance:** The target is 1,000+ requests per second on a decent laptop. Do not introduce O(N²) operations in the hot path of the Go worker pool.
- **Logging:** When fixing bugs in Go, use the `ui.go` logger. Do not use `fmt.Println` directly, as it will break the terminal dashboard UI.
- **There is now a real regression gate** (`.github/workflows/e2e.yml`, `scripts/e2e-test.sh`) against `fixtures/planted-bug-api/` — a minimal, DB-free ASP.NET Core app with one deliberate, deterministic planted bug. It asserts real coverage growth AND that the planted bug is actually detected in `unique-crashes.jsonl`, not just that the pipeline exits zero. Run it locally (`./scripts/e2e-test.sh`) before considering a grammar-pipeline or mutation-engine change done. If you change something that could plausibly break instrumentation, grammar compilation, or crash detection, this is the fastest way to find out before a human does.

---

## 6. Where to Find Things (The Go Engine File Map)

The Go engine (`void/go/`) was refactored into focused single-responsibility files:

| File | Responsibility |
|------|---------------|
| `main.go` | CLI flag parsing, configuration validation, and application bootstrap |
| `fuzzer.go` | Main fuzzer struct and high-level lifecycle hooks (`Run`, epoch scheduling) |
| `worker.go` | Core fuzzing loop, concurrency management, worker thread sync, `mineClientErrorFields` (400-body mining) |
| `coverage.go` | SHM bitmap parsing and HTTP `/shm/coverage` polling |
| `sequence.go` | Stateful producer→consumer chain execution |
| `store.go` | Runtime knowledge extraction, ID harvesting, global value dedup, `dict.json` loading |
| `template.go` | `templates.export.json` parsing and payload rendering |
| `mutation_engine.go` | MOpt-style mutation scheduler, adaptive weights, constraint-aware boundary blending |
| `mutations.go` | Concrete mutation categories (sqli, xss, cmdi, path_traversal, etc.) |
| `crash.go` | Crash deduplication, signature generation, and JSONL logging |
| `cluster.go` | Root-cause clustering: folds many per-payload signatures into one bug via normalized exception message + top app stack frame (endpoint-template fallback when no stack) |
| `oracle.go` | Vulnerability oracles beyond HTTP 500: BOLA/IDOR + auth-bypass via cross-identity/no-auth replay, and positive injection detection (time-based SQLi, evaluated SSTI, reflected XSS) |
| `triage.go` | Source-aware triage and crash severity scoring |
| `poc.go` | PoC shell scripts and Mermaid exploit timelines |
| `report.go` | Final JSON bug report assembly |
| `minimize.go` | Delta-debugging to strip unnecessary fields from crashing payloads |
| `identity.go` | Multi-identity scheduling, weighted selection, race condition probes |
| `auth.go` | JWT/header/cookie auth state, login fallback, CSRF token harvest |
| `ui.go` | Live terminal dashboard rendering and plain logging |
| `utils.go` | HTTP and string utility functions |
| `types.go` | Core data structures (`Config`, `WorkItem`, `SendResult`, `Segment`) |

**Quick lookup:**
- Changing mutation behavior → `mutations.go` and `mutation_engine.go`
- Changing seed scheduling or coverage ceiling → `fuzzer.go` and `worker.go`
- Adding a new C# attribute the grammar should understand → `analyzer/ConstraintWalker.cs` (extraction) + `grammarc/roslyn_merge.py` (merge)
- Changing OpenAPI parsing / body serialization → `grammarc/oas.py` / `grammarc/body_serializer.py`
- Fixing a coverage bug → `coverage.go`
- Changing the fail-closed instrumentation health check → `coverage.go::checkCoverageHealth` (Go, the actual verdict) + `fuzz-prep-multi.py`'s `/shm/health` endpoint (C#, facts only — do not add a verdict there, see §4)
- Adding/changing a CLI subcommand → `upsidefuzz.py` (must stay a thin subprocess wrapper, see §4); zero-install Docker image → `Dockerfile.cli` + `upsidefuzz` launcher; docs → `docs/CLI.md`
- Adjusting crash triage rules → `triage.go` (and `identity.go` for crash payload construction)
- Changing crash minimization or repro → `minimize.go`
- Modifying PoC scripts or exploit timelines → `poc.go`
- Changing the final JSON report structure → `report.go`
- Adding/changing an E2E regression check → `scripts/e2e-test.sh`, `fixtures/planted-bug-api/`, `.github/workflows/e2e.yml`
- Writing the academic paper → `arxiv_paper/` (note: as of this file's last verification, `arxiv_paper/paper.md`'s methodology section still describes the retired RESTler-based pipeline and needs a rewrite before publication — don't treat it as an accurate architecture description)

**If the user asks you to implement a feature, always cross-reference this document to ensure you are modifying the correct logical component.**
