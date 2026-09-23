# UpsideFuzz — Architecture Review & Engineering Roadmap

**Reviewer perspective:** coverage-guided fuzzing, .NET IL rewriting, REST API fuzzing, offensive security.
**Goal being evaluated against:** *the best open-source feedback-guided REST API fuzzer for .NET* — near-zero config, universal instrumentation, deep bug discovery, researcher-adoptable.
**Tone:** brutally honest. This is the project's living technical roadmap, not a marketing document — it reflects current state only, not a changelog of everything ever fixed (see git history / commit messages for that).

**Repository state note (resolved):** the working tree's local, gitignored working state (`bitwarden_*`, `btcpayserver*`, `simplcommerce*`, `esh*`, `restler_*`, `crashes/`, `void/crashes`) is no longer a repo-hygiene problem — `.gitignore` now has blanket rules for all of it, and `git ls-files` confirms zero tracked target-checkout files. First-party code lives in `bin/fuzz-prep-multi.py`/`tools/prep/fuzzprep/`, `bin/compile-grammar.sh`, `tools/grammar/grammarc/`, `tools/dotnet/analyzer/`, `tools/dotnet/instrumentor/`, `void/`, `fixtures/demo-app/`, and the docs; everything else is local, on-demand, gitignored working state, produced by running the pipeline against a target.

**A note on `Top-20 #N` labels:** older code comments, `void/README.md`, `ARCHITECTURE.md`, and several `QUICKSTART_*.md` files still cite features by a `Top-20 #N` ID from this document's earlier numbered-roadmap format. That numbered list has been retired in favor of the current-state sections below (a roadmap that only ever grows numbered items and never removes shipped ones stops being useful), but the IDs already written into those other files are cheap to keep resolvable:

| ID | What shipped | ID | What shipped |
|---|---|---|---|
| #4 | Self-verifying, fail-closed instrumentation (`/shm/health` + warm-up coverage check) | #17 | Bitmap sizing from real instrumented-type count |
| #7 | E2E CI regression gate on a planted-bug fixture | #18 | Differential/parser-confusion auth-bypass oracles |
| #8 | *(still open — ownership-matrix BOLA; see P0 #3 below)* | #19 | Single `upsidefuzz` CLI orchestrator |
| #9 | First-party OpenAPI→grammar compiler (`tools/grammar/grammarc/`), RESTler retired | #21 | CmpLog/RedQueen live comparison-operand harvesting |
| #10 | Real Roslyn syntax-tree analyzer (`tools/dotnet/analyzer/`) | #22 | Static constant/string extraction at instrument time |
| #11 | CMPLOG-lite / 400-body validation-error mining | #23 | Response-schema conformance oracle |
| #12 | State-reward stateful sequence search (typed resource-lifecycle graph + generalized extraction + coverage-directed fanout added on top, 2026-07-27; full learned state-space search still open — see §5) | #25 | Global `-seed` (partial — no byte-exact replay tool yet, see P1 #13 below) |
| #14 | Constraint-aware boundary mutation (partial; see P1 #4/#5 below for the open remainder) | #16 | SARIF findings export (HTML dashboard still open, see P2 #18 below) |

New work should reference this document's actual section names, not a new numbered ID — the point of this refresh is to stop accumulating IDs that need remembering.

---

## Executive Summary

UpsideFuzz does things most open-source REST fuzzers do not: real grey-box coverage feedback on .NET via SharpFuzz/Mono.Cecil IL rewriting (now including async/iterator state machines, where nearly all real business logic in a modern ASP.NET Core app actually lives), AFL-style bucketed hit-count coverage with CmpLog/RedQueen-style live comparison harvesting and static constant extraction, a first-party OpenAPI+Roslyn grammar compiler (RESTler fully retired), a state-reward stateful sequence engine, and — the project's clearest differentiator — *positive* vulnerability oracles (BOLA/IDOR, broken-auth, mass-assignment, differential/parser-confusion auth bypass, time-based SQLi/SSTI, response-schema conformance). Instrumentation is zero-edit (`DOTNET_STARTUP_HOOKS`, no source changes) and self-verifying/fail-closed (a degraded run refuses to start rather than silently reporting zero coverage as success). There is real CI: an E2E regression gate against a planted-bug fixture, and a unit-test gate running the full existing Go/C#/Python test suites on every push.

The system is still architecturally three loosely-joined programs (Python prep/grammar, a Go engine, C# instrumentation) held together by file conventions and Docker, not schema-validated interfaces. The biggest **remaining** gaps: no out-of-band interaction server (OAST), so blind SSRF/XXE/RCE/blind-SQLi findings are entirely unconfirmable; BOLA detection is still body-comparison heuristic rather than ownership-matrix aware, so true cross-tenant BOLA where each user legitimately gets a different-shaped body is missed; instrumentation is Docker-only with no non-container host mode; and auth is still "paste a token file" (now with expiry *warnings*, not auto-refresh).

**Where to focus next:** OAST (cheapest large jump in the "deep, realistic bugs" story), ownership-matrix BOLA, and a non-Docker instrumentation path are the three highest-leverage items — the rest of this document orders everything else under them.

**Top structural verdict:** the fuzzer *engine* (scheduling/mutation/corpus) is ~75% of the way to state-of-the-art; *coverage feedback* is ~65% (bucketed + CmpLog + async-aware, still missing true per-input path novelty); *instrumentation universality* is ~55% (zero-edit + self-verifying, still Docker-only + regex-based build detection); *grammar/state modeling* is ~70% (RESTler retired, real Roslyn constraints, typed structural body mutation now reaches the request body — [`docs/guides/typed-structural-mutation.md`](../guides/typed-structural-mutation.md) — still no full state-graph search or regex-pattern-satisfying synthesis); *engineering rigor* (tests, CI, reproducibility, packaging) is ~55% (both an E2E gate and a full unit-test gate now exist across all three languages, and repo hygiene is resolved; persistent corpus and packaging remain open).

---

## Architecture

Three subsystems joined by files on disk and HTTP, not schema-validated interfaces:

```
 (1) PREP / INSTRUMENTATION              (2) GRAMMAR PIPELINE              (3) VOID ENGINE (Go)
 bin/fuzz-prep-multi.py  (Python)            bin/compile-grammar.sh (Bash)         src/void/internal/engine/*.go
   ├─ MultiProjectAnalyzer                 ├─ tools/grammar/grammarc/ (Python,             ├─ main → fuzzer → worker (epoch loop)
   ├─ generate_multi_docker_configs        │    first-party OpenAPI          ├─ template (typed grammar → segments)
   │    (adapt existing Dockerfile/        │    parser, stdlib-only)         ├─ mutation_engine / mutations (MOpt)
   │    compose, or generate from          ├─ tools/dotnet/analyzer/ (C#,          ├─ sequence (producer→consumer,
   │    scratch)                           │    Microsoft.CodeAnalysis       │    state-reward search)
   ├─ generate_startup_hook_assembly       │    .CSharp syntax-tree pass)    ├─ store (dict + runtime harvest)
   │    → UpsideFuzz.Coverage.dll          └─ roslyn_merge.py                ├─ coverage (SHM/HTTP readers,
   │      (DOTNET_STARTUP_HOOKS,               (OpenAPI + Roslyn merge,     │    hit-count buckets)
   │       zero source edits)                   type/property-scoped)       ├─ cmplog / constants (CmpLog +
   └─ tools/dotnet/instrumentor/Program.cs (C#)      → templates.export.json      │    static constant extraction)
        SharpFuzz.Fuzzer.Instrument           + dict.json                   ├─ oracle (BOLA/authbypass/massassign/
        (Mono.Cecil IL rewriting,                                           │    injection/differential/schema)
         + CmpLog + ConstantExtractor)                                      ├─ identity / auth (multi-identity,
                     │                                                      │    JWT expiry awareness)
        Docker image: app + /coverage_shm/bitmap (tmpfs)  ◀── mmap ─────────┤ crash / cluster / triage / minimize
                                                            / HTTP ──────────┴─ poc / report / sarif / ui / webui
```

Data contracts between the three subsystems are still **implicit**: the grammar path emits `templates.export.json`/`dict.json` in a directory the engine reads by convention; the prep path emits `/shm/*` endpoints and `X-Coverage-Delta`/`X-Exception-*` headers the engine expects; auth is a separate JSON file. Nothing type-checks these contracts across the language boundary.

---

# Subsystem Reviews

For each subsystem: current architecture, strengths, **currently open** weaknesses only, and the recommended next step.

---

## 1. Instrumentation & IL Rewriting

### Current architecture
`bin/fuzz-prep-multi.py::MultiProjectAnalyzer` scans a solution's `*.csproj` files and, by default, instruments every non-framework type (`--instrument-all-user-code`) rather than relying on namespace-classification heuristics. It either adapts an existing `Dockerfile`/compose file in place (detecting build/runtime stages and publish directory via regex) or generates one from scratch. Instrumentation is **zero-edit**: a generated `UpsideFuzz.Coverage` assembly is wired via `DOTNET_STARTUP_HOOKS` + `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`, so the target's own `Program.cs`/`Startup.cs`/`.csproj` are never touched, and an `AssemblyLoad` handler links coverage into assemblies as they load (including lazily-loaded ones). `tools/dotnet/instrumentor/Program.cs` runs three independent Cecil passes over each DLL: SharpFuzz's own basic-block coverage rewrite, `CmpLogInstrumentor` (records live string/int comparison operands), and `ConstantExtractor` (read-only harvest of `Ldstr`/`Ldc_I4`/`Ldc_I8` literals). All three now correctly instrument async/iterator state-machine (`<Method>d__N`) types — previously blanket-excluded, which blinded every one of these mechanisms on the compiler-generated type that holds virtually all of a real `async Task` method's actual IL. Instrumentation is self-verifying and fail-closed: `/shm/health` reports facts (`shm_bound`, `linked_assemblies`, `app_assemblies`, `instrumented_types`), and `src/void/internal/engine/coverage.go::checkCoverageHealth` sends real warm-up requests and refuses to start if the bitmap doesn't actually gain edges (`-allow-degraded-coverage` overrides this).

### Strengths
- SharpFuzz/Cecil IL rewriting gives true basic-block edge coverage — a real grey-box signal most REST fuzzers (Schemathesis, RESTler, Dredd) lack entirely.
- Zero-edit, load-time instrumentation means the target's own source is never modified and lazily-loaded assemblies aren't silently missed.
- Self-verifying, fail-closed startup means a broken instrumentation pass produces a loud failure, not a green run with zero real coverage.
- The `+<>c`/`/<>c` compiler-lambda-cache exclusion (needed to avoid firing coverage probes during static initialization, before the SHM pointer is bound) is a real, hard-won, still-correct fix — and is now independently regression-tested against the specific case (a `Program`/`Startup`'s own async state machines) that could have regressed when async exclusion was removed.

### Currently open weaknesses
1. **[HIGH] Docker is still mandatory.** The entire coverage channel assumes a `/coverage_shm` tmpfs volume and a container. There is no in-process or `dotnet`-attach path — a researcher fuzzing a locally-running API, an Azure Functions app, or a Windows-only target cannot use grey-box mode at all. This is the #1 remaining universality blocker.
2. **[MED] Regex-based Dockerfile/build detection remains structurally brittle**, even after three concrete bugs in this exact area were found and fixed this year (non-main-project DLLs shipped uninstrumented; runtime-stage misdetection on an unnamed final `FROM`; a stale `dockerfile:` reference). `ARG`-parameterized stages, heredocs, `buildx` bake files, and non-`dotnet publish` builds (NativeAOT, `dotnet pack`) are still undetected failure modes, not just historical ones.
3. **[MED] Framework-prefix skip list is a hardcoded denylist** (`System.`, `Microsoft.`, `Newtonsoft.`, …). A target using a vendored/renamed dependency, or legitimately shipping code under a `Microsoft.*`-prefixed namespace of its own, forces special-casing.
4. **[MED] "Business logic" file-classification heuristics are legacy complexity that should be deleted, not just bypassed.** `BUSINESS_PATTERNS`-based namespace collection still exists and still gates instrumentation whenever `--instrument-all-user-code` isn't used, even though that flag is now the default and is strictly more complete.
5. **[LOW] No NativeAOT / ReadyToRun / trimmed single-file support.** Cecil rewriting requires loose managed IL DLLs at publish time; an AOT-compiled or trimmed target produces an uninstrumented-but-passing image.

### Recommended next step
Add a non-Docker host mode using a named, cross-platform shared-memory segment (`MemoryMappedFile.CreateOrOpen` on Windows, `/dev/shm` on Linux) behind the same startup-hook mechanism already built — this is the highest-leverage remaining item in this subsystem because it, not more oracle work, gates whether the tool can run at all on a given target.

**Complexity:** High. **Priority: P0.**

---

## 2. Coverage Feedback (SHM bitmap, middleware, readers)

### Current architecture
Coverage is bucketed (AFL-style hit-count classes, not binary edge-presence) on both the C# (`CoverageExtensions.cs::CountClass`/`MergeAndCountNovel`) and Go (`coverage.go::countClass`/`GetEdges`) sides, with single-scan, first-observer-wins per-request attribution replacing the old double full-bitmap scan. `CmpLogInstrumentor` and `ConstantExtractor` (see §1) feed `/shm/cmplog` and `/shm/constants`, polled by `src/void/internal/engine/cmplog.go`/`constants.go` into live mutation candidates. Bitmap sizing is derived from the real instrumented-type count written at build time (`.upsidefuzz_instrumented.jsonl`) rather than a fixed 256KB guess, and the periodic full-bitmap reset requires both high saturation *and* genuine stagnation, not saturation alone.

### Strengths
- Direct mmap read from a sidecar is a legitimately fast, low-overhead coverage channel.
- Bucketed hit-counts mean a loop executing 1 vs. 5000 times now produces genuinely different coverage, instead of looking identical the moment every edge has been touched once.
- CmpLog + ConstantExtractor together give the mutation engine access to values a black-box fuzzer structurally cannot guess (hardcoded backdoor strings, magic comparison constants) — verified concretely on `fixtures/demo-app/`.

### Currently open weaknesses
1. **[HIGH] No per-*input* path novelty.** Novelty is still measured against one shared, globally-monotonic virgin map rather than true per-thread/per-request trace buffers. Two concurrent requests taking different *paths* through already-seen blocks still look identical to the bitmap; under concurrency, which request happens to reach the merge first still affects which seed gets energy credit. Fixing this needs per-thread trace-buffer isolation in the SharpFuzz probe itself, not just the counting logic — the harder, still-undone half of the original coverage-resolution problem.
2. **[LOW] Bitmap sizing is a proxy, not a literal edge count.** SharpFuzz exposes no public branch/edge count, so sizing is derived from instrumented *type* count (~512 bytes/type heuristic) — reasonably accurate, not exact.
3. **[LOW] Saturation % is computed against a derived ceiling** (the edge count reached at end of the Baseline epoch, or the sized bitmap capacity), not a mathematically exact reachable-edge count. A real but low-impact honesty gap in the reported metric.

### Recommended next step
Per-thread trace-buffer isolation for true per-input novelty — diminishing but still real returns after buckets + CmpLog + async-instrumentation have already landed.

**Complexity:** Medium–High. **Priority: P1.**

---

## 3. Grammar Generation (`tools/grammar/grammarc/` + `tools/dotnet/analyzer/`)

### Current architecture
RESTler is fully retired. `tools/grammar/grammarc/` (Python, stdlib-only) parses OpenAPI 3.x/Swagger 2.0 directly into a typed request model, infers producer/consumer relationships by path/name convention, synthesizes boundary values, and serializes bodies straight to `templates.export.json`/`dict.json` — no intermediate `grammar.py`, no external compiler, no Docker in this step. `tools/dotnet/analyzer/` is a real `Microsoft.CodeAnalysis.CSharp` syntax-tree pass (not regex) extracting type/property-scoped `DataAnnotations`/FluentValidation constraints, `[Authorize]` metadata, and route info, merged over the OpenAPI-derived model (`roslyn_merge.py`, Roslyn wins per-scoped-field). Deliberately syntax-tree-only, not a full semantic model via `MSBuildWorkspace`/NuGet restore — a disclosed reliability tradeoff (works on arbitrary target repos without a restore step), not an oversight.

### Strengths
- Enriching a black-box grammar with real server-side validation constraints (both OpenAPI and C# attributes) is how you get past 400-rejection walls into real logic — a genuine differentiator vs. Schemathesis, which only sees the spec.
- Constraints are keyed by `(fully-qualified type, property)`, not a global canonicalized field name, so two same-named-but-unrelated DTOs don't cross-contaminate each other's constraints.
- One command (`bin/compile-grammar.sh <swagger> [--src <dir>] [--out <dir>]`), no RESTler, no Docker for this step, three languages fewer in the hot grammar path than before.
- **A typed request-body model now reaches mutation** (2026-07-31): `schema_ast.py` builds a full schema AST (object/array/scalar/oneOf+discriminator/required/nullable/constraints) alongside the legacy flat `segments[]`, and the Go engine keeps it as a real tree (`BodyNode`/`BodyValue`) from render through mutation, binding, and minimization, only serializing to bytes immediately pre-send. See [`docs/guides/typed-structural-mutation.md`](../guides/typed-structural-mutation.md) for the full design, the 10 structural operators, and a real measured A/B comparison against the legacy flat mutator.

### Currently open weaknesses
1. **[MED] Constraint-derived boundary generation is blended, not systematic.** Per-field boundaries from OpenAPI/Roslyn constraints reach the existing generic mutation pools, but there's no exhaustive per-constraint boundary walk (e.g. every `[Range]`/`[StringLength]` field automatically getting its own `{min-1,min,min+1,max-1,max,max+1}` pass). The new typed structural mutation's `constraint_boundary` operator (see the guide above) does this for the *typed* body path specifically; this weakness is about the untyped/legacy value-mutation pools still used for path/query/header fields.
2. **[MED] Producer-consumer inference is still heuristic name-matching** (`fooId`/`foo_id`/path-segment guessing), not schema-typed identifiers — works on clean REST APIs, misbatches on composite keys or non-obvious id naming.
3. **[LOW] Typed structural mutation doesn't attempt regex/pattern satisfaction.** `constraint_boundary`/type-substitution synthesize enum/length/numeric edge values but never try to actually satisfy a declared `pattern` — a disclosed v1 scope limit, same one the pre-existing `fieldConstraintStringCandidates` already had for the untyped path.

### Recommended next step
Regex-aware string synthesis for both the typed and untyped constraint-boundary paths (satisfy a declared `pattern` instead of only respecting length/enum) — the next honest gap now that the model itself reaches mutation.

**Complexity:** Medium. **Priority: P2.**

---

## 4. Fuzzing Engine — Scheduling, Mutation, Corpus

### Current architecture
Time budget split into epochs (Baseline → Harvest → Deterministic → Havoc → Splicing) with adaptive rebalancing, Fenwick-tree energy sampling, and MOpt-style hit-rate-driven mutation-category weighting. `Segment` constraint hints (min/max length, numeric range, pattern, enum values — sourced from `tools/grammar/grammarc/`/`analyzer`, see §3) are blended into `mutateAny`/`mutateInt`/`mutateStringCategorized` as additional boundary candidates, additive to the existing generic pools. `worker.go::mineClientErrorFields` parses ASP.NET's ValidationProblemDetails/ModelState 400-body shape and free-text enum hints, feeding extracted values back into the runtime value store the same `custom_payload` rendering already draws from.

### Strengths
- The epoch model + adaptive rebalancing + Fenwick energy sampling + surprise factor is a genuinely sophisticated, AFL++-informed scheduler.
- Constraint-aware boundary mutation measurably increases hit rate on the same bug class in the same time budget (verified: ~7x more crash hits on a known overflow bug after this landed).
- Mining 400-body validation errors back into the mutation pool is cheap and effective on validation-heavy APIs — closes a loop that used to be write-only (human-readable report only).
- **Request-body mutation is now structure-aware for templates with a typed schema** (2026-07-31, `src/void/internal/engine/body_mutate.go`): 10 operators (add/remove field, required-field omission, array resize, oneOf/discriminator switch, type substitution, null injection, undeclared property, duplicate key, nesting-depth stress, constraint boundary) target a real object/array/oneOf tree rather than splicing bytes in a flattened string — see [`docs/guides/typed-structural-mutation.md`](../guides/typed-structural-mutation.md). Path/query/header mutation is still the pre-existing value-centric engine described below; this closes the gap specifically for request bodies.

### Currently open weaknesses
1. **[MED] Splicing is shallow** (one seed's template + havoc), not true JSON-subtree crossing between two different request bodies. The new typed body operators don't cross-splice between two different seeds' trees either — each operates on one render's own tree.
2. **[LOW] No persistent corpus across runs.** Corpus is in-memory, pruned at 500, discarded at process exit — a researcher re-running against the same target starts cold every time.

### Recommended next step
Persist the corpus + coverage frontier to disk (a `corpus/` directory keyed by target) for warm restarts — low effort, real reproducibility and productivity win.

**Complexity:** Low–Medium. **Priority: P1.**

---

## 5. Stateful Sequences & Entity Harvesting

### Current architecture
On a successful write, `enqueueSequenceFollowups` extracts entity IDs, binds them into a `SequenceState`, finds consumers via a dependency index plus same-family path matching, and fans out follow-up requests, cloning state per branch. A coarse workflow-*shape* signature (`sequenceStateSignature`) still rewards reaching a never-before-seen shape with an energy bonus and extra search fanout. Layered directly on top of that (not a replacement — both run together): a typed, bounded **resource-lifecycle state graph** (`resource_graph.go`) tracks explicit lifecycle states (`Created`/`Readable`/`Modified`/`Deleted`/`Invalidated`/`Stale`/...) derived from method+status+prior-state; a **generalized extraction pipeline** (`resource_extraction.go`) replaces the old `id`/`Id`/`data[].id`-only extraction with structural shape detection (GUID/hex/slug/opaque, any field name), HTTP header parsing (`Location`/`Content-Location`/`Link`), HAL `_links`, JSON:API `relationships`, and route-template-typed URI matching (extracting a typed candidate per path-placeholder position, not just the final segment); and **coverage-directed consumer scheduling** (`resource_scheduling.go`) replaces the purely-static verb-affinity sort with a blended score (historical per-endpoint coverage yield, a never-reached bonus, a repeated-failure penalty, bounded epsilon-exploration against starvation). `-resource-graph=false` reproduces the prior extraction/fanout behavior exactly. See `docs/research/design-notes/resource-state-graph-plan.md`/`resource-state-graph-report.md` for the full design and measured results (on a representative 7-body corpus, the old extraction found 1 candidate total; the new pipeline found 11). A 2026-07-28 follow-up pass, prompted by live Bitwarden-run findings, fixed the actual reason real-ID chains were rare in practice: sequence follow-ups' path/body value substitution had never used the resource graph's own extracted values at all (only which *template* to call next was graph-influenced) — `pickFollowupPathValue`/`graphBiasedPayloadCandidates` now prefer graph-known values, the on-disk dedup exemplar can be upgraded to a real-ID-backed one, shallow-but-genuine chains bypass the full-depth persistence gate, crashes link back to their originating sequence, and five new counters explain why a given sequence stopped extending.

### Strengths
- Real runtime value harvesting + producer→consumer chaining, with per-branch state cloning, provenance, and workflow persistence (repro scripts), is a solid working implementation of exactly what separates a stateful API fuzzer from a dumb one.
- Rewarding new *workflow shapes*, not just new coverage edges, is the concrete mechanism that makes multi-step business-logic bugs (which look identical to a coverage bitmap on the 3rd identical follow-up) discoverable at all.
- **Entity extraction is no longer id-name-centric.** GUIDs/slugs/references/HAL links/JSON:API relationships under any field name are now extractable, each with provenance and a confidence score, verified by 9 regression tests each proving the old pipeline blind on a shape the new one finds, plus 3 integration tests against a real `httptest` server (not synthetic strings).
- **An explicit, typed lifecycle model now exists**, distinguishing e.g. a stale post-deletion read (`Stale`, invalid) from an ordinary successful read (`Readable`, valid) — something the shape signature alone structurally cannot express, since both look identical to it.
- **Fanout is now coverage-directed**, not purely static: a never-reached consumer and one with real historical coverage yield are prioritized over the old verb-affinity-only ordering, with a verified (50-trial) starvation-prevention mechanism and verified determinism under a fixed seed.

### Currently open weaknesses
1. **[MED] Still not a full learned state-space search.** The resource graph is a real typed model with real lifecycle transitions, but exploration is score-based, not the reinforcement-learned search DeepREST/EvoMaster implement over the full state space — this pass built the prerequisite typed model and coverage-directed scoring, not that search algorithm itself.
2. **[MED] Composite identities are recognized only when pre-composed** (a JSON:API compound id, a nested single-field object) — synthesizing a composite key by correlating unrelated sibling fields (e.g. inferring `{tenant, user}` together identify one resource) is not attempted.
3. **[LOW] Alias detection is same-step-only.** Two independently-discovered instances that are actually the same resource, observed at different times under different representations, are not retroactively merged.
4. **[LOW] Sequence depth capped at 3** — many real workflows (checkout, KYC, multi-approval) are longer.
5. **[LOW] No live end-to-end throughput comparison** for the coverage-directed scheduler specifically — its own per-call overhead is measured (~40–60ns more than the old static sort at a 12-candidate list size) but a full-run req/s comparison with `-resource-graph` on vs. off has not been done.
6. **[LOW] The 2026-07-28 value-substitution bias fix is unit-tested but not yet re-validated live.** The fix directly targets the measured root cause (real-ID chains losing the dedup race to generic-value chains), but no fresh live run has re-measured whether the dedup real-ID-chain ratio actually improves in practice with it active — the before-numbers (1/72, 3/59) that justified the fix are not yet paired with an after-number.

### Recommended next step
Coverage-directed *sequence fanout depth* — using `findCompatibleResources` to prioritize which already-known resource instance to bind into a deeper follow-up based on which of its lifecycle transitions are still unexplored — is the natural next increment on top of the typed model and scoring now in place, and the more direct remaining step toward the full state-graph search DeepREST/EvoMaster implement.

**Complexity:** Medium–High. **Priority: P1.**

---

## 6. Vulnerability Oracles (`oracle.go`) — the crown jewel

### Current architecture
Positive oracles beyond plain 500s: **BOLA/IDOR** (replay a successful authed resource request under every other identity), **broken-auth** (no-credential replay, gated on endpoints already observed enforcing auth), **mass-assignment** (over-post privileged fields, check reflection), **injection** (time-based SQLi via latency, evaluated SSTI via arithmetic markers, reflected XSS), **differential/parser-confusion auth bypass** (verb, content-type, route-case, and param-location variants, gated on strong evidence the endpoint actually enforces auth — so a hit means the confusion technique itself bypassed a real check), and **response-schema conformance** (live 2xx bodies checked against the declared OpenAPI response schema — undeclared/sensitive fields and type drift). False-positive engineering is mature: trivial-body/error-body detection, concrete-resource-ID gating, same-credentials skipping, and — after a real, previously-presented-as-genuine SSRF false positive was found and fixed — payload-string stripping before matching so an endpoint that merely echoes its input back can't self-satisfy the SSRF check.

### Strengths
- **This is the most valuable and most differentiated part of the project.** No mainstream open-source REST fuzzer ships BOLA + broken-auth + mass-assignment + differential-auth-bypass + positive injection + schema-conformance oracles wired into a coverage-guided loop.
- The honest false-positive engineering (trivial-body/error-body filtering, auth-bypass precondition gating, same-credentials skipping) reflects real offensive-security judgment and is what would make a security researcher trust the findings.
- Response fingerprinting for identical-vs-different body scoring is the right BOLA discriminator for the class of bug it can see.

### Currently open weaknesses
1. **[CRITICAL] No out-of-band interaction server (OAST).** Blind SSRF/XXE/RCE/log4shell/blind-SQLi are entirely unconfirmable without one — the single biggest remaining gap in "deep, realistic" bug discovery, and the cheapest large jump in the project's headline value proposition.
2. **[HIGH] BOLA detection is still body-comparison heuristic, not object-ownership-aware.** "Identical body under two identities" is a strong signal; a *different* 2xx body is downgraded to `needs_manual_verification` — but real BOLA often returns a *different*, still-wrong body (each user's own object, when the vuln is that user A can read an object *owned by B*). Without seeding known-B-owned resource IDs and replaying them under A, the oracle can't distinguish "shared endpoint returning my own data" from "I read your data."
3. **[MED] Injection oracles are shallow beyond time-based SQLi/SSTI-arithmetic.** No boolean-based or error-based SQLi differential; `$type` deserialization gadgets are sent but nothing confirms they actually executed (reflection only), so RCE-class findings are unconfirmed without OAST.
4. **[MED] Mass-assignment confirmation requires the server to echo the field back.** A silent privilege write (accepted but never reflected) is invisible without a follow-up read-back or behavioral probe.

### Recommended next step
Build a basic OAST server (a public DNS/HTTP callback endpoint the engine controls, injected as SSRF/XXE/RCE payload targets, polled for out-of-band hits) — this single addition converts an entire class of currently-unconfirmable blind findings into confirmed ones.

**Complexity:** Medium. **Priority: P0.**

---

## 7. Crash Triage, Clustering, Minimization, Reporting

### Current architecture
Two-level dedup: fine-grained `crashSignature` (method+path+status+exception+response-fingerprint) and root-cause `ClusterKey` (normalized exception message + top app stack frame, else `(method,status,route-template)`). Honest classification tiers (`likely_vuln`/`confirmed_unhandled_exception`/`needs_review`/`target_misconfiguration`/`noise`). SARIF 2.1.0 export (`-sarif-file`) drops findings directly into GitHub code scanning / DefectDojo, using an explicit allowlist of strong, specific oracle-reason tags as SARIF rule IDs (rather than a denylist of weak ones) so a generic contextual tag can never silently become the rule id for a real, specific bug.

### Strengths
- The two-level signature/cluster split solves the real "hundreds of crashes = a handful of bugs" over-counting problem honestly, and app-frame extraction (skipping framework frames) is well done.
- The honest classification taxonomy (a 500 is not automatically a vuln; DI failures are misconfig; malformed-input parse errors are down-ranked) is rare among fuzzing tools and earns researcher trust.
- Minimization + repro-rate + auto-PoC + Mermaid timeline generation is a real bug-reporting pipeline, not just a crash dump.

### Currently open weaknesses
1. **[MED] Root-cause clustering degrades in production mode.** Without a stack trace, clustering falls back to `(method, status, route-template)`, which *under*-clusters — the same bug on different routes becomes different clusters, the inverse of the signature-level over-counting problem this design otherwise solves.
2. **[LOW] Triage severity scores are a hand-tuned additive heuristic**, not CVSS-equivalent — reasonable as a ranking signal, but should be clearly labeled as heuristic wherever displayed, not presented as a standard score.
3. **[LOW] No HTML findings dashboard.** SARIF export exists for CI/scanner integration; there's no human-browsable report for a quick manual review.
4. **[LOW] Minimization is field-removal only**, not value-level shrinking (bisecting a 10K-character string down to the minimal triggering length).

### Recommended next step
Value-level minimization is the cheapest of these and directly improves PoC quality; production-mode clustering is the more structurally interesting problem but lower urgency given dev-mode already clusters well.

**Complexity:** Low–Medium. **Priority: P2.**

---

## 8. Authentication, Identity, Anti-Forgery

### Current architecture
Multi-identity from an auth JSON file: JWT/API-key/cookie/header identities, weighted/round-robin/random scheduling, a `guest` identity, race-burst probing, anti-forgery token harvesting and rotation. Void now reads the unsigned `exp` claim off any JWT-shaped identity token at load time (never verifying the signature) and warns at startup about any identity whose token is already expired or will expire before the configured run finishes, plus a one-time mid-run event the moment a still-valid-at-startup token actually crosses expiry.

### Strengths
- Multi-identity as a first-class concept is what makes the BOLA/auth oracles possible at all — correct architectural coupling.
- JWT expiry awareness turns a silent, confusing wave of 401s partway through a long run into an explicit, timestamped signal.
- Anti-forgery token harvesting handles a real-world friction point (MVC + Identity-style apps) that stops most fuzzers cold.

### Currently open weaknesses
1. **[HIGH] Auth acquisition is still fundamentally manual.** For "near-zero config," the tool should be able to perform a login flow itself (OAuth2 password/client-credentials, form login, `/connect/token`) and refresh automatically per identity. Expiry is now *visible*; it still isn't *fixed automatically*.
2. **[MED] No OpenID Connect/OAuth2 discovery.** Given `.well-known/openid-configuration` + client credentials, identities could be minted automatically instead of pasted in from a manual login.
3. **[LOW] No per-identity role/permission model** to prioritize which BOLA pairs are actually interesting (admin→user is the high-value direction; nothing currently ranks pairs this way).

### Recommended next step
Credential-based auto-login per identity (form/OAuth2 flows, configurable per identity) with automatic refresh — turns the auth file from "must contain live tokens" into "must contain credentials," which is what actually removes the friction.

**Complexity:** Medium. **Priority: P1.**

---

## 9. Developer Experience, Portability, Reliability, Maintainability

### Current architecture
Two CI jobs run on every push/PR: an E2E regression gate (`scripts/e2e/e2e-test.sh`) that instruments a minimal planted-bug fixture, brings it up in Docker, and asserts both real coverage growth and that the one deliberately-planted bug is actually found — not just that the pipeline runs without erroring; and a `unit-tests` job running the full existing Go/C#/Python test suites (previously written, never actually wired into CI) plus new tests for the two areas found most fragile this year (`bin/fuzz-prep-multi.py`'s Dockerfile detection, `bin/compile-grammar.sh`'s flag parsing). A single CLI orchestrator (`bin/compatibility/upsidefuzz.py`, zero-install via `./upsidefuzz` + `Dockerfile.cli`) wraps the four-tool pipeline behind `instrument`/`build`/`up`/`down`/`verify`/`grammar`/`fuzz`/`run` subcommands without changing what any underlying tool does.

### Strengths
- Two-tier CI (fast unit-test gate, slower E2E gate that depends on it passing first) catches a basic regression in ~1-2 minutes instead of only after a 20-minute Docker build.
- The single CLI orchestrator plus zero-install Docker mode means a machine with nothing but Docker installed can run the entire pipeline, including the Roslyn analyzer step.
- Every subcommand is purely additive — running the underlying tools directly, exactly as documented, keeps working unchanged.
- **Repo hygiene is resolved.** `.gitignore` now has blanket rules covering every target-checkout/generated-output pattern (`bitwarden_*/`, `btcpayserver*/`, `simplcommerce*/`, `esh*/`, `restler_*`, `crashes/`, `void/crashes/`, `summaries/`), and `git ls-files` confirms zero tracked target-checkout files. This was the cheapest open item in this document and is no longer open.

### Currently open weaknesses
1. **[MED] Three-language pipeline with implicit, non-schema-validated file contracts.** Python (prep+grammar) + Bash (compile) + Go (engine) + C# (instrumentor), with onboarding and debugging requiring understanding all four.
2. **[MED] 90+ CLI flags on `src/void/internal/config/flags.go`.** Profiles (`fast`/`deep`/`security`) mitigate this well for day-to-day use, but the raw surface remains a real docs/maintenance burden.
3. **[LOW] No versioned releases or packaging.** No `dotnet tool`, no container on a registry, no `brew`/binary release — adoption still requires cloning and reading runbooks.
4. **[LOW] `fixtures/demo-app/` (the flagship in-repo demo target) has zero CI coverage.** Unlike `fixtures/planted-bug-api/`, nothing automated verifies its 24-bug catalog stays intact across future engine/instrumentor changes — everything about it has been verified by hand, not by a regression gate.

### Recommended next step
CI coverage for `fixtures/demo-app/` is the cheapest of the remaining items here — a straightforward second E2E-style gate, no design work required, unlike the schema-contract or flag-surface items.

**Complexity:** Low–Medium. **Priority: P2.**

---

# Security-Researcher Adoption Review

*Reviewed as a working offensive-security engineer deciding whether to run this on a client engagement.*

**Would I trust it?** Yes, more than most open-source fuzzers in this space. The honest triage taxonomy and false-positive engineering in `oracle.go` earn credibility fast; instrumentation is self-verifying and fail-closed (a broken build produces a loud failure, not a silent zero-coverage green run); coverage is bucketed and honestly sized; runs are seedable. I would still not read a clean run as "this API is safe" — no OAST means blind vulnerability classes depend on luck, not confirmation — but I'd trust the coverage numbers and the access-control findings.

**What would frustrate me?**
- No OAST — my blind SSRF/RCE/XXE findings would depend on luck, not confirmation.
- Docker-only, with a regex-based Dockerfile-adaptation step that, while now well-tested, is still fundamentally pattern-matching rather than a real build-graph understanding.
- Auth is still "paste a token file" — expiry is now visible at startup and mid-run, but nothing refreshes it automatically, so a long unattended run against a short-lived-token target still needs babysitting.

**What features would I immediately miss?**
An out-of-band interaction server; ownership-matrix BOLA; auto-login/OAuth2; a persistent, resumable corpus; a non-Docker host mode; an HTML findings dashboard (SARIF itself exists).

**What vulnerabilities is it unlikely to find today?**
Blind injection (SSRF/XXE/RCE/blind-SQLi) without OAST; true cross-tenant BOLA where each user's response body legitimately differs; deep multi-step business-logic bugs needing a full state graph rather than a coarse shape signature; deserialization/polymorphism bugs needing structure-aware mutation over a typed body model; anything in AOT/trimmed targets; anything only reachable on a non-Docker-hostable target.

**What would make me switch *to* it?** The oracle suite plus real .NET grey-box coverage is already unique. Add OAST, ownership-matrix BOLA, and a non-Docker mode, and this becomes the default .NET API fuzzer over Schemathesis/RESTler for anyone doing access-control-focused engagements.

---

# Comparison Table (subsystem maturity, current open gap only)

| Subsystem | Maturity | Gating weakness |
|---|---|---|
| IL rewriting / SharpFuzz | Good | Docker-only, no non-container host mode; no AOT/trimmed support |
| Coverage signal | Good | No per-*input* path novelty (shared virgin map, not per-thread trace buffers) |
| Grammar generation | Good | No typed body model reaching mutation; producer/consumer inference still name-heuristic |
| Scheduling / MOpt / corpus | Strong | No persistent/resumable corpus |
| Sequences / state | Medium | Coarse workflow-shape signature, not a full resource-lifecycle state graph |
| Oracles | **Strong (differentiator)** | No OAST; BOLA is body-heuristic, not ownership-matrix aware |
| Triage / cluster / report | Strong | Production-mode clustering under-clusters without a stack trace; no HTML dashboard |
| Auth / identity | Medium | Manual token file; JWT expiry is visible now, not auto-refreshed |
| DX / CI / reliability | Improving | No versioned releases; `fixtures/demo-app/`'s 24-bug catalog has no CI coverage yet |

---

# Prioritized Open Improvements

Ordering rationale: OAST and ownership-matrix BOLA are the cheapest large jumps left in "deep, realistic bug discovery" — the project's actual differentiator. Non-Docker instrumentation is the last major universality blocker. Everything else either builds on these or is a smaller, independent win.

## P0 — do next

| # | Improvement | Difficulty | Effort | Why first |
|---|---|---|---|---|
| 1 | **Built-in OAST server** for blind SSRF/XXE/RCE/log4shell/blind-SQLi confirmation | Med | 2–3 wk | Cheapest large jump in "deep/realistic" bugs; converts an entire class of currently-unconfirmable findings into confirmed ones |
| 2 | **Non-Docker host mode** (named cross-platform SHM behind the existing startup-hook mechanism) | High | 3–4 wk | Last major blocker between "works on curated targets" and "works on arbitrary .NET" |
| 3 | **Ownership-matrix BOLA** (harvest each identity's own created/owned resource IDs, cross-replay explicitly rather than only replaying the origin request) | Med | 1–2 wk | Catches the real cross-tenant BOLA class the body-heuristic oracle structurally cannot |

## P1 — high value, builds on what's already there

| # | Improvement | Difficulty | Effort | Notes |
|---|---|---|---|---|
| 4 | **Credential-based auto-login + OAuth2/OIDC per identity**, with automatic refresh | Med | 2 wk | Removes the token-file friction JWT-expiry warnings only made visible, not fixed |
| 5 | **Persistent, resumable corpus** (`corpus/` directory keyed by target) | Low–Med | 1 wk | Warm restarts; real reproducibility and researcher-productivity win, independent of everything else here |
| 6 | **JWT/session-lifecycle oracle** (`alg=none`, `kid` injection, tampered/expired token replay, replay after logout, mid-session privilege change) | Med | 2 wk | High-value, .NET-native; reuses existing `identity.go`/`auth.go` |
| 7 | **Sensitive-data/PII exposure oracle** (emails/tokens/PANs/connection strings/stack traces in 2xx bodies) | Low | 1 wk | Real finding class independent of 500s; regex over bodies already collected |
| 8 | **Taint-marking of injected values** (tag fuzzer payloads, detect where they resurface in responses/SQL errors/file paths) | Med | 1–2 wk | Sharpens injection-oracle precision, finds reflected sinks, cuts false positives |
| 9 | **Regression/diff-guided fuzzing** (fuzz only code changed between two commits) | Med | 2 wk | CI-friendly "fuzz just this PR in 5 minutes" — nothing in the .NET space does this out of the box |
| 10 | **Readiness-gated startup + DB-seeding harness** (poll readiness instead of a fixed sleep; seed known per-identity objects) | Low | 1 wk | Removes startup flakiness; also provides ground truth for ownership-matrix BOLA (#3) |
| 11 | **Request-journal replay tool** for byte-exact reproducibility (seeding alone isn't bit-for-bit under concurrency) | Med | 2 wk | The remaining piece of "a specific finding is mechanically replayable," not just re-approximated |
| 12 | **Boolean/error-based injection differentials** (beyond time-based SQLi/SSTI-arithmetic) | Med | 1–2 wk | Widens injection-oracle coverage without needing OAST |
| 13 | **Coverage-directed sequence fanout *depth*** (prioritize which known resource instance to bind into a deeper follow-up based on unexplored lifecycle transitions, via `findCompatibleResources`) | Med | 2 wk | Builds on the typed resource-lifecycle graph + coverage-directed consumer scoring added 2026-07-27 (see §5); the natural next increment toward the full state-graph search DeepREST/EvoMaster implement |

## P2 — real value, lower urgency

| # | Improvement | Difficulty | Effort | Notes |
|---|---|---|---|---|
| 14 | **Value-level minimization** (bisect string length/numeric magnitude, not just field removal) | Low–Med | 1 wk | Better PoCs |
| 15 | **Behavioral mass-assignment confirmation** (read-back or privilege-action probe, not just field-echo detection) | Low–Med | 1 wk | Catches silent privilege writes the echo-based check misses |
| 16 | **HTML findings dashboard** (SARIF export already exists for CI/scanner integration; a live web dashboard now also exists via `-web-ui`, but it's a live-run view, not a persisted HTML report) | Low | 3–5 d | Human-browsable report for quick manual review |
| 17 | **Non-REST surfaces**: gRPC, GraphQL (HotChocolate), SignalR/WebSocket | High | 4–6 wk | Large real .NET surface outside the current REST-only model; GraphQL brings its own oracle class |
| 18 | **Algorithmic-complexity / ReDoS / resource-exhaustion oracle** | Med | 2 wk | DoS class on top of the existing latency baseline |
| 19 | **Distributed parallel fuzzing + corpus sync** across target replicas | High | 3 wk | Scale on large apps; synergizes with persistent corpus (#5) |
| 20 | **Versioned releases/packaging** (`dotnet tool`, registry container, brew/binary release) | Med | 2 wk | Adoption; no longer requires cloning + reading runbooks |
| 21 | **CI coverage for `fixtures/demo-app/`** (a second E2E-style gate checking a handful of its planted bugs stay findable) | Low–Med | 3–5 d | `fixtures/demo-app/`'s 24-bug catalog is currently verified by hand only |
| 22 | **Regex/pattern-satisfying string synthesis** for constraint-boundary mutation (typed and untyped paths alike) | Med | 2–3 wk | Both `body_mutate.go`'s `constraint_boundary` operator and the pre-existing untyped `fieldConstraintStringCandidates` synthesize enum/length/numeric edges but never attempt to satisfy a declared `pattern` |

---

# Missing Features Compared to Existing Fuzzers

### vs. RESTler
RESTler's OpenAPI→grammar compilation and producer-consumer inference have been internalized and superseded by `tools/grammar/grammarc/`+`tools/dotnet/analyzer/` (no more external-tool dependency, type-scoped constraints RESTler never had). RESTler still has more mature resource-lifecycle checkers (use-after-free, resource-leak); UpsideFuzz's oracle set is different and stronger on access-control.

### vs. EvoMaster
- White-box SBST search with a typed test genome and branch-distance fitness — EvoMaster gets closer to flipping a specific branch using numeric distance to the condition. UpsideFuzz has no branch-distance/gradient signal.
- Full test-case minimization + JUnit/JS test export. UpsideFuzz exports curl PoCs, not runnable regression tests.
- SQL database state heuristics. UpsideFuzz has no DB awareness.
- Full white-box SBST search with branch-distance fitness over that genome. UpsideFuzz's typed structural body mutation (§3/§4, [`docs/guides/typed-structural-mutation.md`](../guides/typed-structural-mutation.md)) closes the schema-awareness gap specifically, but has no branch-distance/gradient signal driving it — see the AFL++/EvoMaster bullet above.

### vs. Schemathesis
- Property-based generation from JSON Schema (Hypothesis strategies) with shrinking and stateful `links`. UpsideFuzz has a response-*side* schema-conformance oracle, not a generation-time property engine, and no shrinking.
- `--checks` for status-code/content-type conformance beyond the response-body conformance oracle UpsideFuzz already has.
- Mature CLI/pytest integration and reporting.

### vs. DeepREST
Learned, reinforcement-based state-space exploration for operation ordering and parameter values that reach deep states. UpsideFuzz's sequence engine rewards new workflow *shapes* (a real, working mechanism) but is heuristic-priority, not learned, and the shape signature is coarser than a full state graph.

### vs. libFuzzer / AFL++
In-process per-input coverage, fork mode, value-profile, deterministic + havoc + splice stages, persistent queue, collision-aware map sizing. UpsideFuzz's out-of-process HTTP model can't match per-input speed, has CmpLog (a real AFL++-class feature) but no full per-input path novelty (§2) and no persistent corpus (§4).

**Net:** UpsideFuzz already beats all of these on **access-control/mass-assignment oracles wired to real .NET grey-box coverage, with a self-verifying zero-edit instrumentation story**, and now also on **typed schema-aware structural body mutation** (object/array/oneOf+discriminator, 10 structural operators — see [`docs/guides/typed-structural-mutation.md`](../guides/typed-structural-mutation.md), including a real measured A/B against the legacy flat mutator). It trails on: true per-input coverage resolution and branch-distance signal (AFL++, EvoMaster), learned state-space exploration (DeepREST), out-of-band blind-vulnerability confirmation (nothing in this list needs it as badly, since REST-focused competitors mostly don't target blind classes either — but it's still the sharpest gap for a serious offensive engagement), and persistent/resumable runs (AFL++, libFuzzer).

---

# Vision

## What UpsideFuzz should become

**The default coverage-guided security fuzzer for .NET APIs — one command, no code changes, self-verifying instrumentation, deep access-control and injection oracles confirmed out-of-band, and coverage resolution on par with AFL++.** The differentiator (grey-box .NET + positive vuln oracles + multi-identity) is already here. The remaining work is removing every reason a researcher *wouldn't* reach for it.

## Ideal target architecture (v-next)

```
                         ┌────────────────────────────────────────────┐
                         │  upsidefuzz  (single CLI orchestrator,       │
                         │  already exists: instrument/build/up/down/   │
                         │  verify/grammar/fuzz/run)                    │
                         └───────────────┬────────────────────────────┘
        ┌────────────────────────────────┼──────────────────────────────────┐
        ▼                                 ▼                                   ▼
   tools/dotnet/analyzer/ (Roslyn)             UpsideFuzz.Coverage (DOTNET_          Void Engine (Go)
  - typed per-property             STARTUP_HOOKS, zero-edit,             - typed grammar model (exists) +
    constraints, [Authorize]        already exists)                        structural body mutation (exists)
  - route + auth metadata          - load-time IL rewrite / link         - hit-count-bucket coverage
        │                            (exists)                              (exists) + per-input novelty
        │                          - cross-platform non-Docker SHM         (open)
        │                            (open)                              - CmpLog (exists) + OAST (open)
        │                          - /shm/health self-verify (exists)      - state-reward sequences (coarse,
        └──────────────┐                    │                              exists) + full state graph (open)
                                                                          - persistent corpus (open)
                        ▼                    ▼                                   │
                tools/grammar/grammarc/ + tools/dotnet/analyzer/ → typed request grammar (exists) ─────────┘
                                                                        SARIF (exists) / HTML (open)
```

Key properties still open: **coverage feedback at true per-input resolution** (buckets + CmpLog already exist; per-input path novelty doesn't); **oracles confirmed out-of-band** (OAST) and via ownership matrices, not just body heuristics; **full state-space exploration**, not a coarse shape signature; **a non-Docker instrumentation path**; **persistent, resumable runs**.

## What would make it the best open-source feedback-guided REST API fuzzer for .NET

1. **Coverage you can trust at full resolution** — bucketed and honestly sized (done); per-request, per-input path novelty (open).
2. **Instrumentation that works anywhere** — zero-edit and self-verifying (done); Docker-independent (open).
3. **Oracles that find real, deep, blind vulnerabilities** — the access-control suite is already strong; OAST + ownership matrices + differentials-beyond-time-based close the remaining gap.
4. **State-aware exploration** for business-logic bugs — the shape-signature mechanism exists; a full state graph doesn't yet.
5. **Reproducibility and integration** — SARIF and seedable runs exist; a persistent corpus and a byte-exact replay tool don't yet.

The engine and the oracle layer are already genuinely good and genuinely differentiated. OAST, ownership-matrix BOLA, and a non-Docker mode are the three items standing between this project and "nothing else in the open-source .NET space compares" — everything else in this document is real, valuable, and secondary to those three.
