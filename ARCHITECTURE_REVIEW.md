# UpsideFuzz — Deep Architecture Review & Engineering Roadmap

**Reviewer perspective:** coverage-guided fuzzing, .NET IL rewriting, REST API fuzzing, offensive security.
**Goal being evaluated against:** *the best open-source feedback-guided REST API fuzzer for .NET* — near-zero config, universal instrumentation, deep bug discovery, researcher-adoptable.
**Tone:** brutally honest, as requested. This is written to be the project's official technical roadmap, not to flatter it.

**Repository state note:** the working tree is polluted with many target checkouts (`bitwarden_prep*`, `btcpayserver*`, `simplcommerce*`, `esh*`, `restler_*`, `crashes/`, `void/crashes`). This review covers only first-party code: `fuzz-prep-multi.py`, `enhance-grammar.py`, `compile-grammar.sh`, `sanitize-swagger-for-restler.sh`, `instrumentor/`, `void/`, and the docs. Everything else is a target artifact and should be `.gitignore`d out of the repo (see DX section).

---

## Executive Summary

UpsideFuzz is a genuinely ambitious and, in places, well-engineered system. It already does things most academic REST fuzzers do not: real grey-box coverage feedback on .NET via SharpFuzz IL rewriting, a shared-memory bitmap read directly by a Go engine, MOpt-style adaptive mutation weighting, stateful producer→consumer sequences, and — most valuably — *positive* vulnerability oracles (BOLA/IDOR, broken-auth, mass-assignment, time-based SQLi/SSTI). The oracle layer (`oracle.go`) is the project's crown jewel and the single biggest reason a security researcher would look twice.

But the system is, architecturally, three loosely-joined programs (a Python prep/instrumentor generator, a Bash+Python grammar pipeline, and a Go engine) held together by file conventions, string templating, and Docker. The **coverage signal is fundamentally weaker than AFL/libFuzzer** (binary edge-presence, no hit-count bucketing, concurrency-smeared attribution), the **instrumentation still requires meaningful manual work** and silently degrades when it fails, the **"Roslyn analyzer" and semantic source extraction is regex, not Roslyn**, and the **grammar path is bottlenecked on RESTler**, which caps request quality at "RESTler + string mutation." There is essentially **no automated test/CI safety net** (4 Go test files for ~10.8k LOC, no `.github/workflows`).

The path to "best-in-class" is not more mutation categories. It is: (1) a real per-request coverage channel with hit-count buckets and stable edge IDs; (2) one-command, self-verifying, framework-agnostic instrumentation with a no-Docker fallback; (3) replacing the RESTler dependency and regex SSE with a first-party OpenAPI+Roslyn grammar; (4) a differential/response-aware oracle engine; and (5) reproducibility + CI infrastructure a researcher can trust.

**Top structural verdict:** the fuzzer *engine* is ~70% of the way to state-of-the-art; the *coverage feedback* and *instrumentation universality* are ~40%; the *grammar/state modeling* is ~50%; the *engineering rigor* (tests, CI, reproducibility, packaging) is ~20%. Fix the bottom two tiers first — they gate everything else.

---

## Reconstructed Architecture

Three subsystems joined by files on disk and HTTP:

```
 (1) PREP / INSTRUMENTATION            (2) GRAMMAR PIPELINE           (3) VOID ENGINE (Go)
 fuzz-prep-multi.py  (Python)          compile-grammar.sh (Bash)      void/go/*.go
   ├─ MultiProjectAnalyzer               ├─ sanitize-swagger-*.sh        ├─ main → fuzzer → worker (epoch loop)
   ├─ generate_multi_docker_configs      ├─ RESTler compiler (binary)    ├─ template (RESTler grammar → segments)
   ├─ generate_unified_instrumentor      ├─ enhance-grammar.py           ├─ mutation_engine / mutations (MOpt)
   ├─ generate_multi_coverage_helper     │    ├─ OpenAPIExtractor         ├─ sequence (producer→consumer)
   │    → CoverageExtensions.cs          │    ├─ SourceExtractor (regex!) ├─ store (dict + runtime harvest)
   │    → SHM + ASP.NET middleware       │    └─ DictionaryEnhancer       ├─ coverage (SHM/HTTP readers)
   ├─ inject_multi_shm_endpoints         └─ export-templates.py           ├─ oracle (BOLA/authbypass/massassign/inj)
   └─ instrumentor/Program.cs (C#)          → templates.export.json       ├─ identity / auth (multi-identity)
        SharpFuzz.Fuzzer.Instrument                                       ├─ crash / cluster / triage / minimize
        (Mono.Cecil IL rewriting)                                         └─ poc / report / ui / webui
                     │                                                              │
        Docker image: app + /coverage_shm/bitmap (tmpfs)  ◀── mmap / HTTP ──────────┘
```

Data contracts between them are **implicit**: the grammar path emits `grammar.py`/`dict.json`/`templates.export.json` in a directory the engine reads by convention; the prep path emits `/shm/*` endpoints and `X-Coverage-Delta`/`X-Exception-*` headers the engine expects; auth is a separate JSON file. Nothing type-checks these contracts, and a break in any one degrades silently to "fewer bugs found" rather than an error.

---

# Subsystem Reviews

For each subsystem: current architecture, strengths, weaknesses, what blocks universality, what blocks deeper bugs, and the recommended redesign.

---

## 1. Instrumentation & IL Rewriting

> **✅ Implementation status (partial):** Top-20 item **#3 (zero-edit `DOTNET_STARTUP_HOOKS` instrumentation + load-time linking)** is now implemented as the default `--inject-mode hook`. A generated self-contained `UpsideFuzz.Coverage` assembly (`fuzz-prep-multi.py::generate_startup_hook_assembly`) is wired via `DOTNET_STARTUP_HOOKS` + `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`, so the target's `Program.cs`/`Startup.cs`/`.csproj` are never edited (`_inject_into_startup_cs`, `_detect_builder_name`, `_detect_app_name`, `patch_all_csprojs` are bypassed in hook mode). An `AppDomain.AssemblyLoad` handler links assemblies **as they load**, fixing weakness **#3** (silent lazy-assembly coverage loss) and mitigating **#1** (Docker source-edit fragility). Top-20 **#4 (self-verifying, fail-closed instrumentation)** is now also done: `/shm/health` reports facts (`shm_bound`, `mode`, `total_classes`, `linked_assemblies`, `app_assemblies`) rather than a verdict — SharpFuzz's `Trace` type lives only in `SharpFuzz.Common.dll`, never in the app's own IL-rewritten assemblies, so "is assembly X linked" can't be measured by type reflection on the .NET side (an earlier draft of this got that wrong; caught by the E2E fixture before it shipped). The actual fail-closed decision is made engine-side, in `void/go/coverage.go::checkCoverageHealth`: after templates load, it sends a few real unmutated warm-up requests and checks whether the shared bitmap actually gains new edges. If it doesn't (despite `shm_bound=true`), the engine refuses to start — `-allow-degraded-coverage` overrides this. Still open in this subsystem: Docker is still required (weakness #1 — non-Docker host mode is Top-20 #6), regex Dockerfile detection (#5), the hardcoded framework denylist (#4), and AOT/trimmed targets (#6). Note the hook-mode middleware is *outermost*, so production-mode `X-Exception-Type` fidelity for apps with a swallowing exception handler is slightly reduced vs. `--inject-mode source` (which is retained for exactly that case). The subsections below are retained as design rationale.

### Current architecture
`fuzz-prep-multi.py::MultiProjectAnalyzer` scans `*.csproj`, skips test projects by name/path substring (`'test' in csproj_lower`), classifies `.cs` files as "business logic" by filename/dir heuristics (`_is_business_logic`, `BUSINESS_PATTERNS`), collects namespaces, and detects Docker/builder conventions via regex (`_detect_last_stage`, `_detect_publish_dir`, `_detect_source_stage`, `_detect_builder_name`, `_detect_app_name`). It then generates a 4-stage Dockerfile that builds `instrumentor/Program.cs` (SharpFuzz + Mono.Cecil) and runs it over each app DLL with `--instrument-all-user-code`. `instrumentor/Program.cs::ShouldInstrument` decides per-type inclusion via prefix/substring filters. `generate_multi_coverage_helper` emits `CoverageExtensions.cs` (SHM allocation + `UseCoverageMiddleware`), and `inject_multi_shm_endpoints` patches `Program.cs`/`Startup.cs`.

### Strengths
- SharpFuzz/Cecil IL rewriting gives **true basic-block edge coverage** — a real grey-box signal most REST fuzzers (Schemathesis, RESTler, Dredd) lack entirely. This is the project's core technical asset.
- The 4-stage Docker build cleanly separates instrumentor build → publish → instrument → runtime, and keeps the SDK out of the runtime image.
- `ShouldInstrument` has hard-won, correct exclusions for startup-time probes (`Program+<>c`, `.cctor`, `<Main>`) that would otherwise fire before the SHM pointer is bound and crash the app with `AccessViolationException` (documented from the real Bitwarden failure). This is subtle and right.
- The move from silent `|| true` to fail-loud `exit 1` on instrumentation failure is the correct instinct.

### Weaknesses & architectural limitations
1. **[HIGH] Docker is mandatory.** The entire coverage channel assumes a `/coverage_shm` tmpfs volume and a container. There is no in-process or `dotnet`-attach path. A researcher who wants to fuzz a locally-running API, an Azure Functions app, a self-contained single-file publish, or a Windows-only target cannot use grey-box mode at all. This is the #1 universality blocker.
2. **[HIGH] "Business logic" file heuristics are naming-convention theater.** `BUSINESS_PATTERNS` keys off `*Controller.cs`, `*Service.cs`, etc. This drives namespace collection, which historically drove the allowlist. Any app that doesn't follow these names (minimal APIs in `Program.cs`, vertical-slice/feature folders, F#, source-generated endpoints, MediatR-only apps) gets under-detected. The mitigation (`--instrument-all-user-code`) is now the default and is *better*, which raises the question: **why does the file-classification machinery still exist and gate namespace collection at all?** It's legacy complexity that should largely be deleted (see Simplify).
3. **[HIGH] Instrumentation correctness is invisible after the build.** `verify_coverage.sh` exists but is a post-hoc separate step. There is no guarantee, per assembly, that (a) it was actually rewritten, (b) its `SharpFuzz.Common.Trace.SharedMem` got linked by `SyncSharpFuzz()` reflection, and (c) edges actually increment for real traffic. `SyncSharpFuzz` relies on `AppDomain.CurrentDomain.GetAssemblies()` at request time — assemblies loaded lazily *after* first sync (plugin modules, SimplCommerce-style dynamically-loaded modules) may never be linked, silently losing their coverage. There is no per-assembly "linked/writing" telemetry.
4. **[MED] Framework-prefix skip list is a hardcoded denylist.** `instrumentor/Program.cs` `frameworkPrefixes` and `fuzz-prep-multi.py` exclusions are static string lists (`System.`, `Microsoft.`, `Newtonsoft.`, `Npgsql.`, …). Any target using a vendored/renamed dependency, or legitimately shipping code under `Microsoft.*` (eShopOnWeb is `Microsoft.eShopWeb`), forces special-casing. The allowlist substring match (`fullName.Contains(ns)`) is the documented Bitwarden footgun (`Bit.Core` ⊄ `Bit.Commercial.Core`).
5. **[MED] Regex Dockerfile adaptation is brittle.** `_detect_source_stage` returns the *last* `COPY --from=`, `_detect_publish_dir` greps one `dotnet publish -o`. Multi-project Dockerfiles, `ARG`-parameterized stages, heredocs, `buildx` bake files, non-`dotnet publish` builds (NativeAOT, `dotnet pack`) will misdetect and produce a broken image.
6. **[MED] No support for NativeAOT / ReadyToRun / trimmed single-file.** Cecil rewriting requires managed IL DLLs present at publish. AOT-compiled or trimmed targets have no rewritable IL, and the pipeline will produce an uninstrumented-but-passing image.

### What prevents reuse on arbitrary projects
Mandatory Docker; regex-based Dockerfile/build detection; naming-convention business-logic detection; hardcoded framework denylist; silent per-assembly linking failures; no AOT/trimmed support.

### What prevents deeper bugs
Even when instrumentation succeeds, coverage is **binary edge-presence** (below), so the instrumentation quality ceiling is low regardless. Also: only the app's own assemblies are instrumented — but many real bugs live in the *boundary* with framework serializers/validators, which are deliberately (and necessarily) skipped, so the fuzzer is blind to *why* a given input flips a branch inside model binding.

### Recommended redesign
- **Ship a `.NET` startup module (NuGet analyzer/hosting package), not a Python code generator.** Replace `CoverageExtensions.cs` string-emission with a real package `UpsideFuzz.Coverage` that the target references (or that is injected via `startupHook` `DOTNET_STARTUP_HOOKS`, which needs **zero source edits** — see below). This removes `_inject_into_startup_cs`, `_detect_builder_name`, `_detect_app_name` entirely.
- **Prefer `DOTNET_STARTUP_HOOKS` for injection.** A startup hook is a managed entry point .NET runs before `Main`, set by an env var, requiring no code edits, no `Program.cs` patching, no rebuild of the app project. Combined with an assembly-load callback (`AssemblyLoadContext.Default.Resolving`/`AssemblyLoad`) it can instrument-on-load with Cecil or link SharpFuzz for **lazily loaded** assemblies too, fixing weakness #3.
- **Make instrumentation self-verifying and fail-closed at runtime.** On first request, the coverage module should assert ≥1 edge from ≥1 app assembly and expose `/shm/health` reporting `{assembly: linked|writing|silent}` per DLL. The engine refuses to start (or loudly warns) if health is degraded.
- **Add a non-Docker host mode** with the same startup-hook, using a named shared-memory segment (cross-platform: `MemoryMappedFile.CreateOrOpen` on Windows, `/dev/shm` on Linux) so grey-box works without containers.
- **Move the denylist to an allowlist-by-exclusion computed from the deps graph:** read the target's `.deps.json` to know exactly which assemblies are first-party vs. NuGet, instead of guessing from namespace prefixes.

**Complexity:** High (startup hook + load-time instrumentation is real work). **Benefit:** This single change is what turns "works on our 4 curated targets" into "works on arbitrary .NET." **Priority: P0.**

---

## 2. Coverage Feedback (SHM bitmap, middleware, readers)

> **✅ Implementation status (partial):** Top-20 items **#1 (AFL hit-count buckets + bucketed virgin map)** and **#2 (single-scan, first-observer-wins per-request attribution)** are now implemented. Coverage novelty is bucketed on both sides (`coverage.go::countClass`/`SHMCoverageReader.GetEdges`; `CoverageExtensions.cs::CountClass`/`MergeAndCountNovel`), and the middleware's old double global 256KB before/after scan is replaced by a single post-pipeline merge against a shared virgin map. This resolves weaknesses **#1** and **#4** below in full and substantially mitigates **#3** (concurrency smearing — credit for each new bucket now goes to exactly one request instead of all concurrent ones). Weakness **#2** (per-*input* path novelty) remains open. Top-20 **#17 (bitmap sizing from real instrumented count; drop reset hack; true coverage %)** is now also done (partial), addressing weaknesses **#5** and (in part) **#6**: `instrumentor/Program.cs` appends the real instrumented-*type* count (SharpFuzz exposes no public branch/edge count, so type count is the proxy) to a `.upsidefuzz_instrumented.jsonl` meta file next to the app's DLLs at build time; `fuzz-prep-multi.py::ResolveShmSize` reads it and sizes `SHM_SIZE` from real app surface (~512 bytes/type, rounded to a power of two, clamped to [64KB, 8MB]) instead of a fixed 256KB guess, whenever the `SHM_SIZE` env var isn't pinned explicitly. `void/go/coverage.go::SHMCoverageReader.Init` was fixed to trust the real on-disk SHM file size rather than truncating it down to a possibly-stale `-coverage-bitmap-size` flag — a real latent bug this change surfaced (truncating a properly-sized file silently drops real coverage from the untruncated remainder). The periodic full-bitmap reset (`worker.go::shouldResetCoverageBitmap`) now requires both high saturation AND genuine stagnation (no new edge for ≥30s), not saturation alone, so it no longer discards progress mid-productive-run purely because a byte-percentage crossed 85%. `coverageSaturationPct`'s denominator is unchanged (`baselineEdgesCeiling`, falling back to `coverageCapacity`) — dividing by instrumented *type* count directly would mix units (types vs. bytes/edges) and produce a meaningless percentage, so instead `coverageCapacity` itself is now real-surface-derived, which is what actually closes the "guessed denominator" gap. The subsections below are retained as the design rationale.

### Current architecture
`CoverageExtensions.cs` allocates a 256KB bitmap (file-backed mmap on `/coverage_shm/bitmap`, else `AllocHGlobal`). `SyncSharpFuzz()` reflects over loaded assemblies and points every `SharpFuzz.Common.Trace.SharedMem` at the same buffer. Edge count = bytes `> 0` (`GetCoverageStats`, `for i: if b[i]>0 edges++; hits+=b[i]`). `UseCoverageMiddleware` records `before=GetCurrentEdgeCount()`, runs the pipeline, records `after`, and returns `X-Coverage-Delta`/`X-Coverage-Edges` headers plus `X-Exception-Type/Message` (with the production-mode short-circuit for fuzz requests). The Go side (`coverage.go`) reads via `SHMCoverageReader` (mmap/file, word-scan for new bytes, cumulative `seen[]`) or `HTTPCoverageReader` (`/shm/coverage`).

### Strengths
- Direct mmap read from a sidecar is a legitimately fast, low-overhead coverage channel — better than any HTTP-polling REST fuzzer.
- The per-request `X-Coverage-Delta` header is a clever way to get near-exact attribution without a round trip.
- The production-mode exception short-circuit (emit own 500 with `X-Exception-*` before `Response.HasStarted`) is a real, correct fix for a genuinely hard ASP.NET problem.
- Word-level zero-skipping scan in `SHMCoverageReader.GetEdges` is the standard AFL optimization, correctly implemented.

### Weaknesses & architectural limitations
1. **[CRITICAL] The coverage signal is binary edge-presence with no hit-count buckets.** AFL/libFuzzer/honggfuzz bucket each edge's hit count into log-scale classes (1, 2, 3, 4–7, 8–15, 16–31, …) so that a loop executing 1 vs. 50 vs. 5000 times produces *different* coverage and drives the fuzzer deeper. UpsideFuzz counts `b[i] > 0` — a byte that goes from 1 to 200 is *no new coverage*. SharpFuzz *writes* AFL-style bucketed counts into the bitmap, but the counting logic throws that away. **This is the single biggest reason the fuzzer will plateau early on business logic with loops, retries, pagination, and state machines.** It cannot tell "processed 1 item" from "processed 10,000 items."
2. **[CRITICAL] "New edge" is defined globally and monotonically (`seen[]`), so per-input novelty vanishes after saturation.** Once every edge of an endpoint has been touched once, `GetEdges` returns a flat number forever, `X-Coverage-Delta` is 0, and every subsequent input — including ones taking wildly different *paths* through already-seen blocks — looks identical. There is no notion of *path* or *edge-set-per-input*; the fuzzer only knows "did the global union grow." Real AFL compares each input's bitmap against the virgin map to detect *new edges for this input even if globally old* is impossible, but it *does* detect new buckets. UpsideFuzz has neither buckets nor per-input maps.
3. **[HIGH] Concurrency smearing corrupts attribution (acknowledged in ARCHITECTURE.md, under-sold as "beneficial").** `before`/`after` in the middleware read a *global* counter while N requests run concurrently; deltas are cross-attributed. The doc frames this as a feature ("occasionally over-rewards a seed"). In reality it means energy assignment is noise-dominated above ~4 concurrent workers, and the MOpt weights, seed energy, and epoch rebalancing are all learning from a corrupted signal. A per-request thread-local edge set (SharpFuzz supports `Fuzzer.Instrument` with custom trace) would fix attribution but is expensive; a per-request bitmap diff via a small thread-local scratch region is the standard answer.
4. **[HIGH] `GetCurrentEdgeCount()` scans the full 256KB twice per request.** `GetCoverageStats` iterates all `SHM_SIZE` bytes; the middleware calls it at `before` and `after` for *every* request. That's ~512KB of scanning per request in the hot path, inside the request pipeline, defeating much of the "zero-overhead" claim and adding latency that then perturbs the adaptive-concurrency and time-based-SQLi oracles.
5. **[MED] 256KB fixed bitmap + hash-collision handling by periodic reset.** `worker.go` resets the whole bitmap when >85% full "because collisions dominate." Resetting throws away the global frontier and restarts saturation detection — a blunt instrument. Large apps (Bitwarden, BTCPay) will collide heavily in 256KB. AFL scales the map (up to 64K–1M edges) and uses collision-aware sizing; UpsideFuzz should size the map from the *instrumented edge count* known at build time.
6. **[MED] Saturation denominator is a heuristic (`baselineEdgesCeiling`).** `coverageSaturationPct` divides by the edge count reached at end of Baseline epoch. That's a reasonable proxy but it is not the true reachable-edge count (which is knowable: the instrumentor counts inserted probes). Reporting "% coverage" against a guessed denominator produces misleading dashboards and misleading paper numbers.

### What prevents deeper bugs
Binary edges + global monotonic novelty + concurrency smearing together mean the "coverage-guided" loop is, in practice, closer to "coverage-*aware* random testing." The engine's sophisticated energy/MOpt machinery is starving on a low-resolution signal. **Fixing coverage resolution is the highest-leverage change for bug-finding depth in the entire project.**

### Recommended redesign
- **Adopt AFL hit-count buckets.** Keep SharpFuzz's raw counts; in both the C# `GetCoverageStats` and Go `SHMCoverageReader`, classify each byte into 8 buckets and track a *bucketed* virgin map. Novelty = a new bucket for any edge. This is a small, localized change with outsized impact.
- **Per-request edge set instead of global before/after.** Give each request a thread-local scratch bitmap (SharpFuzz can be configured per-thread, or wrap the trace); the middleware diffs scratch→global and reports the request's *own* new edges. Kills concurrency smearing and the double full-scan (diff only touches touched bytes).
- **Size the bitmap from the real edge count** emitted by the instrumentor (write `edges_instrumented` into a build artifact the engine reads); drop the periodic-reset hack.
- **Report true coverage %** against instrumented-edge count, not the baseline ceiling.

**Complexity:** Medium. **Benefit:** Very high — unlocks depth for every downstream component. **Priority: P0.**

---

## 3. Grammar Generation (RESTler + enhance-grammar.py + SSE)

> **✅ Implementation status:** Top-20 items **#9 (first-party OpenAPI→typed-grammar compiler; RESTler retired)** and **#10 (Roslyn syntax-tree analyzer)** are now implemented as `grammarc/` (Python, stdlib-only) and `analyzer/` (C#, `Microsoft.CodeAnalysis.CSharp`), invoked by the rewritten `compile-grammar.sh`. RESTler, its Docker provisioning, `enhance-grammar.py`'s regex `SourceExtractor`, and the manual compile→cp→`export-templates.py` three-step dance are gone from the primary path — one command (`compile-grammar.sh <swagger> [--src <dir>] [--out <dir>]`) writes `templates.export.json`+`dict.json` directly, with **no Docker involved in grammar compilation at all** (Docker remains needed only for the target's own instrumented container). `analyzer/` is **syntax-tree-only** (no `MSBuildWorkspace`/NuGet-restore semantic model, an explicit scoping choice for reliability across arbitrary target repos) but still fixes weakness #2 below by construction: constraints are keyed by `(fully-qualified type, property)`, not a global canonicalized property name — verified directly against eShopOnWeb, which has *two different classes both named* `CreateCatalogItemRequest` (one real DTO with no constraints, one unrelated UI model with real `[Required]`/`[Range]`), where the old regex extractor's global-name merge would have silently cross-contaminated them. `dependencies.py` adds first-party producer/consumer inference (previously 100% delegated to RESTler's compiler) via path/name convention, de-risked by the fact that `void/go/sequence.go` already independently re-derives path-based chaining at runtime regardless of grammar-supplied `reads`/`writes`. Verified equivalent-or-better against both real targets: eShopOnWeb (8/8 templates, 0 skipped, matching the RESTler baseline exactly) and Bitwarden (599/599 templates, 0 skipped, matching the RESTler-generated grammar's template count exactly, with 750 endpoints and 284 operations gaining real type-scoped Roslyn constraints — parsed 3,864 source files in ~5 seconds total, no Docker pull). A real, previously-undocumented bug was found and fixed as part of this migration — see Inconsistencies item #7 below. Remaining open items in this subsystem: no structure-aware mutation over a typed model (#14), no state-reward sequence search (#12) — the subsections below are retained as design rationale for those.

### Current architecture
`compile-grammar.sh` sanitizes Swagger (`sanitize-swagger-for-restler.sh`), invokes the **RESTler compiler** (external binary in `restler_bin/`) to produce `grammar.py` + `dict.json`, then `enhance-grammar.py` post-processes: `OpenAPIExtractor` pulls enums/formats/min-max/pattern; `SourceExtractor` regex-scrapes C# `[StringLength]`/`[Range]`/`[RegularExpression]`/enum declarations/FluentValidation; `DictionaryEnhancer` merges; `inject_multipart_seeds` adds multipart templates. `export-templates.py` converts `grammar.py` → `templates.export.json`, which `template.go` parses into segment lists.

### Strengths
- Enriching a black-box grammar with *server-side validation constraints* (both OpenAPI and C# attributes) is exactly the right idea — it's how you get past 400-rejection walls into real logic. This is a real differentiator vs. Schemathesis (which only sees the spec).
- Multipart seed generation is a nice touch most REST fuzzers ignore.
- The dictionary/runtime-value merge model (`store.go`) is sound.

### Weaknesses & architectural limitations
1. **[CRITICAL] Hard dependency on RESTler as the grammar compiler.** RESTler is Microsoft's black-box tool; you are inheriting its OpenAPI coverage, its producer-consumer inference, its bugs, its Python-emitting grammar format, and its maintenance cadence. Everything downstream (`export-templates.py`, `template.go`'s segment model) is shaped around RESTler's `grammar.py`. This caps request quality at "what RESTler can express," forces a Python-parses-Python-emits-JSON-parsed-by-Go pipeline (three languages, two serialization hops), and makes the whole grammar path opaque and fragile. A grey-box fuzzer that wants to *beat* RESTler should not be *built on* RESTler.
2. **[HIGH] "Roslyn analyzer" / "Semantic Source Extraction" is regex, not semantic.** Despite `AI_CONTEXT.md`, the README, and the arxiv paper invoking Roslyn, there is **no `Microsoft.CodeAnalysis` anywhere in first-party code.** `SourceExtractor` (`enhance-grammar.py`) is line-regex over stripped C#. It cannot resolve types across files, follow inheritance/partial classes, understand generics, custom `ValidationAttribute`s, `IValidatableObject.Validate`, conditional validation, or FluentValidation beyond simple chains. It attributes constraints by *canonicalized field name* globally, so a `Name` with `[StringLength(50)]` in one DTO constrains *every* `name` field in the app. This is a correctness and precision problem, and a **documentation-vs-implementation inconsistency that should be recorded and fixed** (either build the Roslyn analyzer or stop claiming it).
3. **[HIGH] No schema-aware structural mutation.** `template.go` renders a flat segment list; mutation happens on string/JSON values (`mutation_engine.go`). There is no typed model of the request body, so the fuzzer cannot do *structure-aware* mutations that respect required/optional, oneOf/anyOf, discriminators, or nested object schemas the way EvoMaster (which builds a full typed genome) or a schema-driven Schemathesis (Hypothesis strategies) can. Deep-nested and polymorphic bodies are mutated blindly.
4. **[MED] Constraint extraction is one-directional and lossy.** Constraints inform *valid* value generation but the engine doesn't use them for *boundary* generation systematically (e.g., "max length 50" should auto-generate exactly 50, 51, 49, and 2^31 length inputs targeted at *that* field). Right now boundaries are generic (`mutations.go` overflow category), not constraint-derived per field.
5. **[MED] Producer-consumer inference is inherited from RESTler + heuristic name-matching (`inferDependencyKeys`).** The `sequence.go`/`store.go` dependency graph is rebuilt with fuzzy name singularization (`fooId`, `foo_id`, path-segment guessing). This works on clean APIs and misbatches on APIs with non-obvious id naming, composite keys, or non-REST resource nesting.

### What prevents reuse / deeper bugs
The RESTler dependency and regex SSE make grammar quality target-sensitive and hard to debug; the lack of a typed body model caps structural bug discovery (deserialization edge cases, polymorphism, discriminator confusion).

### Recommended redesign
- **Build a first-party OpenAPI→grammar compiler in Go (or a single C# tool), retire RESTler.** Parse OpenAPI 3.x directly (kiota/NSwag/`Microsoft.OpenApi` for the C# route) into a *typed request model* with full JSON Schema fidelity (required, enums, formats, min/max, patterns, oneOf/anyOf/discriminator, nested refs). This collapses three languages into one, makes the grammar debuggable, and lifts the request-quality ceiling above RESTler.
- **Build the actual Roslyn analyzer** as a separate `dotnet` tool that runs against the target solution and emits per-*DTO-property* constraints (fully type-resolved), custom validators, `[Authorize]` metadata, and route attributes. Feed it into the typed grammar. This is where "Semantic Source Extraction" becomes real.
- **Structure-aware mutation** over the typed model: per-field boundary generation from constraints, schema-respecting and schema-*violating* variants, discriminator/`$type` fuzzing driven by the real type graph (which the Roslyn pass knows).

**Complexity:** High (this is a quarter of the project). **Benefit:** Removes the biggest external dependency, makes grammar quality universal, unlocks structural bugs. **Priority: P1** (after coverage + instrumentation, because those gate the feedback that makes better grammar pay off).

---

## 4. Fuzzing Engine — Scheduling, Mutation, Corpus (`fuzzer.go`, `worker.go`, `mutation_engine.go`, `mutations.go`)

> **✅ Implementation status (partial):** Top-20 **#14 (structure-aware mutation, partial)** and **#11 (CMPLOG-lite / 400-body mining)** are now implemented. `void/go/types.go`'s `Segment` struct carries optional `min_length/max_length/minimum/maximum/pattern/enum_values` fields, sourced from `grammarc/oas.py::FieldHint` (OpenAPI + Roslyn-merged, see subsystem 3) and threaded through `mutateAny`/`mutateHavoc`/`mutateInt`/`mutateNumber`/`mutateStringCategorized` (all now take an optional `*Segment` hint, additive not a replacement — nil/absent hints behave exactly as before, so old `templates.export.json` files without these fields are unaffected). When present, exact boundary values (`{min-1,min,min+1,max-1,max,max+1}`, exact-length strings, valid/invalid enum near-misses) are blended into the existing generic candidate pools rather than replacing them. Verified on eShopOnWeb: the same live-fuzz session found the same known `pageSize` overflow bug class **~7x more often** in the same time budget (124 vs. 18 crash hits) with higher coverage, after this change. Separately, `worker.go::mineClientErrorFields` now parses ASP.NET's ValidationProblemDetails/ModelState 400-body shape (`{"errors":{"Field":["msg"]}}`) plus free-text enum-hint phrasing (`"must be one of [...]"`) and feeds extracted values into `RuntimeStore.addValue` — the same pool `custom_payload` rendering already draws from — closing a loop that was previously write-only (`recordClientErrorSample` stored samples for the human-readable report only, nothing fed back into the engine). Full structure-aware mutation over a typed body model (deserialization/polymorphism-class bugs) remains open — this is boundary-value blending on the existing flattened-segment model, not the deeper typed-genome rework #14's original framing envisioned.

### Current architecture
Time budget split into epochs (`worker.go::mainLoop`): Baseline 5% → Harvest 25% → Deterministic 25% → Havoc 35% → Splicing 10%, with adaptive rebalancing that steals fraction from unproductive epochs into Havoc. Templates picked by weighted health/dependency/source priority (`pickWeightedTemplate`, `templateHealthWeight`). Seeds live in a corpus with Fenwick-tree energy sampling (`addOrBoostSeed`, `minimizeCorpus`), energy boosted by a `log2(requests)` "surprise" factor. Mutations are MOpt-weighted categories (`mutations.go`) with hit-rate-driven weight updates; `mutateJSONBody` does structural JSON havoc including `$type` gadgets; `mutatePath` hits ID-like path segments.

### Strengths
- The epoch model + adaptive rebalancing + Fenwick energy sampling + surprise factor is a **thoughtful, AFL++-informed scheduler** — genuinely more sophisticated than any other REST fuzzer's request selection.
- MOpt-style category weighting driven by real coverage hits is the right mechanism, and the `weight = 1 + hitRate*4` formula is reasonable.
- Endpoint health weighting (down-weight 4xx-walls, crash-loops, edge-stalls, share-caps) is mature and reflects real operational learning.
- `mutateJSONBody`'s stacked structural ops (type-confuse → deep-nest → array-overflow → `$type`) can synthesize complex payloads that beat static dictionaries — a real strength.
- Crash-boost / crash-replay to intensify around a fresh crash is smart.

### Weaknesses & architectural limitations
1. **[HIGH] Everything here learns from the weak coverage signal (§2).** The scheduler is a Ferrari on a dirt road: surprise factor, energy boosts, MOpt hit-rates, and epoch rebalancing all key off `edgeShare`/`CoverageDelta`, which is binary + smeared. Upgrading coverage (§2) will make this machinery *retroactively* much more effective with no scheduler changes.
2. **[MED] Mutation is value-centric, not structure- or grammar-aware.** `mutation_engine.go` mutates rendered strings/JSON after the template is flattened to a raw byte request (`renderTemplate` → `parseRawRequest`). It has thrown away the typed schema by then. It cannot target "the field the server just complained about," and cannot do coverage-directed *field* selection. ✅ Dictionary-token-from-comparison (AFL's `CMPLOG`/RedQueen) landed as #21: `instrumentor/Program.cs::CmpLogInstrumentor` records `String.Equals`/`StartsWith`/`EndsWith`/`Contains`/`op_Equality` operands and literal-vs-compare integers straight out of the target's own IL, fed back into `mutateStringCategorized`/`mutateInt` via `/shm/cmplog` — but it's comparison feedback, not field-targeted feedback: the harvested values are still spliced in blind (any string field, any int field), not routed to "the specific field whose comparison produced them."
3. **[MED] No deterministic havoc stages in the AFL sense.** "Deterministic" epoch applies one random mutation per field probabilistically; it is not the exhaustive bit-flip/arith/interesting-value walk AFL calls deterministic. Fine for REST (byte-flips rarely matter on JSON), but it means the fuzzer misses systematic per-field boundary coverage that a constraint-driven generator would nail.
4. **[MED] Splicing is shallow (10%, "one template + havoc").** It reuses one seed's template with havoc rather than truly crossing two request *bodies* at the JSON-subtree level. Cross-pollination of structural fragments (EvoMaster-style) would be stronger.
5. **[LOW] No persistent corpus across runs.** Corpus is in-memory, pruned at 500, discarded at exit. A researcher re-running against the same target starts cold every time. AFL/libFuzzer persist and reuse a corpus directory — a major productivity and reproducibility feature.

### Recommended redesign
- **Add comparison/`CMPLOG`-style feedback.** Instrument (or middleware-capture) interesting string/int comparisons and validation-failure messages; extract expected tokens (enum names, required field names, format hints from 400 bodies) into the runtime dictionary automatically. The engine already parses 400 bodies (`recordClientErrorSample`) — mine them for "the field 'X' is required" / "must be one of [...]" and feed back. This is cheap and hugely effective on validation-heavy APIs.
- **Move mutation above the flattening step** so it operates on the typed model (§3), enabling field-targeted, constraint-derived, and structure-preserving/violating mutation.
- **Persist the corpus + coverage frontier to disk** (a `corpus/` dir keyed by target) for warm restarts and cross-run accumulation.
- **Structural splicing** at the JSON-subtree level.

**Complexity:** Medium. **Benefit:** High once coverage is fixed. **Priority: P1.**

---

## 5. Stateful Sequences & Entity Harvesting (`sequence.go`, `store.go`)

> **✅ Implementation status (partial):** Top-20 **#12 (state-reward sequence search)** is now implemented, addressing weakness **#1** and part of **#3** below. `sequence.go::sequenceStateSignature` computes a coarse workflow-*shape* signature — the ordered `(method, normalized-path, status-class)` triples of a `SequenceState`'s `History` — deliberately collapsing concrete IDs/payloads (via `normalizeEndpointPath`) and exact status codes (via `statusClass`'s 2xx/3xx/4xx/5xx buckets) so that two sequences reaching the *same shape* via different data are recognized as the same state. `enqueueSequenceFollowups` tracks every distinct signature seen this run (`f.seenStateSigs`); reaching a never-seen shape awards a state-novelty energy bonus (`stateNoveltyBonus`, comparable in scale to a solid multi-edge coverage hit) and one extra fanout branch of search budget — rewarding *new states*, not just new coverage edges, is the concrete mechanism DeepREST/EvoMaster use for logic-bug depth that plain edge-coverage reward can't distinguish (a 3rd identical GET after a POST looks the same to the coverage bitmap as the 1st, but is not new information for the sequence search). `maybePersistSequence` also dedups persisted on-disk workflow reports by final shape (`f.persistedWorkflowSigs`), closing part of weakness **#3** ("no dedup of equivalent workflows"). This is intentionally coarse: there is still no explicit resource-lifecycle model (created→modified→deleted→invalid) or typed state graph, and fanout is not yet coverage-directed toward specifically *unreached* consumers — full state-graph search (weakness **#1**'s complete framing) remains open.

### Current architecture
On a successful write, `enqueueSequenceFollowups` extracts entity IDs (`extractEntityIDs` from body `id`/`Id`/`data[].id` and `Location` header), binds them into a `SequenceState`, finds consumers via a dependency index (`depConsumers`/`idConsumers`) plus same-family path matching (`findFollowups`), and fans out follow-up requests (POST→GET→PUT→DELETE priority via `followupPriority`), cloning state per branch up to `SequenceMaxDepth`. Deep successful workflows are persisted as JSON+curl (`persistWorkflow`). `store.go` maintains a runtime value store + relation graph with correlated-value picking.

### Strengths
- Real runtime value harvesting + producer→consumer chaining is exactly what separates a stateful API fuzzer from a dumb one, and this is a solid, working implementation.
- Per-branch state cloning with provenance, energy accumulation, and workflow persistence (repro scripts) is excellent for real bug reporting.
- The fallback to fuzzed IDs when a producer fails (so consumers still get tested for auth/validation) is a genuinely good idea.

### Weaknesses & architectural limitations
1. **[HIGH] The state model is a flat key→value map, not a state graph.** There is no model of resource lifecycle (created→modified→deleted→invalid), no notion of "this sequence reached a distinct application state," and coverage feedback is per-request, not per-*sequence-state*. This is precisely where **DeepREST** and EvoMaster's state-based search win: they treat reaching a new *state* as the reward. UpsideFuzz rewards new *edges*, so it under-explores the state space (multi-step business-logic bugs: coupon-then-refund, transfer-then-reverse, workflow order violations).
2. **[MED] Entity-ID extraction is `id`-name-centric.** `extractEntityIDs` looks for literal `id`/`Id`/`data[]`. APIs returning `guid`, `slug`, `number`, `reference`, HAL `_links`, or nested resource handles under other names are missed, breaking chains. `inferResourceIDKeyFromPath` similarly guesses.
3. **[MED] No sequence-level coverage or dedup.** Sequences are persisted if "mostly successful and depth≥2 and some energy," but there's no dedup of *equivalent* workflows nor a search that targets *unreached* consumers. Fanout is breadth-first by static priority, not coverage-directed.
4. **[LOW] Sequence depth capped at 3.** Many real workflows (checkout, KYC, multi-approval) are longer.

### Recommended redesign
- **Introduce an explicit state abstraction and reward reaching new states**, not just new edges. Even a coarse state signature (set of resources created + their status transitions observed) turns the sequence engine into a state-space explorer. This is the concrete way to chase DeepREST/EvoMaster on logic bugs.
- **Generalize entity extraction** to schema-typed identifiers (from the typed grammar of §3) and HAL/JSON:API/OData link conventions.
- **Coverage-directed fanout:** prioritize consumers whose edges are unreached; dedup workflows by state signature.

**Complexity:** Medium–High. **Benefit:** High for logic/BOLA bug depth. **Priority: P1.**

---

## 6. Vulnerability Oracles (`oracle.go`) — the crown jewel

> **✅ Implementation status (partial):** Top-20 **#18 (differential oracles)** is now implemented, addressing weakness **#3** below. `oracle.go::maybeEnqueueDifferentialProbes` fires after a successful, resource-scoped request under an authenticated identity, but *only* on endpoints with STRONG evidence of auth enforcement (`authRequiredEndpoints` strength 2 — a plain, credential-free request was previously rejected with 401/403). That precondition is what makes this a distinct bug class from the existing `authbypass` oracle: `authbypass` already tests the literal unauthenticated replay, so if a *confusion* variant succeeds despite the literal replay having failed, the confusion technique itself — not general laxness — is what mattered. Four techniques, each an independent NoAuth probe: **verb** (GET→HEAD only — HEAD is semantically "GET minus body", so a bypass there is a genuine same-data finding; mutating verbs are excluded since they'd change what the request *does*, not just how it's authorized), **content-type** (identical body bytes, `Content-Type` swapped from `application/json` to `text/plain` — some auth/CSRF middleware only gates requests declared as JSON), **route-case** (`swapPathSegmentCase` flips the first letter of each path segment — ASP.NET routing is case-insensitive by default, but custom auth-attribute/WAF/reverse-proxy path matching sometimes isn't), and **param-location** (`appendQueryParam` duplicates the path-embedded resource id as a same-named query parameter — tests whether a differently-sourced same-named parameter routes through a different model-binding/authorization path). Findings reuse `recordAccessControlFinding` with the technique folded into the dedup key and triage `technique` field. The param-location technique is deliberately narrow: it duplicates the *same* id rather than a differently-*owned* one, since testing true cross-tenant object access needs the ownership-matrix infrastructure that is weakness **#1**/Top-20 **#8** (still open) — so param-location here tests routing/binding confusion, not BOLA. The subsections below are retained as the design rationale for the still-open weaknesses.

### Current architecture
Positive oracles beyond 500s: **BOLA/IDOR** (replay a successful authed resource request under every other identity), **broken-auth** (replay with no credentials, gated on endpoints already seen returning 401/403 — `authRequiredEndpoints`), **mass-assignment** (over-post privileged fields, check reflection), and **injection** (time-based SQLi via latency, evaluated SSTI via arithmetic markers, reflected XSS). Findings are de-duplicated, classified (`likely_vuln`/`likely_vuln_high`), and written with origin→shadow identity provenance.

### Strengths
- **This is the most valuable and most differentiated part of the project.** No mainstream open-source REST fuzzer ships BOLA + broken-auth + mass-assignment + positive injection oracles wired into a coverage-guided loop. This is what would make a security researcher adopt it.
- The false-positive engineering is mature: `isTrivialBody`, `looksLikeErrorBody`, `pathHasConcreteResourceID` (digit-bearing tokens only), the auth-bypass precondition (only fire where 401/403 was actually observed), and same-credentials skipping. This shows real offensive-security judgment.
- Response fingerprinting (`stableResponseFingerprint`) for identical-vs-different body scoring is the right BOLA discriminator.

### Weaknesses & architectural limitations
1. **[HIGH] BOLA detection is body-comparison heuristic, not object-ownership-aware.** "Identical body under two identities" is strong; "different 2xx body" is downgraded to `needs_manual_verification` — but real BOLA often returns *different* bodies (each user's own object) and the vuln is that user A can read *object owned by B*. Without seeding *known-B-owned resource IDs* and replaying them under A, the oracle can't distinguish "shared endpoint returning my own data" from "I just read your data." The **A/B resource-ownership matrix** (create object as B, note its ID, request it as A) is the definitive test and is missing.
2. **[MED] Injection oracles are shallow.** Time-based SQLi requires the payload to literally contain `sleep(`/`waitfor delay`/`pg_sleep(`/`benchmark(` (`isTimeBasedSQLiHit`) — but those must first survive into the query. No boolean-based / error-based SQLi differential, no out-of-band (OAST/Collaborator-style) detection for blind SSRF/XXE/RCE/log4shell, which is how those are found in practice. `$type` gadgets are sent but there's no oracle confirming deserialization *executed* (only reflection), so RCE-class bugs are shot in the dark.
3. **[MED] No differential oracle.** Sending the same logical request two ways (e.g., param in query vs. body, different content-types, HTTP verb tunneling, case-variant routes) and diffing responses is a rich source of auth-bypass and parser-confusion bugs (see also HTTP request smuggling, `..;/` path confusion). Not present.
4. **[MED] Mass-assignment confirmation requires the server to echo the field back.** Many privilege escalations don't reflect the field (it's written silently). A follow-up *read-back as a lower-privilege identity* or a *behavioral* check (can I now do an admin action?) would catch silent ones.

### Recommended redesign
- **Add an out-of-band interaction server** (built-in OAST) for blind SSRF/XXE/RCE/log4shell/blind-SQLi confirmation — this is table stakes for serious vuln hunting and would massively raise the ceiling on "deep/realistic" findings.
- **Ownership-matrix BOLA:** in multi-identity mode, harvest each identity's created/owned resource IDs and cross-replay them explicitly, rather than only replaying the origin request.
- **Boolean/error-based injection differentials** in addition to time-based.
- **Behavioral mass-assignment confirmation** (read-back / privilege-action probe).

**Complexity:** Medium (OAST is the biggest piece). **Benefit:** Very high for researcher adoption and "deep/realistic" bugs — this is the marketing story. **Priority: P0/P1** (OAST is P0 for the value proposition).

---

## 7. Crash Triage, Clustering, Minimization, Reporting (`crash.go`, `cluster.go`, `triage.go`, `minimize.go`, `report.go`, `poc.go`)

### Current architecture
Two-level dedup: fine-grained `crashSignature` (method+path+status+exception+response-fingerprint, mode-configurable) and root-cause `ClusterKey` (normalized exception message + top *app* stack frame, else `(method,status,route-template)`). Honest classification tiers (`likely_vuln`/`confirmed_unhandled_exception`/`needs_review`/`target_misconfiguration`/`noise`). Per-crash minimization (`minimize.go`), repro verification (`reproCheckCrash`), curl PoC + Mermaid timeline generation.

### Strengths
- The **two-level signature/cluster split is exactly right** and solves the real "933 crashes = 5 bugs" over-counting problem honestly. `cluster.go`'s app-frame extraction (skipping framework frames) is well done.
- The **honest classification taxonomy** (a 500 is not a vuln; DI failures are misconfig; malformed-input parse errors are down-ranked) is *rare and credible* — most tools over-claim. This earns researcher trust.
- Minimization + repro % + auto-PoC + timeline is a real bug-reporting pipeline, not just a crash dump.

### Weaknesses
1. **[MED] Root-cause clustering degrades hard in production mode.** Without a stack trace, clustering falls back to `(method, status, route-template)`, which *under*-clusters (same bug on different routes = different clusters) — the inverse of the signature problem. The production-mode `X-Exception-Message` helps but there's no symbolication/normalization of app frames without dev mode.
2. **[MED] Triage scoring is a hand-tuned additive heuristic** (`+4` for 500, `+1.5` stack leak, etc., `triage.go`). Reasonable but arbitrary and unvalidated; severity numbers will not correspond to real CVSS and shouldn't be presented as if they do.
3. **[LOW] No crash bucket export to standard formats** (SARIF, so results drop into GitHub code scanning / DefectDojo). This is a pure adoption feature.
4. **[LOW] Minimization is field-removal only**, not value-simplification (shrinking a 10k string to the minimal triggering length).

### Recommended redesign
- **SARIF output** for the whole findings set (CI/security-tooling integration).
- **Value-level minimization** (bisect string lengths / numeric magnitudes), not just field removal.
- Keep the taxonomy — it's a strength; just document that severity scores are heuristic, not CVSS.

**Complexity:** Low–Medium. **Benefit:** Medium (adoption + report quality). **Priority: P2.**

---

## 8. Authentication, Identity, Anti-Forgery (`auth.go`, `identity.go`)

### Current architecture
Multi-identity from an auth JSON file (`docs/FUZZER_AUTHENTICATION.md` schema): JWT/API-key/cookie/header identities, weighted/round-robin/random scheduling, guest identity, race-burst probing. JWT/login fallback + auto-reauth on 401 streams (`worker.go`). Anti-forgery token harvesting from HTML and rotation.

### Strengths
- Multi-identity as a first-class concept is what makes the BOLA/auth oracles possible — correct architectural coupling.
- Auto-reauth on token expiry and anti-forgery harvesting handle two real-world friction points (SimplCommerce-style MVC + Identity) that stop most fuzzers cold.

### Weaknesses
1. **[HIGH] Auth acquisition is largely manual (auth file).** For "near-zero config," the tool should be able to *perform a login flow itself* from credentials (OAuth2 password/client-credentials, form login, `/connect/token`) and refresh automatically, for each identity. There's login fallback but the primary path is "paste tokens," which expires and frustrates.
2. **[MED] No OpenID Connect / OAuth2 discovery.** Given `.well-known/openid-configuration` + client creds, identities could be minted automatically. Bitwarden/BTCPay quickstarts show how much manual token wrangling is currently required.
3. **[LOW] No per-identity role/permission model** to inform *which* BOLA pairs are interesting (admin→user is the high-value direction).

### Recommended redesign
- **Credential-based auto-login per identity** (form, OAuth2 flows, custom login-request template) with automatic refresh; make the token file optional.
- **OIDC discovery** for zero-config identity minting.

**Complexity:** Medium. **Benefit:** High for zero-config + researcher friction. **Priority: P1.**

---

## 9. Developer Experience, Portability, Reliability, Maintainability

> **✅ Implementation status (partial):** Top-20 **#7 (E2E CI on a planted-bug sample app)** is now implemented: `.github/workflows/e2e.yml` runs `scripts/e2e-test.sh` on every push/PR — instrument (`fuzz-prep-multi.py`) → build+start the container → verify the zero-edit coverage hook (`verify-hook.sh`) → compile the grammar (`compile-grammar.sh`) → run a short live fuzz session (`void`) → assert `coverage_end_edges > 0` **and** the planted bug (`GET /items?pageSize=<negative>` → `ArgumentOutOfRangeException` → 500) is actually present in `unique-crashes.jsonl`, not just that the pipeline ran without error. The fixture (`fixtures/planted-bug-api/`) is a minimal, DB-free ASP.NET Core minimal-API app, nested under `src/PlantedBugApi/` deliberately (a flat single-project layout collides with the generated Dockerfile's `COPY . ./` + implicit `**/*.cs` glob picking up the tool's own sibling `instrumentor_src/Program.cs`, itself top-level-statements). Building this fixture directly surfaced and fixed three real, previously-unknown bugs across the pipeline (see the Inconsistencies section below): a substring-vs-path-segment bug in `analyzer/RoslynUtil.IsTestPath` excluding any directory merely starting with "test", `analyzer/RouteAuthWalker` never having scanned top-level-statement `Program.cs` files (only class bodies) for minimal-API route registrations, and a bash-3.2-specific unbound-array crash in `compile-grammar.sh` when `--src` is omitted. This is the project's first CI of any kind. The rest of this subsystem's original weaknesses (thin unit-test coverage beyond this one E2E path, three-language pipeline, docs drift) remain open.
>
> Top-20 **#19 (single CLI orchestrator)** is also now implemented (partial — repo hygiene, the other half of #19, is still open): `upsidefuzz.py` wraps the existing pipeline (`fuzz-prep-multi.py` → `docker compose` → `verify-hook.sh` → `compile-grammar.sh` → `void`) behind subcommands (`instrument`/`build`/`up`/`down`/`verify`/`grammar`/`fuzz`) plus an all-in-one `run`, hiding the four-tool/four-language incantations without changing what any of them do. A second, purely additive layer (`Dockerfile.cli` + the `./upsidefuzz` launcher) bundles Python, the .NET SDK, and a prebuilt `void` binary into one image, so a user needs only Docker installed locally — running the tools directly and natively keeps working exactly as documented. Building this via a real Docker-launcher end-to-end run against `fixtures/planted-bug-api/` surfaced and fixed two more real, previously-latent bugs: `compile-grammar.sh`'s `( cd "$ROOT_DIR" && python3 -m grammarc.cli ... )` resolved relative `--out`/`--swagger` paths against the *script's own location* rather than the caller's cwd — silently correct only when they happened to be the same directory (true for every invocation before this), silently wrong (writing output into a location the caller couldn't see) otherwise; and the same `dotnet build` MSBuild-errors-go-to-stdout-not-stderr trap that swallowed the SDK-version-mismatch error this exposed, both fixed and regression-tested from both the repo root and a different cwd. See `docs/CLI.md`.

### Current state
- **[HIGH] No CI, thin tests.** ~~No `.github/workflows`.~~ **Partially addressed:** `.github/workflows/e2e.yml` now exists (Top-20 #7, see status note above) — one E2E gate, not full unit coverage. Only 4 Go `_test.go` files for ~10.8k LOC of engine (now 6, with `mutation_engine_test.go`/`worker_error_mining_test.go` added alongside #14/#11); the Python (2.5k LOC of instrumentation/grammar, the most fragile part) still has *no* unit tests (the E2E script exercises it, but doesn't unit-test `grammarc/` in isolation). For a security tool, untested instrumentation is untrustworthy.
- **[HIGH] Repo hygiene.** The tree carries multiple full target checkouts and generated outputs (`bitwarden_prep*`, `btcpayserver*`, `simplcommerce*`, `esh*`, `restler_output`, `crashes/`, `void/crashes`, `__pycache__`). This bloats clones, confuses the architecture, and risks committing target/customer code. These must be `.gitignore`d and removed from history.
- **[MED] Three-language pipeline with implicit file contracts.** Python (prep+grammar) + Bash (compile) + Go (engine) + C# (instrumentor) with no schema-validated interfaces. Onboarding and debugging require understanding all four. RESTler adds a fifth moving part.
- **[MED] 90+ CLI flags.** `main.go` exposes an enormous surface. Profiles (`fast`/`deep`/`security`) mitigate this well, but the raw surface is a maintenance and docs burden.
- **[MED] Documentation-vs-implementation drift.** "Roslyn analyzer" (doesn't exist), "zero HTTP overhead" (double full-scan per request), "% coverage" (guessed denominator). Every such claim erodes researcher trust when they read the code.
- **[LOW] No versioned releases / packaging.** No `dotnet tool`, no container on a registry, no `brew`/binary release. Adoption requires cloning and reading long runbooks.

### Recommended redesign
- **A single CLI orchestrator** (`upsidefuzz run --target ...`) that drives prep→grammar→fuzz as one command with sane defaults, hiding the multi-language pipeline. One tool, three subcommands, not four scripts + Docker incantations.
- **E2E CI on a tiny planted-bug sample app**: instrument, assert per-assembly coverage health, assert the fuzzer finds the planted BOLA + 500 + SQLi within N seconds. This is the single most trust-building thing you can add.
- **Purge target checkouts from the repo**; ship them as `git submodule` or download scripts under `targets/`.
- **Publish releases**: prebuilt engine binaries + a container image + a `dotnet tool` for the instrumentor/analyzer.

**Complexity:** Medium. **Benefit:** High for adoption and trust. **Priority: P1 (CI/hygiene), P2 (packaging).**

---

# Security-Researcher Adoption Review

*Reviewed as a working offensive-security engineer deciding whether to run this on a client engagement.*

**Would I trust it?** More than at first review. The honest triage taxonomy and FP-engineering in `oracle.go` earn credibility fast, and the trust gaps I flagged are now largely closed: there **is** CI (`e2e.yml` on a planted-bug fixture), instrumentation is **self-verifying and fail-closed** (`checkCoverageHealth`, `/shm/health`), coverage is bucketed + honestly sized, and runs are now seedable (`-seed`, #25 partial) instead of silently unrepeatable. Remaining trust gap: seeding isn't bit-for-bit under concurrency and there's still no request-journal replay tool, so a specific finding is reproducible-in-spirit (same seed, same target, similar outcome) but not guaranteed byte-identical on replay. I would still not read a clean run as "this API is safe" (no OAST → blind vulns), but I'd trust the coverage numbers.

**What would frustrate me?**
- Getting it running: Docker-only grey-box, regex Dockerfile adaptation that may misdetect my build, pasting JWTs that expire mid-run, RESTler in the loop.
- No OAST — so my blind SSRF/RCE/XXE findings depend on luck.
- Silent degradation: if instrumentation half-fails, I get a green run with no coverage and no error.
- Multi-target repo clutter and 4-script pipeline; long runbooks per target.

**What features would I immediately miss?**
Out-of-band interaction server; ownership-matrix BOLA; auto-login/OAuth2; persistent corpus; SARIF/HTML report; a no-Docker mode; hit-count coverage I can graph against a real denominator; a resumable run.

**What vulnerabilities is it unlikely to find today?**
Blind injection (SSRF/XXE/RCE/blind-SQLi) without OAST; multi-step business-logic bugs needing state modeling; true cross-tenant BOLA where bodies differ; race conditions beyond simple bursts; auth bugs needing verb/path/parser confusion differentials; anything in AOT/trimmed targets; anything gated behind loop-depth the binary-coverage signal can't see.

**What would make me switch *to* it?** The oracle suite + coverage feedback on .NET is unique. If instrumentation were one command and self-verifying, OAST existed, and there were a resumable corpus + SARIF output, this becomes my default .NET API fuzzer over Schemathesis/RESTler.

---

# Comparison Table (subsystem maturity)

| Subsystem | Maturity | Gating weakness |
|---|---|---|
| IL rewriting / SharpFuzz | Good | ✅ zero-edit hook + load-time linking (lazy assemblies) + fail-closed health done; still Docker-only, no AOT |
| Coverage signal | Good (was Weak) | ✅ AFL hit-count buckets + single-scan first-observer-wins attribution done; ✅ CMPLOG-via-IL (#21) done; per-*input* path novelty still open |
| Grammar generation | Good (was Medium) | ✅ RESTler retired (`grammarc/`), ✅ real Roslyn SSE (`analyzer/`, syntax-tree scope); no typed body model / structural mutation still open |
| Scheduling / MOpt / corpus | **Strong** | ✅ CMPLOG-lite (#11) + field-aware boundary mutation (#14, partial) landed; no persistence still open |
| Sequences / state | Medium | Flat key-value, not state-graph reward |
| Oracles | **Strong (differentiator)** | No OAST; body-heuristic BOLA; no differentials |
| Triage / cluster / report | Strong | Prod-mode under-clustering; no SARIF |
| Auth / identity | Medium | Manual token file; no auto-login/OIDC |
| DX / CI / reliability | Improving (was **Weak**) | ✅ first E2E CI gate (#7); still thin unit coverage beyond it, repo clutter, 4-language pipeline |

---

# Top 20 Highest-ROI Improvements (ranked)

Ordering rationale: coverage resolution and instrumentation universality gate *everything downstream*, so they come first even though the oracle work is more "exciting." OAST is elevated because it's the cheapest large jump in the headline value proposition.

| # | Improvement | Priority | Difficulty | Effort | Δ Coverage | Δ Bugs | Δ Universality | Why before others |
|---|---|---|---|---|---|---|---|---|
| 1 | ✅ **DONE — AFL hit-count buckets + bucketed virgin map** (`coverage.go::countClass`/`GetEdges`, `CoverageExtensions.cs::CountClass`/`MergeAndCountNovel`) | P0 | Med | 1–2 wk | **High** | High | — | Every scheduler/MOpt/energy decision learns from this; cheapest depth unlock |
| 2 | ✅ **DONE (pragmatic) — single-scan, first-observer-wins per-request attribution** (kill smearing double-count; remove double full-scan). Full per-thread trace-buffer isolation still needs SharpFuzz probe changes | P0 | Med–High | 2–3 wk | High | High | — | Fixes attribution the whole engine depends on; also a perf win |
| 3 | ✅ **DONE — `DOTNET_STARTUP_HOOKS` zero-edit instrumentation + load-time linking** (default `--inject-mode hook`; `generate_startup_hook_assembly`; `AssemblyLoad` handler fixes lazy assemblies; `/shm/health`). Legacy `--inject-mode source` retained | P0 | High | 3–4 wk | Med | Med | **High** | Turns "4 curated targets" into "arbitrary .NET"; fixes silent link loss |
| 4 | ✅ **DONE — Self-verifying, fail-closed instrumentation** (`/shm/health` facts + `void/go/coverage.go::checkCoverageHealth` warm-up probe; engine refuses degraded runs by default, `-allow-degraded-coverage` to override) | P0 | Low–Med | 1 wk | Med | Med | High | Removes silent-no-coverage false negatives; trust |
| 5 | **Built-in OAST server** for blind SSRF/XXE/RCE/log4shell/blind-SQLi | P0 | Med | 2–3 wk | — | **High** | — | Biggest jump in "deep/realistic" bugs; headline researcher feature |
| 6 | **Non-Docker host mode** (named cross-platform SHM) | P1 | Med | 2 wk | — | — | High | Unblocks local/Windows/non-container targets |
| 7 | ✅ **DONE — E2E CI on planted-bug sample app** (`fixtures/planted-bug-api/`, `scripts/e2e-test.sh`, `.github/workflows/e2e.yml`) — instrument→coverage→grammar→fuzz→detect | P1 | Low–Med | 1 wk | — | — | Med | Trust + regression safety for all future work |
| 8 | **Ownership-matrix BOLA** (cross-replay known-owned IDs across identities) | P1 | Med | 1–2 wk | — | High | — | Catches the real cross-tenant BOLA the body-heuristic misses |
| 9 | ✅ **DONE — first-party OpenAPI→typed-grammar compiler (`grammarc/`); RESTler retired** | P1 | High | 4–6 wk | Med | Med | High | Removes biggest external dep; enables structural mutation |
| 10 | ✅ **DONE — Roslyn syntax-tree analyzer (`analyzer/`)**: type/property-scoped constraints, `[Authorize]`/route metadata, FluentValidation chain walking. Semantic model (`MSBuildWorkspace`) intentionally out of scope | P1 | High | 3–4 wk | Med | Med | Med | Makes "SSE" real; precise valid-value generation past 400-walls |
| 11 | ✅ **DONE — Comparison/400-body mining (CMPLOG-lite)** (`worker.go::mineClientErrorFields`) — extracts required fields/enums from ASP.NET ValidationProblemDetails/ModelState error bodies into `RuntimeStore` | P1 | Low–Med | 1 wk | High | Med | — | Cheap; smashes validation walls on real APIs |
| 12 | ✅ **DONE (partial) — State-reward sequence search** (`sequence.go::sequenceStateSignature`/`statusClass` — ordered method+normpath+status-class workflow-shape signature; `enqueueSequenceFollowups` awards a state-novelty energy bonus + one extra fanout branch on a never-seen shape, `maybePersistSequence` dedups persisted workflows by final shape) — coarse (no resource-lifecycle/typed state graph); full state-graph search still open | P1 | Med–High | 3 wk | Med | High | — | The DeepREST/EvoMaster gap for logic bugs |
| 13 | **Credential auto-login + OAuth2/OIDC per identity** | P1 | Med | 2 wk | — | Med | High | Removes token-file friction; enables long unattended runs |
| 14 | ✅ **DONE (partial) — Structure-aware mutation over typed model** (`Segment.MinLength/MaxLength/Minimum/Maximum/Pattern/EnumValues`, blended additively into `mutateInt`/`mutateNumber`/`mutateStringCategorized`) — per-field boundaries from constraints now reach mutation; full typed-model structural mutation (deserialization/polymorphism) still open | P1 | Med | 2–3 wk | Med | Med | — | Depends on #9/#10; unlocks deserialization/polymorphism bugs |
| 15 | **Persistent, resumable corpus + coverage frontier** (`corpus/` dir) | P2 | Low–Med | 1 wk | Med | — | — | Warm restarts; reproducibility; researcher productivity |
| 16 | **SARIF + HTML findings export** | P2 | Low | 3–5 d | — | — | Med | Drops into CI / DefectDojo / GitHub scanning |
| 17 | ✅ **DONE (partial) — Bitmap sizing from real instrumented-type count; smarter reset; honest capacity** (`instrumentor/Program.cs` writes `.upsidefuzz_instrumented.jsonl`; `fuzz-prep-multi.py::ResolveShmSize` auto-sizes SHM_SIZE from it when unset; `void/go/coverage.go::SHMCoverageReader.Init` trusts the real on-disk file size instead of truncating to a stale flag; `worker.go::shouldResetCoverageBitmap` now requires saturation AND stagnation, not saturation alone) — sizes from instrumented TYPE count (a proxy; SharpFuzz exposes no public branch/edge count), not a literal edge count | P2 | Low | 3–5 d | Med | — | — | Honest metrics; fewer collisions on big apps |
| 18 | ✅ **DONE (partial) — Differential oracles** (`oracle.go::maybeEnqueueDifferentialProbes` — verb (GET→HEAD), content-type (JSON→text/plain, same bytes), route-case, param-location confusion; gated on `authRequiredEndpoints` strength 2 so a hit means the confusion itself bypassed a real check) — param-location technique duplicates the same id as a query param rather than a differently-owned id (no ownership-matrix infra yet — see #8) | P2 | Med | 2 wk | — | Med | — | New auth-bypass & parser-confusion bug class |
| 19 | ✅ **DONE (partial) — Single `upsidefuzz` CLI orchestrator** (`upsidefuzz.py`, subcommands `instrument`/`build`/`up`/`down`/`verify`/`grammar`/`fuzz`/`run`/`doctor`; zero-install Docker mode via `./upsidefuzz` + `Dockerfile.cli`, bundling Python/.NET SDK/void so only Docker is required locally). Repo hygiene (purging target checkouts from history) still open | P2 | Med | 2 wk | — | — | High | Adoption; hides 4-language pipeline |
| 20 | **Value-level minimization + behavioral mass-assign confirmation** | P2 | Low–Med | 1 wk | — | Med | — | Better PoCs; catches silent privilege writes |

**Status roll-up (verified against the tree):** DONE — #1, #2, #3, #4, #7, #9, #10, #11, #12, #14, #17, #18, #19 (several "partial", see per-row notes). OPEN — #5 (OAST), #6 (non-Docker host mode), #8 (ownership-matrix BOLA), #13 (auth/OIDC), #15 (persistent corpus), #16 (SARIF/HTML — no first-party exporter found), #20 (value-min + behavioral mass-assign).

---

# Additional High-ROI Improvements (21–32)

Because most of the original twenty are now landed, this is the next tranche. Same columns. Ordering favors (a) trust/reproducibility and (b) depth unlocks that build on machinery the project already owns (Cecil IL rewriting, the `analyzer/` Roslyn pass, `grammarc/`, the oracle layer).

| # | Improvement | Priority | Difficulty | Effort | Δ Coverage | Δ Bugs | Δ Universality | Why it ranks here / files |
|---|---|---|---|---|---|---|---|---|
| 21 | ✅ **DONE — CmpLog/RedQueen via IL comparison instrumentation** (`instrumentor/Program.cs::CmpLogInstrumentor` — independent Cecil pass, `--cmplog`, hook mode only; `CmpLogProbe` in the coverage hook runtime + `GET /shm/cmplog`; `void/go/cmplog.go` polls into `mutateStringCategorized`/`mutateInt`) — captures operands of `String.Equals`/`op_Equality`/`StartsWith`/`EndsWith`/`Contains` calls and integer-literal-vs-`ceq`/`beq`/`bne.un` sites at rewrite time and feeds them back as live mutation candidates | P0 | High | 3–4 wk | **High** | High | — | Owns the Cecil pipeline (`instrumentor/Program.cs`); the .NET analog of AFL++'s biggest depth feature. Beats magic-value checks that buckets+mutation can't guess. Distinct from #11 (that mines 400 bodies). **Scope limits**: only the constant-immediately-before-the-compare shape is captured (`x == CONST` yes, `CONST == x` no, unless the compiler happens to reorder); general relational compares (`clt`/`cgt`/`ble`/`bge`) and switch-statement case values (both the sequential-`Equals` and hash-jump-table forms) are not covered — would need real stack-depth data-flow analysis this pass deliberately doesn't attempt |
| 22 | **Binary constant/string extraction at instrument time** — Cecil harvests string/numeric literals from IL into `dict.json` | P1 | Low | 3–5 d | High | Med | — | Cheap (one existing Cecil pass); free domain dictionary, like `afl -x` |
| 23 | **Response-schema conformance oracle** — validate response bodies against the OpenAPI schema; mismatch = bug | P1 | Low | 3–5 d | — | Med | — | `grammarc/` already parses the spec; a whole free bug class (leaked fields, type drift) currently ignored |
| 24 | **JWT / session-lifecycle oracle** — `alg=none`, `kid` injection, tampered/expired token, replay after logout, mid-session privilege change | P1 | Med | 2 wk | — | High | — | High-value, very .NET; reuses `identity.go`/`auth.go`; natural extension of the oracle lead |
| 25 | ◑ **DONE (partial) — global seed** (`main.go` `-seed`, `types.go::Config.Seed` → `rand.Seed(cfg.Seed)` before `NewFuzzer`; explicit "unseeded (default: random)" vs. "seeded" startup line either way) — removes the dominant source of run-to-run variance in mutation/scheduling draws; **not** bit-for-bit under concurrency (goroutine scheduling order still varies), and no request-journal replay tool exists yet (a specific finding can't be mechanically replayed from a log, only re-approximated by re-running with the same seed) | P0 | Med | 2 wk | — | — (trust) | — | The direct 6→8 mover. `math/rand` was previously unseeded → runs were unrepeatable even approximately |
| 26 | **Sensitive-data / PII exposure oracle** — detect emails/tokens/PAN/connection-strings/stack traces in 2xx bodies | P1 | Low | 1 wk | — | High | — | Real finding class independent of 500s; regex over bodies already collected (`learnFromResponse`) |
| 27 | **Taint-marking of injected values** — tag fuzzer payloads, detect where they resurface (response, SQL error, file path) | P1 | Med | 1–2 wk | — | High | — | Sharpens injection precision in `oracle.go`, finds reflected sinks, cuts false positives |
| 28 | **Regression / diff-guided fuzzing** — fuzz only code changed between two commits (Cecil knows the methods; prioritize their endpoints) | P1 | Med | 2 wk | — | Med | — | Adoption killer-feature for CI ("fuzz just this PR in 5 min"); nothing in .NET does it out of the box |
| 29 | **Non-REST surfaces: gRPC, GraphQL (HotChocolate), SignalR/WebSocket** | P2 | High | 4–6 wk | Med | High | High | Large real .NET surface currently outside `template.go`; GraphQL brings its own oracle class (introspection, alias/depth DoS, batching) |
| 30 | **Algorithmic-complexity / ReDoS / resource-exhaustion oracle** — flag response-time/memory blow-up on crafted inputs | P2 | Med | 2 wk | — | Med | — | DoS class atop existing latency baseline (`baselineLatMS`) + `/shm` (add GC/mem) |
| 31 | **Readiness-gated startup + DB-seeding harness** — poll readiness instead of `sleep 45`; seed known per-identity objects | P1 | Low | 1 wk | — | — (reliability) | — | Removes the startup flap (bit us in `verify-hook.sh`) AND provides ground truth for ownership-matrix BOLA (#8) |
| 32 | **Distributed parallel fuzzing + corpus sync** (AFL `-M/-S` across N target replicas) | P2 | High | 3 wk | — | Med (throughput) | — | Scale on large apps; synergizes with persistent corpus (#15) |

**Suggested near-term order (mixing old + new):** trust first — #7 (done) → #25 global seed (done, partial — request-journal replay still open) → **#31 readiness/seeding** → finish #4; then depth — #21 CmpLog (done) → **#22 constants** → **#5 OAST** ; then new finding classes — **#23 schema-conformance** → **#26 PII** → **#24 JWT** → **#27 taint**. The cheapest single credibility win remaining is finishing **#25** (a real replay tool, not just a seed).

**Status roll-up for this tranche:** DONE — #21 (CmpLog), #25 (partial — global seed only). OPEN — #22, #23, #24, #26, #27, #28, #29, #30, #31, #32.

---

# Missing Features Compared to Existing Fuzzers

### vs. RESTler
- RESTler has mature, battle-tested OpenAPI→grammar compilation and producer-consumer inference (which UpsideFuzz currently *depends on* rather than surpasses) and a large stateful test-generation corpus. UpsideFuzz should internalize and then exceed this, not import it.
- RESTler has extensive checkers (use-after-free of resources, resource-leak, payload-body checkers). UpsideFuzz's oracle set is different (and better on access-control) but lacks RESTler's resource-lifecycle checkers.

### vs. EvoMaster
- **White-box, SBST search with a typed test genome** and fitness driven by branch distance (not just edge presence) — EvoMaster gets *closer to flipping a specific branch* using the numeric distance to the condition. UpsideFuzz has no branch-distance/gradient signal.
- **Full test-case minimization + JUnit/JS test export.** UpsideFuzz exports curl PoCs, not runnable regression tests.
- **SQL database heuristics** (detects and mutates DB state). UpsideFuzz has no DB awareness.
- **Structure-aware genome mutation** respecting the full schema. UpsideFuzz mutates flattened strings/JSON.

### vs. Schemathesis
- **Property-based generation from JSON Schema (Hypothesis strategies)** with shrinking, stateful links (OpenAPI `links`), and rich schema conformance checks (response-schema validation as an oracle). UpsideFuzz doesn't validate responses against the schema at all — a whole free oracle class (spec-violation bugs) is unused.
- **`--checks` for spec conformance, status-code conformance, content-type conformance.** UpsideFuzz has none of these low-cost oracles.
- Mature CLI/pytest integration and reporting.

### vs. DeepREST
- **Learned, state-aware exploration** that uses reinforcement to discover operation orderings and parameter values that reach deep states. UpsideFuzz's sequence engine is heuristic-priority, not learned, and rewards edges not states.

### vs. libFuzzer
- **In-process, per-input coverage with `-fork`, value-profile (`-use_value_profile`) and full comparison instrumentation.** UpsideFuzz's out-of-process HTTP model can't match per-input speed and has no value-profile/CMPLOG.
- **Deterministic corpus persistence and merge.** Missing.

### vs. AFL++
- **Hit-count buckets, CMPLOG/RedQueen input-to-state, MOpt (real), collision-aware map sizing, deterministic + havoc + splice stages, persistent queue, cmplog/coverage-guided dictionary.** UpsideFuzz has MOpt-style weighting and havoc/splice *names* but lacks buckets, CMPLOG, and persistence — the three features that most drive AFL++'s depth.

**Net:** UpsideFuzz already *beats* all of these on **access-control/mass-assignment oracles wired to .NET grey-box coverage**. It *trails* on: coverage resolution (buckets/branch-distance/CMPLOG — AFL++, libFuzzer, EvoMaster), typed schema-aware generation (EvoMaster, Schemathesis), learned state exploration (DeepREST), response/spec-conformance oracles (Schemathesis), and runnable-test export + reproducibility (EvoMaster).

---

# Recorded Documentation ↔ Implementation Inconsistencies

1. ~~**"Roslyn analyzer" / "Semantic Source Extraction"** (README, `AI_CONTEXT.md`, `arxiv_paper/`) — **not implemented.** `enhance-grammar.py::SourceExtractor` is line-regex; no `Microsoft.CodeAnalysis` in first-party code. *Trust the implementation: it is regex.*~~ **✅ FIXED:** `analyzer/` is a real `Microsoft.CodeAnalysis.CSharp` syntax-tree analyzer (Top-20 #10). Precisely scoped, not overclaimed: it parses syntax trees directly (attribute arguments, lambda chains, base-list inheritance within the source tree) but does **not** build a full semantic model via `MSBuildWorkspace`/NuGet restore — cross-assembly base types are left unresolved rather than guessed. `enhance-grammar.py` and its regex `SourceExtractor` are retained only as the legacy fallback path (see `void/export-templates.py`'s deprecation note), no longer the primary path.
2. ~~**"Zero HTTP overhead" / "zero-overhead per batch"** — the middleware calls `GetCurrentEdgeCount()` (full 262,144-byte scan) twice per request.~~ **✅ FIXED:** `GetCurrentEdgeCount` removed; the middleware now does a single bucketed merge pass per request (`MergeAndCountNovel`, with an all-zero-word fast path). ARCHITECTURE.md §5 updated to describe "one bitmap pass per request" rather than "zero overhead."
3. **"% coverage / near saturation"** — computed against a *guessed* `baselineEdgesCeiling` (`worker.go::coverageSaturationPct`), not the true instrumented-edge count. Misleading metric.
4. ~~**"Coverage smearing … gracefully filtered out"** — under-states a real correctness problem: energy/MOpt/rebalancing all learn from smeared, globally-monotonic, binary deltas.~~ **✅ MOSTLY FIXED:** deltas are now bucketed (not binary) and attributed first-observer-wins (no double-count across concurrent requests). ARCHITECTURE.md §5 rewritten accordingly. Residual: novelty is still measured against a *shared* virgin map rather than true per-thread trace buffers, so ordering (which concurrent request reaches the merge first) still influences which seed gets credit — a far smaller effect than the old double-counting.
5. **README "instruments arbitrary .NET APIs … almost zero configuration"** vs. reality: Docker required, regex build detection, per-target quickstart runbooks, manual auth token files, RESTler in the loop. Aspirational, not current.
6. **Namespace allowlist substring match** (`fullName.Contains(ns)` in `instrumentor/Program.cs`) — documented Bitwarden footgun; the default is now `--instrument-all-user-code`, so the allowlist path is legacy risk that should be removed or fixed to prefix/exact matching.
7. ~~**`custom_payload` segment values were never substituted at render time.**~~ **✅ FOUND AND FIXED** during the #9/#10 migration (2026-07-23): `void/export-templates.py::seg_payload()` emitted JSON key `"name"` for every `custom_payload` segment; `void/go/types.go`'s `Segment` struct has *separate* `Name` (`json:"name"`) and `PayloadKey` (`json:"payload_key"`) fields with different JSON tags. `void/go/template.go`'s actual rendering switch (`case "custom_payload"`, and `fuzzer.go`'s `isIDLikeKey` ID-harvesting registration) read **only** `s.PayloadKey` — which was therefore always `""` for every `custom_payload` segment the pipeline ever produced, including RESTler's own dependency `.reader()`/`.writer()` chaining (not just static dictionary lookups). Concretely: sequence-harvested IDs, correlated values, and dictionary lookups keyed by field name silently never reached these segments; they fell back to a generic default every time. This directly undermined producer→consumer chaining — the project's most-touted feature — for the entire lifetime of the RESTler-based pipeline. **Fixed by construction** in `grammarc/emit_templates.py`/`body_serializer.py`, which emit `"payload_key"` directly (Go required zero changes — it was always reading the right field, just never receiving it). Verified via direct segment inspection on eShopOnWeb: `PUT /api/catalog-items`'s body `"id"` field and `GET`/`DELETE /api/catalog-items/{catalogItemId}`'s path parameter now both resolve to the identical `payload_key: "catalogitemid"`, and a live fuzz run showed the sequence engine's dependency graph populated (`producers=2 consumers=3`) where it would previously have been structurally inert for this segment kind.
8. **`analyzer/RoslynUtil.IsTestPath` excluded any directory merely *starting with* "test".** Found and fixed 2026-07-23 while building the Top-20 #7 E2E fixture: the check was `lower.Contains("/test")` (missing the trailing `/`), so a legitimate directory like `fixtures/planted-bug-api`'s original name `testdata/planted-bug-api` matched and the analyzer silently parsed 0 files from it. Fixed to match whole path *segments* (`test`, `tests`, `*.Tests`) instead of a bare substring — verified the fix doesn't regress eShopOnWeb (same 209 files / 33 endpoints before and after).
9. **`analyzer/RouteAuthWalker` never scanned top-level-statement `Program.cs` files for minimal-API routes — only class bodies.** Found and fixed 2026-07-23: `BuildMinimalApiEndpoints` iterated `idx.AllClasses`, but C# 9+ top-level statements (the modern ASP.NET default template style: `var app = ...; app.MapGet(...);` directly in `Program.cs`, no enclosing class) have no `ClassDeclarationSyntax` in the parsed syntax tree at all — the "Program" class wrapper is a compile-time/semantic construct, not a syntactic one. `SourceIndex` now also retains each file's `CompilationUnitSyntax` root (`FileRoots`), and `RouteAuthWalker` additionally scans each file's top-level `GlobalStatementSyntax` nodes. Verified against `fixtures/planted-bug-api` (0 → 4 endpoints detected) with no regression on eShopOnWeb (still 33, all class-based there).
10. **`compile-grammar.sh` crashed with `ROSLYN_ARGS[@]: unbound variable` whenever `--src` was omitted, on macOS specifically.** Found and fixed 2026-07-23 while writing `scripts/e2e-test.sh` (the first automated, non-interactive exercise of the `--src`-less code path). Root cause: macOS's system `/bin/bash` is 3.2 (GPLv3 avoidance) — a version with a known bug where `"${empty_array[@]}"` under `set -u` throws "unbound variable" even for a *declared-but-empty* array, unlike bash ≥ 4.4. Fixed with an explicit `${#ROSLYN_ARGS[@]} -gt 0` length guard before expansion. Would not have reproduced on a GitHub Actions `ubuntu-latest` runner (modern bash), which is exactly why the interactive, manually-driven verification earlier in this session never caught it — the E2E script's value as a regression gate is already paying for itself.

---

# Vision

## What UpsideFuzz should become

**The default coverage-guided security fuzzer for .NET APIs — one command, no code changes, self-verifying instrumentation, deep access-control and injection oracles, and coverage resolution on par with AFL++.** The thing that makes it unique is already here (grey-box .NET + positive vuln oracles + multi-identity). The vision is to remove every reason a researcher *wouldn't* reach for it.

## Ideal target architecture (v-next)

```
                         ┌────────────────────────────────────────────┐
                         │  upsidefuzz  (single Go CLI orchestrator)    │
                         │  run | analyze | instrument | report        │
                         └───────────────┬────────────────────────────┘
        ┌────────────────────────────────┼──────────────────────────────────┐
        ▼                                 ▼                                   ▼
 UpsideFuzz.Analyzer (Roslyn)     UpsideFuzz.Coverage (NuGet /        Void Engine (Go)
  - typed per-property             DOTNET_STARTUP_HOOKS)               - typed grammar model
    constraints, [Authorize],      - load-time IL rewrite / link       - hit-count-bucket coverage
    custom validators              - per-request thread-local edges     - CMPLOG / 400-body mining
  - route + auth metadata          - cross-platform named SHM           - state-reward sequences
        │                          - /shm/health self-verify            - oracles + OAST server
        └──────────────┐                    │                           - persistent corpus
                        ▼                    ▼                                   │
                First-party OpenAPI + Analyzer → typed request grammar ─────────┘
                                                                        SARIF / HTML / JUnit-style repro
```

Key properties:
- **No RESTler, no Bash glue, no source edits.** One Go CLI + two `dotnet` components (analyzer, coverage hook) + the engine.
- **Coverage feedback at AFL++ resolution** (buckets + per-input + CMPLOG), so the excellent existing scheduler finally runs on a real signal.
- **Instrumentation that either works and proves it, or refuses to run** — never a silent no-coverage green run.
- **Oracles confirmed out-of-band** (OAST) and via ownership matrices, not just body heuristics.
- **State-space exploration** rewarded, closing the logic-bug gap with DeepREST/EvoMaster.
- **Reproducible**: persistent corpus, resumable runs, SARIF + runnable repro export.

## Long-term roadmap

**Phase 0 — Trust the signal (P0):** ✅ hit-count buckets (#1), ✅ per-request edge sets (#2), ✅ self-verifying/fail-closed instrumentation (#4), ✅ E2E CI (#7); repo hygiene still open. *Outcome: the numbers mean something and the tool can't silently no-op — Phase 0 is now done except repo hygiene.*

**Phase 1 — Universality (P0/P1):** startup-hook + load-time instrumentation (#3), non-Docker host mode (#6), credential auto-login/OIDC (#13). *Outcome: runs on arbitrary .NET APIs with one command.*

**Phase 2 — Depth (P0/P1):** OAST server (#5), ownership-matrix BOLA (#8), ✅ 400-body/CMPLOG mining (#11, done — `worker.go::mineClientErrorFields`), state-reward sequences (#12), differential oracles (#18). *Outcome: finds deep, realistic, blind vulns the current build can't.*

**Phase 3 — Grammar independence (P1):** ✅ first-party OpenAPI typed grammar + retire RESTler (#9), ✅ real Roslyn analyzer (#10), ✅ structure-aware mutation (#14, partial) — all done (`grammarc/`, `analyzer/`, `Segment` constraint fields). *Outcome so far: grammar quality no longer target-sensitive to RESTler's coverage/bugs/maintenance cadence, and per-field boundaries now reach mutation; still open: full typed-model structural mutation (deserialization/polymorphism).*

**Phase 4 — Product polish (P2):** persistent/resumable corpus (#15), SARIF/HTML (#16), honest coverage metrics (#17), ✅ single CLI orchestrator (#19, partial — `upsidefuzz.py` + `./upsidefuzz` Docker launcher done; repo hygiene and versioned releases/packaging still open), value-level minimization (#20). *Outcome: an adoptable, reproducible, releasable product.*

## What would make it the best open-source feedback-guided REST API fuzzer for .NET
1. **Coverage you can trust** — bucketed, per-request, honestly measured.
2. **Instrumentation you can't misconfigure** — zero-edit, self-verifying, works everywhere .NET runs.
3. **Oracles that find real, deep, blind vulnerabilities** — OAST + ownership matrices + differentials on top of the already-strong access-control suite.
4. **State-aware exploration** for business-logic bugs.
5. **Reproducibility and integration** — persistent corpus, SARIF, CI, one-command runs, real releases.

The engine is already good. The differentiator (oracles) is already unique. The two things standing between this project and "best-in-class" are **a real coverage signal** and **instrumentation that works on anything without babysitting** — fix those two, keep the oracle lead, and nothing else in the open-source .NET space compares.
