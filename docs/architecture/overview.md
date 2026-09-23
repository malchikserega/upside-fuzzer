# UpsideFuzz Platform Architecture

This document describes the internal design, components, and data flows of the **UpsideFuzz** platform — from source analysis through instrumentation, runtime synchronization, coverage feedback, and coverage-guided fuzzing.

**→ [Back to README](../../README.md) · [Full Runbook](../getting-started/quickstart.md) · [Docs Index](../index.md)**

---

## High-Level Overview

The platform automates transforming a standard .NET solution into a feedback-driven fuzzing target in six stages:

1. **Analysis** — Discovering business logic across all projects in a solution
2. **Preparation** — Adapting Docker configs, injecting coverage infrastructure
3. **Instrumentation** — Injecting SharpFuzz coverage probes into target DLLs during Docker build
4. **Synchronization** — Linking all instrumented DLLs to a single shared memory bitmap at runtime
5. **Grammar Generation** — Compiling an OpenAPI spec directly into typed request templates (`tools/grammar/grammarc/`, first-party, no RESTler), optionally enriched with real Roslyn syntax-tree analysis of the C# source (`tools/dotnet/analyzer/`)
6. **Fuzzing** — Sending mutated inputs with epoch-based scheduling, adaptive concurrency, and crash triage

---

## End-to-End Flow Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                        .NET Solution Source                        │
│              (*.sln / *.csproj / Dockerfile / compose)             │
└──────────────────────────────┬─────────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  bin/fuzz-prep-multi.py  │
                    │                      │
                    │  • Scan *.csproj     │
                    │  • Skip test projects│
                    │  • Detect biz logic  │
                    │  • Collect namespaces│
                    └──────────┬──────────┘
                               │  Writes to OUTPUT_DIR (copy of src)
         ┌─────────────────────┼──────────────────────────┐
         │                     │                          │
         ▼                     ▼                          ▼
  Dockerfile            compose.yaml           New/Modified Files
  (4 stages)           (+SHM volumes)         instrumentor_src/
  injected             +Development env       Helpers/CoverageExtensions.cs
                       +sidecar template      Program.cs (patched)
                                              *.csproj (patched)
                               │
                    ┌──────────▼──────────┐
                    │  docker compose      │
                    │       build          │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     Stage 1: builder   Stage 2+3: instrument  Stage 4: runtime
     dotnet publish     SharpFuzz IL rewriting  minimal aspnet image
                        (namespace-filtered)    COPY from instrumentation
              │                │                │
              └────────────────┴────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  docker compose up   │
                    │                      │
                    │  [App Container]     │
                    │  ┌─────────────────┐ │
                    │  │  Web API Process │ │
                    │  │  DLL-A.dll ──┐  │ │
                    │  │  DLL-B.dll ──┼─►│ │  SHM bitmap (256KB default)
                    │  │  DLL-C.dll ──┘  │ │  /coverage_shm/bitmap
                    │  │  [SyncSharpFuzz]─┼─┼─► (tmpfs mmap)
                    │  │  /shm/create    │ │
                    │  │  /shm/coverage  │ │
                    │  │  /shm/reset     │ │
                    │  └─────────────────┘ │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                                 │
              ▼                                 ▼
   bin/compile-grammar.sh                  GET /swagger/v1/swagger.json
   (tools/grammar/grammarc/ + optional tools/dotnet/analyzer/)
              │
     ┌────────┴────────┐
     │                 │
     ▼                 ▼
templates.export.json  dict.json
 (templates)        (tokens)
     │
     └──────────────────────────────────────────┐
                                                │
                    ┌───────────────────────────▼──────────────────────┐
                    │            Void                         │
                    │                                                   │
                    │  ┌─ Epoch scheduler ─────────────────────────┐   │
                    │  │  Baseline → Deterministic → Havoc →        │   │
                    │  │  Splicing                                  │   │
                    │  └───────────────────────────────────────────┘   │
                    │                                                   │
                    │  ┌─ Worker pool (adaptive concurrency) ───────┐  │
                    │  │  goroutines → HTTP requests → responses    │  │
                    │  │  cookie jar, auth header, anti-forgery     │  │
                    │  └───────────────────────────────────────────┘   │
                    │                                                   │
                    │  ┌─ Coverage reader ──────────────────────────┐  │
                    │  │  Mode A: mmap /coverage_shm/bitmap         │  │
                    │  │  Mode B: GET /shm/coverage (HTTP)          │  │
                    │  └───────────────────────────────────────────┘   │
                    │                                                   │
                    │  ┌─ Mutation engine ──────────────────────────┐  │
                    │  │  MOpt-style weighted categories             │  │
                    │  │  sqli / xss / cmdi / ssti / ssrf /...      │  │
                    │  └───────────────────────────────────────────┘   │
                    │                                                   │
                    │  ┌─ Crash triage ─────────────────────────────┐  │
                    │  │  Repro → Minimize → JSONL → PoC file       │  │
                    │  └───────────────────────────────────────────┘   │
                    └───────────────────────────────────────────────────┘
```

---

## 1. Discovery & Analysis (`bin/fuzz-prep-multi.py`)

### Project Enumeration
- Scans the source directory for all `.csproj` files
- Identifies the **main project** (web SDK or `--main` flag)
- **Skips test projects** by name/path pattern (`*.Tests.csproj`, `/test/`, `/tests/`)

### Business Logic Detection
Uses file-name and directory heuristics to identify code worth fuzzing:

| Pattern | Category |
|---------|----------|
| `*Controller.cs` | API endpoint handlers |
| `*Service.cs` | Business logic services |
| `*Repository.cs` | Data access layer |
| `*Validator.cs` | Input validation rules |
| `*Handler.cs` | CQRS/MediatR handlers |
| `*Command.cs`, `*Query.cs` | CQRS command/query objects |
| `*Aggregate.cs`, `*Specification.cs` | DDD patterns |
| `*Endpoint.cs` | Minimal API / FastEndpoints |
| `*Logic.cs`, `*Manager.cs` | Domain logic |
| Directories: `Controllers/`, `Features/`, `Handlers/` | Structural detection |

### Dynamic Configuration Detection

| Detection | Method | Fallback |
|-----------|--------|----------|
| Builder variable name | Regex on `WebApplication.CreateBuilder(...)` | `builder` |
| App variable name | Regex on `<builder>.Build()` | `app` |
| Dockerfile runtime stage | Last `FROM ... AS <name>` stage | `runtime` |
| Dockerfile publish directory | `--output` / `-o` in `dotnet publish` | `/app/publish` |
| Dockerfile source stage | Stage before runtime with publish output | `publish` |
| SDK version | `global.json` → `sdk.version` | Derived from `TargetFramework` |
| Target framework | `<TargetFramework>` or highest in `<TargetFrameworks>` | `net8.0` |
| Root namespace | `<RootNamespace>` in `.csproj` | Project name |

### Namespace Aggregation
Collects namespaces from identified files to create a **whitelist filter configuration** (`namespaces.json`) for the generic instrumentor. The instrumentor reads this config at runtime to only instrument code in these namespaces — skipping system libraries and generated code.

### Compose Generation Opt-Out (`--no-compose`)
By default, when `--src` has no existing compose file, `bin/fuzz-prep-multi.py` generates a single-service `docker-compose.instrumented.yml` from scratch. For a multi-service target (a DB, an identity/auth server, background workers, ...) this auto-generated file is typically thrown away in favor of a hand-written one anyway. `--no-compose` skips generating it and instead writes `COMPOSE_REQUIREMENTS.md` — what a hand-written compose file needs (env vars, volumes, ports) to work with the generated instrumentation — into `--out`. This has no effect when `--src` already has a compose file: that one is always adapted in place either way, regardless of the flag. See `docs/guides/target-specific/bitwarden-runbook.md` for a worked multi-service example.

---

## 2. Docker Build Pipeline

The adapted Dockerfile has 4 stages:

```
┌───────────────────────────┐
│  instrumentor-build        │  Builds the SharpFuzz instrumentor tool
│  FROM sdk AS               │  from instrumentor_src/Program.cs
│  instrumentor-build        │  (separate stage — doesn't slow app build)
└─────────────┬─────────────┘
              │
┌─────────────▼─────────────┐
│  builder → publish         │  Standard project build:
│  FROM sdk AS builder       │  dotnet restore → dotnet publish
└─────────────┬─────────────┘
              │
┌─────────────▼─────────────┐
│  instrumentation           │  FROM publish AS instrumentation
│  Inherits published output │  Copies instrumentor from step 1
│  Runs: instrumentor.dll    │  Instruments all business logic DLLs
│  for each *.dll            │  in-place (IL rewriting)
└─────────────┬─────────────┘
              │
┌─────────────▼─────────────┐
│  final / runtime / app     │  FROM aspnet AS final
│  COPY --from=instrumentation │  Gets pre-instrumented binaries
│  Runs the app normally     │  No SDK needed at runtime
└───────────────────────────┘
```

---

## 2a. Coverage Injection Modes (`--inject-mode`)

The coverage *runtime* (SHM allocation, SharpFuzz linking, `/shm/*` endpoints, per-request `X-Coverage-Delta` middleware) is delivered in one of two ways. IL rewriting of the business DLLs (§3) is identical in both.

### `hook` — zero-edit (default)
The prep tool generates a **self-contained `UpsideFuzz.Coverage` assembly** (`coverage_hook_src/`) and wires it via environment variables baked into the runtime image — **the target's `Program.cs`, `Startup.cs`, and `.csproj` files are never modified**:

- `DOTNET_STARTUP_HOOKS=/coverage/UpsideFuzz.Coverage.dll` — the runtime runs `StartupHook.Initialize()` **before `Main`**. It maps the shared bitmap, registers an `AssemblyLoadContext.Default.Resolving` handler (so the hook DLL + `SharpFuzz.Common.dll` load from `/coverage` without being in the app's probing path), links every currently-loaded SharpFuzz assembly, and installs an `AppDomain.CurrentDomain.AssemblyLoad` handler that links every assembly loaded **later** — this is the fix for lazily/dynamically loaded modules whose coverage was previously lost.
- `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=UpsideFuzz.Coverage` — ASP.NET loads `CoverageHostingStartup` (an `IHostingStartup`), which registers an `IStartupFilter` that inserts the coverage middleware at the front of the pipeline. The middleware serves `/shm/create`, `/shm/coverage`, `/shm/reset`, `/shm/health` inline and emits per-request `X-Coverage-Delta`/`X-Exception-*` headers.

Because `StartupHook.Initialize()` runs before any application code, the SHM pointer is bound **earlier** than in source mode, and the per-assembly `AssemblyLoad` linking closes the lazy-assembly gap. The Docker build gains one stage (`coverage-hook-build`) that publishes the assembly; the runtime stage copies `UpsideFuzz.Coverage.dll` + `SharpFuzz.Common.dll` into `/coverage` and sets the two env vars.

### `source` — legacy (`--inject-mode source`)
The previous behavior: `generate_multi_coverage_helper` writes `CoverageExtensions.cs` into the main project and `inject_multi_shm_endpoints` edits `Program.cs`/`Startup.cs` (`_inject_into_startup_cs`) to add `Initialize()`, `UseCoverageMiddleware()`, and `AddCoverageEndpoints()`. Retained for targets where source editing is preferred or where the middleware must sit *inside* the app's exception handler for maximal production-mode exception-type fidelity (the hook-mode middleware is outermost; see §5 caveat).

Both modes expose the identical `/shm/*` HTTP contract and `X-Coverage-Delta` header, so the Go engine is unchanged and mode-agnostic.

## 3. Instrumentation (IL Rewriting with SharpFuzz)

### How SharpFuzz Works
1. **Assembly Rewriting** — Reads target DLL using Mono.Cecil
2. **Probe Injection** — Inserts `SharpFuzz.Common.Trace.OnBranch` call at every basic block entry
3. **Shared Memory** — Injected code expects `SharpFuzz.Common.Trace.SharedMem` to point to valid memory

### Instrumentation Modes
The instrumentor has two selection modes; both always exclude entry points (`Program`, `Startup`), EF infra (`Migration`, `DesignTimeDbContext`), our own `CoverageExtensions`, and auto-generated types (`.g.`, `c__DisplayClass`).

**Async/iterator state machines (`d__`) are deliberately instrumented, not excluded** (fixed 2026-07-26 — previously listed alongside `c__DisplayClass` in this same "always skip" bucket). Excluding `d__` used to make coverage probes, CmpLog, and ConstantExtractor all blind to a comparison, branch, or literal written directly inside an `async Task` method — the "outer" method a class exposes is just a thin state-machine-builder stub; virtually all of a real `async` method's actual IL lives in its compiler-generated `<Method>d__N` nested type. Since that's where nearly all business logic in a modern ASP.NET Core app actually lives, this was blinding the fuzzer's smartest mechanisms on exactly the code that matters most (confirmed concretely on `fixtures/demo-app/`'s own catalog — see its README's "coverage-guided fuzzing" writeups). Removing it is safe: the *actual* static-init-timing risk (`Bit.Api.Program+<>c..cctor`'s `AccessViolationException`) is independently handled by the `+<>c`/`/<>c` compiler-lambda-cache check below, which still fully applies — including to a `Program`/`Startup`'s own async state machines, caught by the existing `Program`/`Startup` prefix checks regardless of the `d__` middle segment. See `tools/dotnet/instrumentor/Program.cs::InstrumentationFilter.Decide`'s own comment and `tools/dotnet/instrumentor.Tests/InstrumentationFilterTests.cs` for the full reasoning and regression coverage.

1. **`--instrument-all-user-code` (recommended, now the default for generated Dockerfiles):** rewrite every type whose full name does NOT start with a framework prefix (`System.`, `Microsoft.`, `Newtonsoft.`, …). Because the DLL list already contains only the target's own business assemblies, this instruments all of the app's code and nothing third-party.
2. **`namespaces.json` allowlist:** instrument only types whose full name **contains** a listed namespace (substring match via `fullName.Contains`). Convenient but dangerous — any namespace not listed is silently dropped. This is exactly how Bitwarden's entire `Bit.Commercial.*` Secrets Manager code was omitted from coverage: `Bit.Core` is not a substring of `Bit.Commercial.Core`, and the assembly itself was missing from the DLL list.

**Fail-loud + verify:** the generated instrument loop now aborts the build (`exit 1`) if a present DLL fails to instrument, instead of the old silent `|| true`. After bring-up, `verify_coverage.sh` hits an endpoint with an `X-Fuzz-Request-Id` and asserts `X-Coverage-Edges > 0` — a one-command guard against silently-broken coverage.

---

## 4. Runtime Synchronization (SHM Linking)

When the application starts, multiple DLLs each have their own copy of SharpFuzz. They all need to write to the **same** shared coverage bitmap. The current default size is **256KB** (`262144` bytes), with a minimum supported size of **64KB**.

### SHM Allocation (Dual Mode)

**Mode 1: File-Backed mmap** (when `coverage_shm` tmpfs volume is mounted)
```
/coverage_shm/bitmap  ← tmpfs file, 256KB by default (configurable)
  ↑ written by ASP.NET (all DLLs via reflection linking)
  ↑ read by Go fuzzer sidecar (direct mmap, zero HTTP overhead)
```

```csharp
var fs = new FileStream("/coverage_shm/bitmap", FileMode.OpenOrCreate, ...);
fs.SetLength(262144);
mmf = MemoryMappedFile.CreateFromFile(fs, null, 262144, ...);
accessor = mmf.CreateViewAccessor(0, 262144);
accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
globalShmAddr = (IntPtr)ptr;
```

**Mode 2: Heap Allocation** (fallback when no tmpfs volume)
```csharp
globalShmAddr = Marshal.AllocHGlobal(262144);
```
Coverage only accessible via HTTP endpoints (`GET /shm/coverage`).

The `/shm/create` response reports which mode is active: `"mode":"file-backed-mmap"` or `"mode":"heap"`.

### Reflection-Based Linking (`SyncSharpFuzz`)

```
AppDomain.CurrentDomain.GetAssemblies()
  → find all SharpFuzz.Common.Trace types
  → set SharedMem field to globalShmAddr
  → all DLLs now write to the same shared bitmap
```

This works regardless of how many project DLLs were instrumented — they all get linked to the same pointer at startup.

**Load-time linking (hook mode).** In the default `hook` mode this linking happens in two places: (1) at process start in `StartupHook.Initialize()` (`CoverageRuntime.Bootstrap` → `LinkAssembly` over all loaded assemblies), and (2) continuously, via an `AppDomain.CurrentDomain.AssemblyLoad` handler that calls `LinkAssembly` on **each assembly as it loads**. This closes a real gap in the old one-shot `SyncSharpFuzz`: assemblies loaded *after* startup (plugin/module-style dynamic loading, e.g. SimplCommerce modules) were never linked and silently contributed no coverage. `GET /shm/health` reports `linked_assemblies` and the app assemblies the runtime has observed loaded so this can be inspected at runtime — see §5's `/shm/health` and §7's fail-closed startup check (Top-20 #4) for how the engine actually verifies this rather than trusting it blindly.

---

## 5. Coverage Reporting Protocol

### `POST /shm/create` — Initialize
- Allocates SHM using the current configured size (see "Bitmap Sizing" below; 256KB default, minimum 64KB, maximum 8MB), or opens the existing tmpfs file
- Calls `SyncSharpFuzz()` to link all loaded DLLs
- Returns `{"status": "synced", "mode": "...", "bitmap_size": 262144}` (or the configured/auto-sized size)

### `GET /shm/coverage` — Global Stats
- Reads the shared bitmap via pointer arithmetic
- `edges` = number of distinct **(edge, hit-count bucket)** classes discovered so far (AFL-style bucketed novelty, see below), maintained by the coverage middleware in a persistent virgin map; `hits` = raw sum of all bitmap bytes
- Returns `{"edges": 150, "hits": 5000, "size": 262144}`

### `POST /shm/reset` — Reset Bitmap
- Zeroes the shared bitmap
- Used between fuzzing sessions; the Go engine also calls this mid-run when the bitmap is both saturated and stagnant (see "Bitmap Sizing" below)

### `GET /shm/coverage/traces` — Legacy
- Maintained for legacy compatibility but largely superseded by header-based injection.

### `GET /shm/health` — Instrumentation facts (Top-20 #4)
- Returns `{"shm_bound": bool, "mode": "...", "total_classes": N, "linked_assemblies": N, "instrumented_types": N, "app_assemblies": [...]}`.
- **Deliberately reports facts, not a verdict.** SharpFuzz's `Trace.SharedMem` type lives only in `SharpFuzz.Common.dll` — never in the app's own IL-rewritten assemblies — so "is assembly X linked" cannot be measured by type reflection on the .NET side; an app assembly that is instrumented correctly will *never* show up as having its own `Trace` type. `app_assemblies` is a diagnostic list of assembly names the runtime has observed loaded that aren't framework/SharpFuzz code (same `frameworkPrefixes` denylist as `tools/dotnet/instrumentor/Program.cs`, kept in sync manually), useful when diagnosing a failure — not a pass/fail signal by itself. `instrumented_types` (Top-20 #17) is the real build-time instrumented-type count — see "Bitmap Sizing" below.
- The actual fail-closed decision is made **engine-side** — see §7's "Self-verifying, fail-closed instrumentation" below.

### Bitmap Sizing (Top-20 #17)
Previously the SHM bitmap was a fixed 256KB regardless of application size, so large apps (Bitwarden, BTCPay) collided heavily while tiny ones wasted memory scanning a mostly-empty map. The bitmap is now sized from the **real instrumented-type count** captured at build time:
1. `tools/dotnet/instrumentor/Program.cs` counts the types it actually instruments (`instrumentedCount`) and, on success, appends a line to `.upsidefuzz_instrumented.jsonl` next to the DLL it just rewrote: `{"assembly":"Foo.dll","instrumented_types":N}`. A multi-assembly app (one `instrumentor.dll` invocation per DLL during the Docker build) accumulates one line per assembly.
2. At runtime, `CoverageRuntime`/`CoverageExtensions`'s `ResolveInstrumentedTypeCount()` reads that file from `AppContext.BaseDirectory` and sums `instrumented_types` across all lines.
3. `ResolveShmSize()` uses that sum — **only when the `SHM_SIZE` env var isn't pinned explicitly** — to compute a size: ~512 bitmap bytes per instrumented type, rounded up to a power of two, clamped to `[65536, 8388608]` (64KB–8MB). SharpFuzz exposes no public branch/edge count, so instrumented *type* count is a proxy, not a literal edge count — documented as such rather than overclaimed.
4. On the Go side, `SHMCoverageReader.Init()` (direct-shm mode) trusts the **actual on-disk file size** as ground truth instead of truncating it down to whatever `-coverage-bitmap-size` happened to be passed. This fixed a real latent bug: since the .NET side now sizes the file dynamically, a stale/mismatched flag value used to silently truncate the Go side's view of a properly-sized file, dropping real coverage from the untruncated remainder. A size mismatch is now only ever a diagnostic printf, never a truncation.
5. The periodic full-bitmap reset (previously: saturation > 85% alone, on a 90s timer) now also requires **stagnation** — no new edge for ≥30 seconds (`worker.go::shouldResetCoverageBitmap`) — so a reset only fires when there's actual evidence hash collisions are corrupting the signal, not just because a byte-percentage threshold was crossed while the fuzzer was still making real progress.

### AFL-Style Hit-Count Buckets (bucketed virgin map)
Coverage novelty is measured with **AFL-style hit-count buckets**, not binary edge-presence. Each edge's raw 8-bit hit count is classified into a log-scale bucket — `1, 2, 3, 4–7, 8–15, 16–31, 32–127, 128+` — via a 256-entry lookup table (`CountClass` in `CoverageExtensions.cs`, `countClass` in `coverage.go`). A **bucket bit never before seen for an edge** counts as new coverage, tracked in a persistent per-edge bucket bitmask (the "virgin map": `seenBuckets` C#-side, `seen []byte` Go-side).

This is the key resolution upgrade: an edge executed **once** is now distinguished from the same edge executed **50 or 5000 times**, so the fuzzer keeps making measurable progress inside loops, pagination, retry logic, and state machines instead of plateauing the instant every edge has been touched at least once. `edges` therefore reports *distinct (edge, bucket) classes discovered*, a strictly richer and still-monotonic signal than the previous byte->0 count.

### Per-Request Attribution (`X-Coverage-Delta`) — single-scan, first-observer-wins
The .NET middleware computes each request's novelty **once**, after the pipeline runs:
1. The pipeline executes the API business logic (SharpFuzz probes write hit counts into the shared bitmap).
2. In the middleware `finally`, `MergeAndCountNovel()` makes **one** pass over the live bitmap (with an all-zero 8-byte-word fast path), folds it into the shared bucketed virgin map, and returns the number of buckets *this request was the first to discover*.
3. That count is injected into the response header `X-Coverage-Delta: <number>` (and `X-Coverage-Edges: <totalClasses>`).

**Why this replaces the old global before/after delta:**
The previous design read a *global* edge count before and after every request — two full 256KB bitmap scans per request in the hot path — and under concurrency both a Request A and a concurrent Request B that reached new code would each be credited the *same* delta ("coverage smearing"), corrupting the energy/MOpt signal. Novelty is now measured against the **shared** virgin map on a **first-observer-wins** basis: whichever request reaches the merge first claims each new bucket; a concurrent request sees it already recorded and is credited 0. This eliminates the double-counting smearing and **halves the per-request scan cost** (one pass instead of two). The merge is guarded by a short lock (`covLock`), so concurrent requests serialize only for the microsecond-scale bucket merge, not for the whole pipeline.

**Exception attribution in production mode (`X-Exception-Type` / `X-Exception-Message`):**
The coverage middleware also reports the .NET exception type and message on 5xx responses. The subtlety: in non-Development mode the app's exception handler starts the response and clears headers *before* the middleware's `finally` block runs, so a header set there is lost — this previously left ~84% of production-mode crashes unattributable. The middleware now detects requests carrying `X-Fuzz-Request-Id` (fuzzer traffic only) and, on an unhandled exception, short-circuits with its own 500 carrying `X-Exception-Type` + `X-Exception-Message` (sanitized: CR/LF and control chars stripped, truncated). Real traffic (no fuzz header) is re-thrown untouched. The Go engine reads both headers; the message feeds `cluster.go`'s root-cause key so clustering stays precise even without a dev-mode stack trace.
---

## 6. Grammar Generation (`tools/grammar/grammarc/` + `tools/dotnet/analyzer/` — RESTler retired)

RESTler (an external Docker-packaged compiler) has been retired (Top-20 #9). `bin/compile-grammar.sh`
now drives two first-party components directly, with **no Docker involved in this step at all**
(Docker remains needed only for the target's own instrumented container):

```
swagger.json                    .NET source (optional, --src)
     │                                 │
     ▼                                 ▼
tools/grammar/grammarc/oas.py              tools/dotnet/analyzer/ (Microsoft.CodeAnalysis.CSharp,
(OpenAPI 2/3 parser:           syntax-tree only — no MSBuildWorkspace/
 $ref/allOf/oneOf/anyOf)        NuGet-restore semantic model)
     │                                 │
     │                        roslyn-constraints.json
     │                        (per-type/property constraints,
     │                         [Authorize]/route metadata,
     │                         keyed by fully-qualified type —
     │                         not a global property name)
     │                                 │
     └───────────► tools/grammar/grammarc/roslyn_merge.py ◄──────┘
                    (Roslyn wins per-field on a scoped
                     match; OAS-derived value otherwise)
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
  body_serializer.py    dependencies.py      boundary.py / multipart.py
  (schema → static/       (producer/consumer     (boundary-value pools,
   fuzzable/custom_        id inference by         multipart seed
   payload segments)        path/name convention)   templates)
          │                   │                   │
          └───────────────────┴───────────────────┘
                              │
                              ▼
              templates.export.json  +  dict.json
              (written directly — no intermediate grammar.py,
               no manual cp, no separate export-templates.py step)
```

The grammar provides:
- Request templates with method, path, headers, and body structure
- Typed fuzzable fields (`string`, `int`, `number`, `bool`, `datetime`, `uuid`, `object`), plus
  `custom_payload` fields for anything with a real constraint (enum/pattern/length/range/id-shaped/
  semantically-specific format) — routed through `dict.json`'s boundary pools and sequence/
  correlation state, not just a static default
- **Producer-consumer dependencies** — POST creates an ID that GET/PUT/DELETE uses, via a shared
  `payload_key` string threaded through path params, body fields, `dict.json`, and
  `src/void/internal/engine/store.go`'s `SequenceState`/`RuntimeStore`

**A previously-undocumented bug, found and fixed during this migration:** the old
`export-templates.py::seg_payload()` emitted JSON key `"name"` for every `custom_payload`
segment, but `src/void/internal/engine/types.go`'s `Segment` struct and `template.go`'s rendering switch read
only `PayloadKey` (JSON key `"payload_key"`) — a field-name mismatch that meant this value was
**always the empty string**, so producer→consumer chaining for `custom_payload`-kind segments
(including RESTler's own dependency chaining, not just static dictionary lookups) never actually
substituted a harvested value at render time, for the entire lifetime of the RESTler-based
pipeline. `tools/grammar/grammarc/emit_templates.py` emits `"payload_key"` directly, fixing this by
construction — no Go-side changes were needed, since Go was always reading the correct field, it
just never received it.

`void/export-templates.py` (the old grammar.py → JSON exporter) is retained only as a legacy
fallback for grammar directories generated before this migration and not yet regenerated
(`src/void/internal/engine/template.go::exportTemplates`, invoked automatically when `templates.export.json` is
missing but a `grammar.py` is present) — it is not part of the primary path.

### 6a. Segment constraint metadata (Top-20 #14)

`src/void/internal/engine/types.go`'s `Segment` struct carries optional per-field constraint metadata,
sourced from `tools/grammar/grammarc/oas.py::FieldHint` (OpenAPI + Roslyn-merged) and emitted by
`tools/grammar/grammarc/body_serializer.py::seg_fuzzable`/`seg_payload` whenever the underlying field
declares one:
```go
MinLength  *int      `json:"min_length,omitempty"`
MaxLength  *int      `json:"max_length,omitempty"`
Minimum    *float64  `json:"minimum,omitempty"`
Maximum    *float64  `json:"maximum,omitempty"`
Pattern    string    `json:"pattern,omitempty"`
EnumValues []string  `json:"enum_values,omitempty"`
```
All fields are `omitempty` and loaded via plain `json.Unmarshal` (no custom decoding) —
a `templates.export.json` generated before this addition simply decodes these to Go zero
values, so old grammars behave exactly as before. `src/void/internal/engine/mutation_engine.go`'s
`mutateAny`/`mutateHavoc`/`mutateInt`/`mutateNumber`/`mutateStringCategorized` all take
an optional `*Segment` hint; when non-nil and the relevant constraint is set, exact
boundary candidates (`{min-1, min, min+1, max-1, max, max+1}` for numerics, exact
min/max-length strings, valid/near-miss-invalid enum values) are blended into the
existing generic candidate pools — additive, not a replacement, so the nil-hint path
(anything without a schema-derived constraint) is unchanged. Verified on eShopOnWeb: the
same live-fuzz session hit the same known `pageSize` overflow bug class ~7x more often
in the same time budget after this change (124 vs. 18 crash hits, from 18k vs 54k total
requests — depth over breadth).

### 6b. Custom dictionary convention (`dict.custom.json`)

`dict.json` (§6's final artifact) is fully auto-discovered and fully overwritten by
`tools/grammar/grammarc/` on every compile — never a safe place for hand-added domain values,
since the next spec change or re-run silently discards them. `tools/grammar/grammarc/emit_dict.py`
adds a second, deliberately separate file with the opposite lifecycle:

- **`scaffold_custom_dict_if_missing(out_dir)`** — called once per `compile_grammar`
  invocation (`cli.py`), before the pool is finalized. Writes `dict.custom.json` with
  an inline `_readme` (plain JSON string array — no real comment syntax exists in
  JSON, so the documentation has to be data, not decoration) and one placeholder key
  (`exampleFieldName`, deliberately shaped so it can never be mistaken for a real
  target field) **only if the file doesn't already exist**; a no-op — returns
  `False`, touches nothing — on every subsequent run.
- **`merge_custom_dict_convention(pool, out_dir)`** — thin wrapper over the existing
  `merge_external_dict` (the same function `--dict <path>` already used), pointed at
  the fixed `out_dir / "dict.custom.json"` path instead of a CLI-supplied one. Called
  unconditionally after any explicit `--dict` merge, so the two are independent and
  additive: a one-off/CI-supplied `--dict` file for pipeline-specific values, plus
  the convention file for values a human maintains by hand across runs.

Net effect: `dict.custom.json` is created once, read every time, and never written to
again by the tool — the inverse lifecycle of `dict.json` — so values added there
survive indefinitely across regenerations, including ones triggered by the target's
own OpenAPI spec changing. No `--dict` flag or other configuration is required for
this path; it's purely a fixed filename convention inside `--out`. Full user-facing
workflow: `INSTRUCTIONS.md` §10 ("Custom Dictionary Format"). Tests:
`tools/grammar/grammarc/test_emit_dict.py` (`python3 -m unittest grammarc.test_emit_dict`),
covering scaffold creation, the never-overwrite guarantee, and a full two-run
survives-regeneration simulation.

---

## 7. Void Engine (Fuzzing Runtime)

Moved to its own document: **[ARCHITECTURE_ENGINE.md](engine.md)** —
component map, CmpLog/RedQueen, constant extraction, the response-schema
conformance oracle, state-reward sequence search, the typed resource-lifecycle
graph, epoch architecture, mutation engine, triage scoring, clustering, SARIF
export, and the vulnerability oracles. Split out from this file since it had grown
to cover more than half of this document's length on its own — this file now
covers the pipeline *up to* the point `void` starts running; that one covers what
happens once it does.

---

## 8. SHM Architecture: Why Shared Memory?

HTTP coverage polling (the fallback) adds ~0.5–2ms per batch. At high concurrency (64+ workers), this becomes a meaningful bottleneck. Direct SHM mode eliminates it entirely:

| Method | Throughput (est.) | Overhead | Notes |
|--------|-------------------|----------|-------|
| HTTP JSON (`GET /shm/coverage`) | ~300–600 req/s cap | TCP + routing + serialization | Works everywhere, no volume needed |
| File-backed mmap (`-direct-shm`) | 2000+ req/s | ~microseconds (OS page cache) | Requires `coverage_shm` tmpfs volume (Docker sidecar mode) |

How file-backed mmap works across containers:

```
  [App Container]                    [Fuzzer Container]
  /coverage_shm/bitmap               /coverage_shm/bitmap
        ↑                                   ↓
        └─────── Docker tmpfs volume ────────┘
                  (same physical pages)

  SharpFuzz probes write at every branch
  Go fuzzer reads bitmap every N requests
  → zero HTTP overhead, zero serialization
```

---

## 9. Verified Projects

These targets have current quickstarts, prepared trees, or active benchmark material in this workspace:

| Project | Type | Services | Notes |
|---------|------|---------|-------|
| **Bitwarden** | OSS password manager backend | MSSQL, Identity service, Migrator | Multi-user auth, strict validation, multi-identity fuzzing |
| **BTCPayServer** | OSS payment platform | PostgreSQL, NBXplorer, Bitcoin stack | Greenfield API, API-key auth, larger service graph |
| **eShopOnWeb** | OSS sample store API | SQL Server | Smallest end-to-end target in the repo; `PublicApi` is main project |
| **SimplCommerce** | OSS modular e-commerce | SQL Server, MVC/auth stack | Cookie auth and anti-forgery-heavy target |

---

## 10. Project File Map (Current State)

This section used to carry a full, hand-maintained file-by-file tree here — it drifted
badly (twice) and duplicated content already kept current elsewhere, so it's now a
concise map instead, pointing to the files that actually stay accurate:

```
upside-fuzzer/
├── upsidefuzz                  ★ The one public launcher (Docker zero-install, --no-docker native)
├── bin/                        Entry-point scripts: fuzz-prep-multi.py, compile-grammar.sh, verify-hook.sh
│   └── compatibility/          Back-compat wrappers (upsidefuzz.py, campaign.py, security_scenarios.py)
├── src/
│   ├── void/                   ★ Self-contained Go module (go.mod here) -- the fuzzing engine
│   └── cli/upsidefuzz/         The upsidefuzz CLI package (cli.py + __main__.py)
├── tools/
│   ├── prep/fuzzprep/          ★ Multi-project .NET instrumentation implementation
│   ├── grammar/grammarc/       ★ First-party OpenAPI → typed grammar compiler (Python, stdlib)
│   ├── campaign/                campaign.yaml + security_scenarios.yaml contracts
│   └── dotnet/{analyzer,instrumentor}/   The two C# build-time tools, each with xUnit tests
├── fixtures/demo-app/          ★ TeamFlow: flagship in-repo demo target
├── fixtures/planted-bug-api/   Minimal fixture used by the E2E CI gate
├── deployments/docker/         Dockerfile.void, Dockerfile.cli
├── scripts/                    e2e-test.sh (CI gate), test-compile-grammar-cli.sh
├── tests/integration/compatibility/   Smoke tests for every bin/ wrapper + the launcher
├── docs/                       See docs/index.md
└── README.md
```

For the exhaustive, kept-current file-by-file breakdown: `src/void/internal/engine/`'s
own component map lives in [`engine.md`](engine.md#component-map) (this document's
sibling covering the fuzzing runtime specifically), `tools/prep/fuzzprep/`'s in
`tools/prep/fuzzprep/__init__.py`, `tools/grammar/grammarc/`'s in
`tools/grammar/grammarc/README.md`, and the full old-path → new-path map from the
2026-07-31 repo cleanup in [`docs/guides/repo-layout.md`](../guides/repo-layout.md).

Third-party target checkouts (`bitwarden_prep/`, `btcpayserver/`, `eshprep/`,
`simplcommerce_prep/`, etc.), their generated `grammars/`, and fuzzer output
directories (`crashes/`, `summaries/`) are local, gitignored working state —
produced on demand by `bin/fuzz-prep-multi.py`/`bin/compile-grammar.sh`/`void`, never
committed, and not part of this map.

---

## 11. Continuous Integration and test coverage

Moved to its own page: **[testing.md](testing.md)** — the E2E regression gate,
how `fixtures/planted-bug-api/` is shaped and why, and the unit/integration
test coverage history (Go/Python/.NET) by pass. Split out during the
repo-architecture refactor alongside [tests/README.md](../../tests/README.md)
(which documents the current test *organization*; this page documents the CI
*gate* and its history).

---

