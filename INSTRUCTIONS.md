# UpsideFuzz: Complete Guide to Instrumenting and Fuzzing Any .NET Project

Step-by-step runbook for **any .NET 8+ web API** — from source code to coverage-guided fuzzing on a new system.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [How It Works — Overview](#2-how-it-works--overview)
3. [Step 1: Instrument the Project](#3-step-1-instrument-the-project)
4. [Step 2: Build & Start with Docker Compose](#4-step-2-build--start-with-docker-compose)
5. [Step 3: Verify Instrumentation](#5-step-3-verify-instrumentation)
6. [Step 4: Compile the Grammar](#6-step-4-compile-the-grammar)
7. [Step 5: Run the Fuzzer](#7-step-5-run-the-fuzzer)
8. [Go Fuzzer CLI Reference](#8-go-fuzzer-cli-reference)
9. [Real-World Examples](#9-real-world-examples)
   - [mpt-helpdesk](#mpt-helpdesk)
   - [mpt-currency](#mpt-currency)
   - [nopCommerce](#nopcommerce)
   - [eShopOnWeb](#eshoponweb-dev-example)
   - [CustomerLoyalty](#customerloyalty-dev-example)
10. [Custom Dictionary Format](#10-custom-dictionary-format)
11. [Quality Gates](#11-quality-gates)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

Install the following on any new system before running UpsideFuzz:

| Tool | Version | Purpose |
|------|---------|---------|
| **Docker** + **Docker Compose v2** | Docker 24+, Compose 2.x | Build & run instrumented containers |
| **Python** | 3.9+ | Run `fuzz-prep-multi.py` and `enhance-grammar.py` |
| **.NET SDK** | 8+ | RESTler grammar compiler (`compile-grammar.sh`) |
| **Go** (optional) | 1.22+ | Only if you build the Go fuzzer binary locally |

```bash
# Verify tooling
docker --version        # Docker version 24+
docker compose version  # Docker Compose version v2+
python3 --version       # Python 3.9+
dotnet --version        # 8.0+
```

> **Note:** The Go fuzzer runs as a Docker container, so Go itself is NOT required on the host unless you build locally.

---

## 2. How It Works — Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Your .NET Solution (source)                                            │
│  *.sln / *.csproj / Dockerfile / docker-compose.yml                    │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                    fuzz-prep-multi.py
                    (Analyzes, copies, instruments)
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Instrumented Project Copy (output dir)                                 │
│                                                                         │
│  ┌─── Dockerfile (4 stages) ──────────────────────────────────────┐    │
│  │  1. builder        → dotnet restore + publish                  │    │
│  │  2. instrumentor-build → build SharpFuzz instrumentor tool     │    │
│  │  3. instrumentation  → rewrite DLL IL with coverage probes     │    │
│  │  4. runtime        → minimal aspnet image (pre-instrumented)   │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─── compose.yaml ───────────────────────────────────────────────┐    │
│  │  + /dev/shm:/dev/shm volume                                    │    │
│  │  + coverage_shm (tmpfs) volume                                 │    │
│  │  + ASPNETCORE_ENVIRONMENT=Development                          │    │
│  │  + [commented] void sidecar                          │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─── Helpers/CoverageExtensions.cs ──────────────────────────────┐    │
│  │  POST /shm/create    → alloc SHM, sync SharpFuzz across DLLs  │    │
│  │  GET  /shm/coverage  → returns { edges, hits }                 │    │
│  │  POST /shm/reset     → zeroes the bitmap                       │    │
│  └────────────────────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                    docker compose build
                    docker compose up -d
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Running Containers                                                     │
│                                                                         │
│  [App API]  ←─── SharpFuzz probes write to 64KB bitmap                │
│  [DB/Cache] ←─── seeded & migrated at startup                          │
│                                                                         │
│  Coverage bitmap:                                                       │
│    file-backed mmap  →  /coverage_shm/bitmap  (tmpfs volume)           │
│    fallback heap     →  in-process only                                │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
              compile-grammar.sh swagger.json --src <src>
              (RESTler compile + enhance-grammar.py enrichment)
                             │
                             ▼
┌────────────────────────────┐     ┌────────────────────────────────────┐
│  grammar.py                │     │  dict.json                         │
│  • Request templates       │     │  • Domain-specific tokens          │
│  • Fuzzable fields         │     │  • Enum values, IDs, strings       │
│  • Producer→Consumer deps  │     │  • From OpenAPI + C# source        │
└────────────┬───────────────┘     └─────────────────────────────────── ┘
             │
    docker compose --profile fuzz-go run --rm void -grammar <grammar_dir>
             │
             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Void (Coverage-Guided)                                       │
│                                                                         │
│  Epochs: Baseline → Deterministic → Havoc → Splicing                   │
│  Reads bitmap via mmap (--direct-shm) or HTTP (/shm/coverage)          │
│  Logs crashes to JSONL, prints live TUI dashboard                       │
│  Adaptive concurrency, crash triage, PoC generation                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Step 1: Instrument the Project

```bash
python3 /path/to/mvpsharpfuzznet/fuzz-prep-multi.py \
  --src <SOURCE_DIR> \
  --out <OUTPUT_DIR> \
  [--main <WEB_API_PROJECT_NAME>]
```

| Flag | Description |
|------|-------------|
| `--src` | Path to the .NET solution (source, NOT instrumented) |
| `--out` | Output directory for the instrumented copy |
| `--main` | Web API project name (required for multi-project solutions) |

**Example:**
```bash
python3 fuzz-prep-multi.py \
  --src ./mpt-helpdesk \
  --out ./prepared-helpdesk \
  --main Mpt.Helpdesk.Api
```

### What the script does

1. **Scans** all `.csproj` files in the solution
2. **Skips** test projects (`*.Tests.csproj`, paths containing `/test/`, `/tests/`)
3. **Detects business logic** via file-name heuristics:

   | Pattern | Category |
   |---------|----------|
   | `*Controller.cs` | API endpoint handlers |
   | `*Service.cs` | Business logic services |
   | `*Repository.cs` | Data access layer |
   | `*Handler.cs` | CQRS/MediatR handlers |
   | `*Validator.cs` | Input validation |
   | `*Command.cs`, `*Query.cs` | CQRS objects |
   | `*Aggregate.cs`, `*Specification.cs` | DDD patterns |
   | `*Endpoint.cs` | Minimal API / FastEndpoints |
   | `*Logic.cs`, `*Manager.cs` | Domain logic |
   | Directories: `Controllers/`, `Features/`, `Handlers/` | Structural |

4. **Generates** `instrumentor_src/Program.cs` — namespace-filtered SharpFuzz instrumentor
5. **Generates** `Helpers/CoverageExtensions.cs` — SHM middleware + endpoints
6. **Adapts** original Dockerfile with 2 injected build stages:
   - `instrumentor-build` — compiles the SharpFuzz instrumentor tool
   - `instrumentation` — rewrites DLL IL in-place
7. **Adapts** original `docker-compose.yml`:
   - Adds `/dev/shm:/dev/shm` volume mount
   - Adds `coverage_shm` tmpfs volume
   - Adds `ASPNETCORE_ENVIRONMENT=Development`
   - Adds commented-out `void` sidecar block
8. **Patches** `.csproj` files: adds `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>` and `SharpFuzz` package reference
9. Injects into `Program.cs`: `CoverageExtensions.Initialize()`, `UseCoverageMiddleware()`, `AddCoverageEndpoints()`

### Files modified in output (NOT in source)

| File | Change |
|------|--------|
| `Dockerfile` | +2 build stages |
| `docker-compose.yml` | +SHM volumes, +Development env, +sidecar |
| `Program.cs` | +coverage initialization |
| `*.csproj` | +`AllowUnsafeBlocks`, +`SharpFuzz` |
| `Directory.Packages.props` | +SharpFuzz version (if CPVM) |
| `instrumentor_src/Program.cs` | **New file** — SharpFuzz instrumentor |
| `Helpers/CoverageExtensions.cs` | **New file** — SHM middleware + endpoints |

---

## 4. Step 2: Build & Start with Docker Compose

```bash
cd <OUTPUT_DIR>
docker compose build
docker compose up -d

# Wait for DB migrations to complete (varies by project — typically 30-60s)
sleep 45

# Confirm API is responding
curl -s http://localhost:<PORT>/swagger/v1/swagger.json | head -c 200
```

> **Port conflicts:** Run `docker ps` first. If ports are in use, edit the `ports:` section in `docker-compose.yml`.

> **DB migrations:** If the project doesn't auto-migrate on startup, you may need to add retry-based `db.Database.Migrate()` to `Program.cs`.

---

## 5. Step 3: Verify Instrumentation

```bash
# 1. Initialize SHM — allocates 64KB bitmap, syncs SharpFuzz across all DLLs
curl -s -X POST http://localhost:<PORT>/shm/create
# → {"status":"synced","mode":"file-backed-mmap","bitmap_size":65536,...}

# 2. Send any API request to generate coverage
curl -s http://localhost:<PORT>/api/some-endpoint

# 3. Check coverage counters
curl -s http://localhost:<PORT>/shm/coverage
# → {"edges":43,"hits":87}
```

| Response field | Meaning |
|----------------|---------|
| `edges` | Unique code paths discovered (should be > 0 after any request) |
| `hits` | Cumulative branch executions |
| `mode: file-backed-mmap` | SHM bitmap on shared tmpfs — Go fuzzer can read it via mmap |
| `mode: heap` | Fallback — no tmpfs volume, HTTP coverage only |

**If `edges` is 0 after real API requests:**
- SHM not synced → call `POST /shm/create` first
- Wrong project `--main` → re-run `fuzz-prep-multi.py` pointing to the correct web project
- Auth required → test your endpoints with curl adding the auth header

---

## 6. Step 4: Compile the Grammar

The grammar describes every API request shape — method, path, headers, body — as typed, fuzzable templates.

```bash
cd /path/to/mvpsharpfuzznet

# Download swagger from running instrumented app
curl -s http://localhost:<PORT>/swagger/v1/swagger.json -o swagger.json

# Compile grammar (with source-aware enhancement)
./compile-grammar.sh swagger.json --src <SOURCE_DIR>

# Or with a custom dictionary for domain-specific values:
./compile-grammar.sh swagger.json --dict custom-dict.json --src <SOURCE_DIR>

# Save to grammars/<project>/
mkdir -p grammars/<project>
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/<project>/
```

> **nopCommerce tip:** Prefer `/fuzz/openapi.json` over `/swagger/v1/swagger.json` — it covers conventional MVC routes.

### What `compile-grammar.sh` does

1. Runs **RESTler compiler** against the OpenAPI spec → produces `grammar.py` (typed request templates + producer/consumer dependency chains) and `dict.json`
2. Runs **`enhance-grammar.py`** (post-processor) that enriches the outputs with:
   - OpenAPI constraints: `enum` values, `format`, `minimum/maximum`, `pattern` regex
   - C# source constraints: `[Required]`, `[Range]`, `[StringLength]`, `[RegularExpression]`, FluentValidation chains, enum declarations
   - Multipart form-data: autogenerated seed templates for `multipart/form-data` endpoints

---

## 7. Step 5: Run the Fuzzer

### Mode A — Go Fuzzer as Docker sidecar (recommended, direct SHM)

Add the `fuzz-go` profile to the output compose and run:

```bash
cd <OUTPUT_DIR>

export AUTH_TOKEN="<your-jwt-token>"
docker compose --profile fuzz-go run --rm void \
  -grammar /grammar_path \
  -direct-shm \
  -time-budget 60
```

All bug-finding features (triage, repro, minimization, race detection, anti-forgery) are **on by default** — no extra flags needed.

For a fast CI scan (disable slow analysis):

```bash
export AUTH_TOKEN="<your-jwt-token>"
docker compose --profile fuzz-go run --rm void \
  -grammar /grammar_path \
  -direct-shm \
  -time-budget 20 \
  -concurrency 64 -max-concurrency 128 \
  -request-timeout 2.5 -coverage-interval 6 \
  -crash-triage=false -repro-runs 0 -minimize-crash=false \
  -crash-replay-count 0 -crash-boost-requests 0 \
  -no-ui
```

> For this to work, the `void` service must be defined in the compose file with the `fuzz-go` profile. `fuzz-prep-multi.py` adds a commented-out template — uncomment and configure it.

### Mode B — Go Fuzzer on host (HTTP coverage mode)

Target URL and auth are set via **environment variables**, not flags:

```bash
cd /path/to/mvpsharpfuzznet/void/go

# Build binary (one-time — see Build section below)
go build -o void .

# Run against a locally running instrumented app
export TARGET_HOST="http://localhost:<PORT>"
export SHM_HOST="http://localhost:<PORT>"   # same as TARGET_HOST unless separate
export AUTH_TOKEN="<your-jwt-token>"

./void -grammar ../grammars/<project> -time-budget 20
```

All bug-finding features are **on by default**: crash triage, repro, minimization, race detection, anti-forgery tokens, adaptive concurrency, source-aware prioritization.

### Fuzzing without auth (public API)

Simply omit `AUTH_TOKEN` / `AUTH_URL`. The fuzzer starts immediately without authentication.

### Inspect crash output

```bash
# Live crash log (JSONL, one record per crash)
tail -f crashes/all-crashes.jsonl

# Deduplicated unique crashes
tail -n 50 crashes/unique-crashes.jsonl

# Pretty-print a crash
cat crashes/unique-crashes.jsonl | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin]"
```

---

## 8. Go Fuzzer CLI Reference

> **Target URL and auth are environment variables, not flags:**
> ```bash
> export TARGET_HOST="http://localhost:8080"
> export SHM_HOST="http://localhost:8080"  # same unless separate coverage host
> export AUTH_TOKEN="<jwt>"
> ```

### Minimal invocation

```bash
# Host mode (HTTP coverage)
./void -grammar /path/to/grammar -time-budget 60

# Docker sidecar (direct SHM — faster)
docker compose --profile fuzz-go run --rm void \
  -grammar /path/to/grammar \
  -direct-shm -time-budget 60
```

### Flags you almost never need to change

The following are **on by default** and only need explicit flags to *disable*:

| Feature | Default | To disable |
|---------|---------|------------|
| Adaptive concurrency | ON | `-adaptive-concurrency=false` |
| Crash triage & scoring | ON | `-crash-triage=false` |
| Crash reproducibility check | 5 runs | `-repro-runs 0` |
| Crash payload minimization | ON | `-minimize-crash=false` |
| Race condition detection | ON | `-race-mode=false` |
| Anti-forgery token harvesting | ON | `-auto-antiforgery=false` |
| Source-aware endpoint priority | ON | `-source-aware-priority=false` |
| Multi-identity scheduling | ON | `-multi-identity=false` |

### Flags worth tuning

| Flag | Default | When to change |
|------|---------|----------------|
| `-time-budget` | `10` min | Increase for thorough scan (60–120 min) |
| `-concurrency` | `10` | Increase for fast targets (32–64) |
| `-max-concurrency` | `64` | Upper bound for adaptive mode |
| `-request-timeout` | `5.0` s | Lower for fast targets (2.5), raise for slow ones |
| `-direct-shm` | `false` | Set `true` in Docker sidecar mode |
| `-sequence-prob` | `0.30` | Raise to 0.5–0.6 for stateful API testing |
| `-sequence-max-depth` | `3` | Raise to 5–6 for deep workflows |
| `-sequence-fanout` | `6` | Raise to 8–10 for wide API surface |
| `-skip-endpoint-on-500` | `false` | Set `true` when 500s are expected (misconfigured infra) |
| `-coverage-interval` | `1` | Raise to 5–10 for throughput benchmarking |

### Fast-scan profile (CI — maximize throughput, skip slow analysis)

```bash
docker compose --profile fuzz-go run --rm void \
  -grammar /path/to/grammar \
  -direct-shm \
  -time-budget 20 \
  -concurrency 64 -max-concurrency 128 \
  -request-timeout 2.5 -coverage-interval 6 \
  -crash-triage=false -repro-runs 0 -minimize-crash=false \
  -crash-replay-count 0 -crash-boost-requests 0 \
  -no-ui
```

### Full flag reference

See [`void/README.md`](void/README.md) for the complete table of all 60+ flags with accurate defaults taken from source.

### Build for any platform

See [`void/README.md §Build`](void/README.md#build-for-any-platform) for cross-compilation and Docker buildx instructions.

---

## 9. Real-World Examples

### mpt-helpdesk

Multi-service .NET solution with SQL Server, Azure Service Bus, Blob Storage, and a separate Worker process.

#### Instrument

```bash
python3 fuzz-prep-multi.py \
  --src ./mpt-helpdesk \
  --out ./prepared-helpdesk \
  --main Mpt.Helpdesk.Api
```

#### Build & start

```bash
cd prepared-helpdesk
docker compose build
docker compose up -d
sleep 60  # DB migration + Azurite startup

# Verify
curl -s -X POST http://localhost:8080/shm/create
curl -s http://localhost:8080/shm/coverage
```

#### Compile grammar

```bash
cd /path/to/mvpsharpfuzznet
curl -s http://localhost:8080/swagger/v1/swagger.json -o swagger.json
./compile-grammar.sh swagger.json --src ./mpt-helpdesk
mkdir -p grammars/helpdesk
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/helpdesk/
```

#### Fuzz — base profile

```bash
cd prepared-helpdesk
AUTH_TOKEN="<token>" docker compose --profile fuzz-go run --rm void \
  --direct-shm --shm-path /coverage_shm/bitmap --shm-read-mode file \
  --grammar /grammar --templates-json /fuzzer/templates.helpdesk.json --src /src \
  --time-budget 20 --concurrency 16 --adaptive-concurrency \
  --sequence-prob 0.35 --sequence-max-depth 4 --sequence-fanout 8
```

#### Fuzz — max throughput profile

```bash
AUTH_TOKEN="<token>" docker compose --profile fuzz-go run --rm void \
  --direct-shm --shm-path /coverage_shm/bitmap --shm-read-mode file \
  --grammar /grammar --templates-json /fuzzer/templates.helpdesk.json \
  --time-budget 20 --concurrency 64 --min-concurrency 64 --max-concurrency 160 \
  --adaptive-concurrency --request-timeout 2.0 --max-response-bytes 8192 \
  --coverage-interval 8 --sequence-prob 0 --race-mode=false \
  --crash-triage=false --repro-runs 0 --minimize-crash=false \
  --crash-replay-count 0 --skip-endpoint-on-500 --no-ui
```

#### Fuzz — hybrid profile (race detection + multi-identity)

```bash
AUTH_TOKEN="<token>" docker compose --profile fuzz-go run --rm void \
  --direct-shm --shm-path /coverage_shm/bitmap --shm-read-mode file \
  --grammar /grammar --templates-json /fuzzer/templates.helpdesk.json --src /src \
  --time-budget 20 --concurrency 48 --min-concurrency 24 --max-concurrency 96 \
  --adaptive-concurrency --sequence-prob 0.25 --sequence-max-depth 3 \
  --sequence-fanout 5 --race-prob 0.06 --race-burst 3 \
  --source-aware-priority=true --multi-identity=true \
  --crash-triage=false --repro-runs 0 --minimize-crash=false
```

---

### mpt-currency

.NET API with currency management endpoints. Similar setup to helpdesk but simpler service graph.

#### Instrument

```bash
python3 fuzz-prep-multi.py \
  --src ./mpt-currency \
  --out ./mpt-prepared \
  --main <WebApiProjectName>
```

#### Fuzz

```bash
cd mpt-prepared
AUTH_TOKEN="..." \
docker compose --profile fuzz-go run --rm void \
  --direct-shm --shm-path /coverage_shm/bitmap \
  --time-budget 7 --concurrency 16 --coverage-interval 4 \
  --sequence-prob 0.35 --sequence-max-depth 4 --sequence-fanout 8
```

---

### nopCommerce

Large open-source .NET e-commerce platform. Uses the automated bootstrap script.

#### Instrument + grammar + compose in one command

```bash
cd /path/to/mvpsharpfuzznet

./prepare-nopcommerce.sh \
  --src /absolute/path/to/nopCommerce \
  --swagger-url http://localhost/fuzz/openapi.json
```

> The bootstrap script: instruments the project, builds Docker images, starts the stack, waits for DB seeding, downloads the swagger spec, and compiles the grammar.

#### Fuzz

```bash
cd nopcommerce-prepared

docker compose -f docker-compose.yml -f docker-compose.fuzz-go.yml \
  --profile fuzz-go run --rm void \
  --direct-shm \
  --shm-path /coverage_shm/bitmap \
  --coverage-bitmap-size 262144 \
  --coverage-interval 4 \
  --endpoint-stall-reqs 220 \
  --endpoint-zero-edge-reqs 120 \
  --antiforgery-sample-rate 0.10 \
  --antiforgery-max-tokens 2048 \
  --antiforgery-token-ttl 300 \
  --time-budget 30 \
  --concurrency 16 \
  --adaptive-concurrency \
  --ui-endpoint-sort recent \
  --ui-endpoint-rotate \
  --ui-endpoint-rotate-sec 0.8
```

---

### eShopOnWeb (dev example)

```bash
# Instrument
python3 fuzz-prep-multi.py --src ./esh --out ./eshprep --main PublicApi

# Start
cd eshprep && docker compose up -d && sleep 40

# Compile grammar
cd .. && ./compile-grammar.sh swagger-eshop.json --src ./esh
cp restler_output/Compile/* grammars/eshop/

# Fuzz (HTTP mode)
cd void/go
export TARGET_HOST="http://localhost:5200"
export SHM_HOST="http://localhost:5200"
export AUTH_TOKEN="<token>"
./void -grammar ../../grammars/eshop -time-budget 5
```

---

### CustomerLoyalty (dev example)

```bash
# Instrument
python3 fuzz-prep-multi.py --src ./customer-loyalty --out ./loyalty-prep --main WebAPI

# Start
cd loyalty-prep && docker compose up -d && sleep 40

# Compile grammar
cd .. && ./compile-grammar.sh swagger-loyalty.json --src ./customer-loyalty
cp restler_output/Compile/* grammars/loyalty/

# Fuzz (HTTP mode)
cd void/go
export TARGET_HOST="http://localhost:5100"
export SHM_HOST="http://localhost:5100"
export AUTH_TOKEN="<token>"
./void -grammar ../../grammars/loyalty -time-budget 5
```

---

## 10. Custom Dictionary Format

The `--dict` flag to `compile-grammar.sh` accepts a JSON file that provides domain-specific values to seed the fuzzer's mutation engine.

### Structure

```json
{
  "fuzzableString": ["value1", "value2"],
  "fuzzableInt": ["1", "42", "999"],
  "customFieldName": ["domain-specific-value"],
  "restler_custom_payload": {
    "fieldName": ["exact-value-1", "exact-value-2"]
  },
  "restler_custom_payload_unquoted": {
    "numericField": ["123", "456"]
  },
  "restler_custom_payload_query": {
    "queryParam": ["filter-value"]
  }
}
```

### Top-level arrays

Any top-level key whose value is an array of strings is treated as a pool of values for that semantic type:

```json
{
  "fuzzableString": ["hello", "world", "<script>", "' OR 1=1--"],
  "fuzzableInt": ["0", "-1", "2147483647"]
}
```

### RESTler payload containers

| Key | Description |
|-----|-------------|
| `restler_custom_payload` | Exact string values (quoted in JSON body) |
| `restler_custom_payload_unquoted` | Unquoted values (numbers, booleans) |
| `restler_custom_payload_query` | Values for URL query parameters |
| `restler_custom_payload_header` | Values for HTTP headers |

**Inside each container**, keys are matched to request field names (case-insensitive, canonical normalization):

```json
{
  "restler_custom_payload": {
    "currencyCode": ["USD", "EUR", "GBP", "JPY"],
    "countryId": ["US", "DE", "GB", "FR"],
    "userId": ["usr-001", "usr-002"]
  }
}
```

### Real-world example: SoftwareOne marketplace currencies

```json
{
  "restler_custom_payload": {
    "currencyCode": ["USD", "EUR", "GBP", "CHF", "SEK", "PLN"],
    "currencyId": ["CUR-001", "CUR-002"],
    "amount": ["0", "1", "100", "99999.99", "-1"]
  },
  "fuzzableString": ["test", "INVALID", ""],
  "fuzzableInt": ["0", "1", "-1", "2147483647"]
}
```

### Tips

- Keys are normalized: `userId`, `user_id`, `UserId`, `user-id` all match the same canonical key.
- Values containing `{{`, `${`, `#{}` are filtered out by the runtime store to avoid injection feedback loops.
- Nested `dictionaries:` wrapper is supported (backward compat with old format).

---

## 11. Quality Gates

Use these gates to evaluate whether a fuzzing run reached meaningful depth.

| Gate | Check | Meaning |
|------|-------|---------|
| **A — Instrumentation** | `edges > 0` after API calls | SharpFuzz probes are active and SHM is linked |
| **B — Grammar quality** | Multiple endpoints loaded; at least one 2xx on write endpoints | Swagger spec was valid; auth is configured |
| **C — Stateful depth** | Event log shows `SEQUENCE +N depth=...`; consumer endpoints return 2xx | Producer→consumer chains are discovered and used |
| **D — Crash logging** | `all-crashes.jsonl` non-empty when 5xx appear | Crash capture and deduplication work |

**Recommended baseline for most APIs:**

```bash
--time-budget 20
--concurrency 12
--request-timeout 2.5
--sequence-prob 0.55
--sequence-max-depth 5
--sequence-fanout 8
```

**For slow / unstable APIs:**
```bash
--concurrency 6
--request-timeout 5
--sequence-fanout 4
```

---

## 12. Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Connection refused | DB/migrations not ready | Increase `sleep` after `docker compose up -d` |
| `edges: 0` after requests | SHM not initialized | Call `POST /shm/create` first |
| `edges: 0` with all requests | Auth failing | Set `AUTH_TOKEN` or `AUTH_URL` / `AUTH_BODY` |
| `/shm/create` returns 404 | Wrong project instrumented | Re-run `fuzz-prep-multi.py --main <correct-project>` |
| Auth failing | Wrong credentials | `curl -X POST $TARGET_HOST$AUTH_URL -d "$AUTH_BODY"` |
| Grammar has 0 endpoints | Wrong swagger.json | Re-download: `/swagger/v1/swagger.json` or `/fuzz/openapi.json` |
| Docker build fails on instrumentation | DLL not found | Check publish output path in Dockerfile; run `docker build --progress=plain .` |
| All writes are 401/403 | Auth token expired or wrong role | Refresh `AUTH_TOKEN`; verify the user has write permissions |
| Coverage is flat after warmup | All endpoints exhausted or API too slow | Increase `--sequence-prob`, reduce `--concurrency` |
| Fuzzer exits immediately | grammar.py parse error | Check Python syntax: `python3 -c "import grammar"` from grammar dir |
