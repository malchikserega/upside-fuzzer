# UpsideFuzz: Complete Guide to Instrumenting and Fuzzing Any .NET Project

Step-by-step runbook for **any .NET 8+ web API** — from source code to coverage-guided fuzzing on a new system.

**→ [Back to README](README.md) · [Architecture](ARCHITECTURE.md) · [Authentication](docs/FUZZER_AUTHENTICATION.md) · [Docs Index](docs/INDEX.md)**

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [How It Works — Overview](#2-how-it-works--overview)
3. [Step 1: Instrument the Project](#3-step-1-instrument-the-project)
4. [Step 2: Build & Start with Docker Compose](#4-step-2-build--start-with-docker-compose)
5. [Step 3: Verify Instrumentation](#5-step-3-verify-instrumentation)
6. [Step 4: Compile the Grammar](#6-step-4-compile-the-grammar)
   - [Template export for Void (`templates.export.json`)](#grammar-folder-and-template-export-for-void)
7. [Step 5: Run the Fuzzer](#7-step-5-run-the-fuzzer)
   - [Authentication (JWT, API keys, custom headers, and cookies)](#authentication-jwt-api-keys-custom-headers-and-cookies)
   - [Void without Docker Compose (`docker run`)](#void-without-docker-compose-docker-run)
8. [Go Fuzzer CLI Reference](#8-go-fuzzer-cli-reference)
9. [Real-World Examples](#9-real-world-examples)
   - [Bitwarden](#bitwarden)
   - [BTCPayServer](#btcpayserver)
   - [eShopOnWeb](#eshoponweb)
   - [SimplCommerce](#simplcommerce)
10. [Custom Dictionary Format](#10-custom-dictionary-format)
11. [Quality Gates](#11-quality-gates)
12. [Troubleshooting](#12-troubleshooting)

**Project quickstarts:** [Bitwarden](QUICKSTART_BITWARDEN.md) · [BTCPayServer](QUICKSTART_BTCPAYSERVER.md) · [eShopOnWeb](QUICKSTART_ESHOP.md) · [SimplCommerce](QUICKSTART_SIMPLCOMMERCE.md)

> **Steps 1–5 below, as one command:** `./upsidefuzz run --src ... --out ... --target ... --swagger ...`
> runs instrument → build+up → verify → grammar → fuzz end to end, needing only Docker locally
> (no Python/.NET/Go install required). See [docs/CLI.md](docs/CLI.md). This runbook documents the
> manual, step-by-step path — both work identically underneath; use whichever fits.

---

## 1. Prerequisites

Install the following on any new system before running UpsideFuzz:

| Tool | Version | Purpose |
|------|---------|---------|
| **Docker** + **Docker Compose v2** | Docker 24+, Compose 2.x | Build & run instrumented containers (not needed for grammar compilation itself) |
| **Python** | 3.9+ | Run `fuzz-prep-multi.py` and `grammarc/` (stdlib-only, no `pip install` needed) |
| **.NET SDK** | 8+ | `analyzer/` — the Roslyn syntax-tree analyzer `compile-grammar.sh` runs when `--src` is given |
| **Go** (optional) | 1.22+ | Only if you build the Go fuzzer binary locally |
| **sqlpackage** (optional) | Microsoft build | Import `.bacpac` into SQL Server from the host for targets that require manual SQL Server restores |

```bash
# Verify tooling
docker --version        # Docker version 24+
docker compose version  # Docker Compose version v2+
python3 --version       # Python 3.9+
dotnet --version        # 8.0+
```

> **Note:** The Go fuzzer runs as a Docker container, so Go itself is NOT required on the host unless you build locally.

> **Apple Silicon / ARM hosts:** SQL Server in Docker is usually `linux/amd64` and often runs under emulation unless the target compose file pins that platform explicitly. Expect slower first-time pulls and DB startup on SQL Server-backed targets.

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
│  [App API]  ←─── SharpFuzz probes write to 256KB bitmap (default)     │
│  [DB/Cache] ←─── seeded & migrated at startup                          │
│                                                                         │
│  Coverage bitmap:                                                       │
│    file-backed mmap  →  /coverage_shm/bitmap  (tmpfs volume)           │
│    fallback heap     →  in-process only                                │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
              compile-grammar.sh swagger.json --src <src>
              (grammarc/ OpenAPI parser + analyzer/ Roslyn syntax-tree
               analysis — first-party, no RESTler, no Docker for this step)
                             │
                             ▼
┌────────────────────────────┐     ┌────────────────────────────────────┐
│  templates.export.json     │     │  dict.json                         │
│  • Request templates       │     │  • Domain-specific tokens          │
│  • Fuzzable/custom_payload │     │  • Enum values, IDs, strings       │
│  • Producer→Consumer deps  │     │  • From OpenAPI + real C# Roslyn   │
│    (written directly)      │     │    constraints (type/property-     │
│                             │     │    scoped, not global-name)        │
└────────────┬───────────────┘     └─────────────────────────────────── ┘
             │
    docker compose --profile fuzz-go run --rm void -grammar <grammar_dir>
             │
             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Void (Coverage-Guided)                                       │
│                                                                         │
│  Epochs: Baseline → Deterministic → Havoc → Splicing                   │
│  Reads bitmap via mmap (-direct-shm) or HTTP (/shm/coverage)           │
│  Logs crashes to JSONL, prints live TUI dashboard                       │
│  Adaptive concurrency, crash triage, PoC generation                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Step 1: Instrument the Project

```bash
python3 /path/to/upside-fuzzer/fuzz-prep-multi.py \
  --src <SOURCE_DIR> \
  --out <OUTPUT_DIR> \
  [--main <WEB_API_PROJECT_NAME>]
```

| Flag | Description |
|------|-------------|
| `--src` | Path to the .NET solution (source, NOT instrumented) |
| `--out` | Output directory for the instrumented copy |
| `--main` | Web API project name (required for multi-project solutions) |
| `--inject-mode` | `hook` (default, zero-edit) or `source` (legacy source editing). See below. |

### Injection mode (`--inject-mode`)

| Mode | What it does | When to use |
|------|--------------|-------------|
| `hook` *(default)* | **Zero-edit.** Generates a self-contained `UpsideFuzz.Coverage` assembly and wires it via `DOTNET_STARTUP_HOOKS` + `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`. The target's `Program.cs`/`Startup.cs`/`.csproj` are never modified. Coverage is linked at load time, including lazily/dynamically loaded modules (via an `AssemblyLoad` handler). Verify with `curl /shm/health`. | Almost always — most robust and universal. |
| `source` | **Legacy.** Injects `CoverageExtensions.cs` into the main project and edits `Program.cs`/`Startup.cs` to add the middleware/endpoints. | Only if you need the middleware *inside* the app's exception handler for maximal production-mode exception-type fidelity, or a target where startup hooks are disallowed. |

Both modes expose the identical `/shm/*` endpoints and `X-Coverage-Delta` header — every step after instrumentation is the same, with one exception: `/shm/cmplog` (CmpLog/RedQueen, Top-20+ #21 — see below) is hook-mode only.

### CmpLog: recovering hardcoded "magic value" checks (hook mode only)

Hook-mode builds also run a second, independent instrumentation pass that
records the literal operands of the target's own string/int comparisons
(`String.Equals`/`StartsWith`/`EndsWith`/`Contains`/`==`, and integer
literal-vs-compare sites) straight out of its IL — recovering hardcoded checks
like `if (code == "SUPER_SECRET_2026")` that no OpenAPI spec or dictionary could
ever guess. Nothing to configure: it runs automatically for hook-mode builds, and
the fuzzer polls it automatically (`-cmplog`, on by default — see §8 flag table).
Full mechanism in `ARCHITECTURE.md` §7 ("CmpLog/RedQueen via IL Comparison
Instrumentation").

New command (explicit, equivalent to the default):
```bash
python3 fuzz-prep-multi.py --src <SOURCE_DIR> --out <OUTPUT_DIR> --main <PROJECT> --inject-mode hook
```
Legacy behavior (previous releases):
```bash
python3 fuzz-prep-multi.py --src <SOURCE_DIR> --out <OUTPUT_DIR> --main <PROJECT> --inject-mode source
```

**Example:**
```bash
python3 fuzz-prep-multi.py \
  --src ./btcpayserver \
  --out ./btcpayserver_prep \
  --main BTCPayServer
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

4. **Copies** `instrumentor_src/Program.cs` — generic SharpFuzz instrumentor
5. **Generates** `instrumentor_src/namespaces.json` — discovered namespace allowlist configuration
6. **Generates** `Helpers/CoverageExtensions.cs` — SHM middleware + endpoints
7. **Adapts** original Dockerfile with 2 injected build stages:
   - `instrumentor-build` — compiles the SharpFuzz instrumentor tool and copies config
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
| `instrumentor_src/Program.cs` | **Copied file** — Generic SharpFuzz instrumentor |
| `instrumentor_src/namespaces.json` | **New file** — Discovered namespaces configuration |
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
# 1. Initialize SHM — allocates the shared bitmap (auto-sized from the real instrumented-type
#    count captured at build time, 256KB default/64KB min/8MB max — see Top-20 #17), syncs SharpFuzz across all DLLs
curl -s -X POST http://localhost:<PORT>/shm/create
# → {"status":"synced","mode":"file-backed-mmap","bitmap_size":262144,...}

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

### Self-verifying, fail-closed startup check (Top-20 #4)

You don't have to run the checks above manually before every session — the Go
fuzzer does an equivalent check automatically at startup, right after loading
templates: it sends a few real unmutated warm-up requests and refuses to start
if the coverage bitmap doesn't gain any new edges (even if `/shm/health`
reports `shm_bound: true` — a target can be reachable and report app
assemblies loaded while still never having been actually IL-rewritten). You'll
see this in the fuzzer's own startup output:

```
Coverage health: shm_bound=true mode=file-backed-mmap app_assemblies=[Api Core]
Coverage health OK: warm-up probe (3 request(s)) produced 10 new edge(s)
```

If it instead exits with `run failed: coverage instrumentation degraded: ...`,
work through the manual checks above rather than passing
`-allow-degraded-coverage` — a run that overrides this will complete but find
nothing, since the coverage feedback loop the whole scheduler depends on is
broken.

---

## 6. Step 4: Compile the Grammar

The grammar describes every API request shape — method, path, headers, body — as typed, fuzzable templates.

```bash
cd /path/to/upside-fuzzer

# Download swagger from running instrumented app
curl -s http://localhost:<PORT>/swagger/v1/swagger.json -o swagger.json

# Compile grammar (with Roslyn source-aware enhancement) — writes directly to grammars/<project>/
./compile-grammar.sh swagger.json --src <SOURCE_DIR> --out grammars/<project>

# Or with a custom dictionary for domain-specific values:
./compile-grammar.sh swagger.json --dict custom-dict.json --src <SOURCE_DIR> --out grammars/<project>
```

That's the whole step — `templates.export.json` and `dict.json` land directly in
`grammars/<project>/`, no manual `cp`, no separate export step, no Docker.

> **Swagger tip:** If a target exposes both a public swagger and a fuzz-specific/internal OpenAPI document, prefer the richer spec as long as it still matches the running API surface you fuzz.

### What `compile-grammar.sh` does

RESTler has been retired (Top-20 #9/#10 — see `ARCHITECTURE_REVIEW.md`). The pipeline is
now two first-party components, with **no Docker or external compiler involved**:

1. **`grammarc/`** (Python, stdlib-only) parses the OpenAPI spec directly ($ref/allOf/oneOf/anyOf
   resolution, v2+v3 parameter/body shapes), infers producer/consumer id relationships by
   path/name convention, synthesizes boundary values, and serializes request bodies straight
   to segments.
2. **`analyzer/`** (C#, real `Microsoft.CodeAnalysis.CSharp` syntax-tree parsing — not regex),
   run automatically when `--src` is given, extracts **type/property-scoped** constraints:
   `[Required]`, `[Range]`, `[StringLength]`, `[RegularExpression]`, FluentValidation chains,
   enum declarations, `[Authorize]`/route metadata. Scoped by `(fully-qualified type, property)`
   — not a global property name, which is what the old regex-based `enhance-grammar.py`
   used and which could cross-contaminate unrelated DTOs that happen to share a field name
   (verified on eShopOnWeb: two unrelated classes both named `CreateCatalogItemRequest`).
3. `grammarc/roslyn_merge.py` merges the two, Roslyn winning per-field on a scoped match, and
   emits `templates.export.json` + `dict.json` directly to `--out`.
4. Multipart form-data endpoints get autogenerated seed templates the same way.

### Grammar folder and template export for Void

The Go fuzzer (Void) loads **`templates.export.json`** + **`dict.json`** directly from the
directory passed via `-grammar` — `compile-grammar.sh` writes both there already, no
extra export step needed for grammars generated by the current pipeline.

`void/export-templates.py` (an old `grammar.py` → JSON converter) still exists as a
**legacy fallback** for grammar directories generated before this migration and not yet
regenerated: `void/go/template.go`'s `exportTemplates()` invokes it automatically at Void
startup only if `templates.export.json` is missing but a `grammar.py` is present. If you
regenerate with the current `compile-grammar.sh`, you'll never hit this path. If you do
see `exec: "python3": executable file not found in $PATH` against an old grammar
directory, either regenerate it with `compile-grammar.sh` (recommended — removes the
dependency entirely) or rebuild `void/Dockerfile.go`, which still bundles `python3` for
this fallback.

You may mount any folder holding `templates.export.json`/`dict.json` as `/grammar` in
Compose (e.g. `../grammars/bitwarden:/grammar:ro`).

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
cd /path/to/upside-fuzzer/void/go

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

### Authentication: JWT, API keys, custom headers, and cookies

For serious access-control fuzzing, prefer a documented auth identity file passed with `-auth-file` or `AUTH_FILE`. The file can hold multiple JWT, API-key, cookie, or arbitrary-header identities and is parsed once at startup.

See **[`docs/FUZZER_AUTHENTICATION.md`](docs/FUZZER_AUTHENTICATION.md)** and **[`docs/auth.identities.example.json`](docs/auth.identities.example.json)**.

| Mechanism | Meaning |
|-----------|---------|
| **`-auth-file ./auth.identities.json`** | Recommended multi-identity file for JWT/API-key/cookie/header auth. |
| **`AUTH_FILE=./auth.identities.json`** | Environment-variable equivalent of `-auth-file`. |
| **`AUTH_TOKEN`** | Raw JWT recommended: Void sets `Authorization: Bearer <AUTH_TOKEN>`. If you paste `Bearer ...`, Void strips that prefix. |
| **`AUTH_HEADERS_JSON`** | JSON object of header name → value, e.g. `{"Authorization":"Bearer eyJ...","X-Custom":"v"}`. Header values are sent as written (include `Bearer ` inside `Authorization` if you use this path). |
| **`AUTH_HEADER`** | Legacy single header shortcut in `Header-Name: value` format. Prefer `AUTH_HEADERS_JSON` or `-auth-file` for new runs. |
| **`AUTH_COOKIE`** | Optional `Cookie` header value for cookie-based sessions. |
| **`AUTH_URL`**, **`AUTH_METHOD`**, **`AUTH_BODY`**, **`AUTH_CONTENT_TYPE`**, **`AUTH_TOKEN_FIELD`** | If no token/headers/cookie are pre-set, Void can perform one login request against `TARGET_HOST` and parse a token (defaults in code: `POST` `/api/authenticate`, JSON field `token`). See `void/go/auth.go`. |
| **`AUTH_IDENTITIES_JSON`** | Backward-compatible inline multi-identity JSON. Prefer `-auth-file` for new runs. |

Examples:

```bash
docker compose --profile fuzz-go run --rm void \
  -auth-file ./auth.identities.json \
  -multi-identity=true \
  -identity-mode weighted
```

```bash
export AUTH_TOKEN='eyJhbGciOi...'
docker compose --profile fuzz-go run --rm void
```

```bash
export AUTH_HEADERS_JSON='{"Authorization":"Bearer eyJhbGciOi...","X-Api-Key":"secret"}'
docker compose --profile fuzz-go run --rm void
```

### Void without Docker Compose (`docker run`)

You can run the fuzzer container with plain `docker run` as long as (1) the **target stack is already up**, (2) the container joins the **same Docker network** as the API (so `http://api:8080` or your service hostname resolves), and (3) the **same `coverage_shm` volume** is mounted at the path Void uses (`-shm-path`, e.g. `/coverage_shm/bitmap`) **and** is attached to the instrumented API the same way as in Compose.

```bash
REPO=/absolute/path/to/upside-fuzzer

docker run --rm -it \
  --network mytarget_default \
  -e TARGET_HOST=http://api:8080 \
  -e SHM_HOST=http://api:8080 \
  -e AUTH_TOKEN='eyJhbGciOi...' \
  -v mytarget_coverage_shm:/coverage_shm \
  -v "$REPO/void:/fuzzer" \
  -v "$REPO/grammars/my-target:/grammar:ro" \
  -v "$REPO/my-target/src:/src:ro" \
  void-fuzzer:latest \
  -grammar /grammar -templates-json /grammar/templates.export.json \
  -direct-shm -shm-path /coverage_shm/bitmap -coverage-bitmap-size 1048576 -shm-read-mode file \
  -time-budget 7 -concurrency 16 -adaptive-concurrency -coverage-interval 4 \
  -sequence-prob 0.35 -sequence-max-depth 4 -sequence-fanout 8 \
  -src /src
```

Replace `mytarget_default`, `mytarget_coverage_shm`, `http://api:8080`, and `void-fuzzer:latest` with the names your Compose project actually uses (`docker compose ls`, `docker volume ls`, `docker compose images`). If you use `docker compose -p myproj`, prefixes become `myproj_*`.

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
| Multi-identity scheduling | ON | `-multi-identity=false`; configure identities with `-auth-file` |

> **Note on Crash Triage:** The `-crash-triage` feature (enabled by default) now detects the `crash_layer` (e.g., `model_binding`, `deserialization`, `controller`). Crashes that happen pre-authentication (like JSON parse errors) are automatically penalized in score and capped at `needs_review` severity, preventing noise from trivial 400-level-masked-as-500 errors.

### Flags worth tuning

| Flag | Default | When to change |
|------|---------|----------------|
| `-time-budget` | `10` min | Increase for thorough scan (60–120 min) |
| `-concurrency` | `10` | Increase for fast targets (32–64) |
| `-max-concurrency` | `64` | Upper bound for adaptive mode |
| `-request-timeout` | `5.0` s | Lower for fast targets (2.5), raise for slow ones |
| `-direct-shm` | `false` | Set `true` in Docker sidecar mode |
| `-auth-file` | empty | Use for JWT/API-key/cookie multi-identity access-control fuzzing |
| `-sequence-prob` | `0.30` | Raise to 0.5–0.6 for stateful API testing |
| `-sequence-max-depth` | `3` | Raise to 5–6 for deep workflows |
| `-sequence-fanout` | `6` | Raise to 8–10 for wide API surface |
| `-skip-endpoint-on-500` | `false` | Set `true` when 500s are expected (misconfigured infra) |
| `-coverage-interval` | `1` | Raise to 5–10 for throughput benchmarking |
| `-cmplog` | `true` | Set `false` to skip polling `/shm/cmplog` (no effect against a target instrumented without `--cmplog`, or in `--inject-mode source`) |
| `-cmplog-interval` | `3.0` s | Raise on very high-latency targets to cut poll overhead |

### Security flag interactions

Some options look like duplicates because they work at different scopes:

| Flags | Difference | When to use |
|-------|------------|-------------|
| `-skip-on-crash` vs `-skip-endpoint-on-500` | `-skip-on-crash` removes only the crashing template after any 5xx. `-skip-endpoint-on-500` blocks every template for that endpoint after the first HTTP 500. | Use both for noisy targets where breadth matters more than repeatedly exploring one broken route. |
| `-repro-runs` vs `-crash-replay-count` | Repro runs verify a finding for the report. Crash replay schedules more fuzzing near a crash to discover variants. | Keep repro for report quality. Set `-crash-replay-count 0` when you want strict no-revisit behavior. |
| `-crash-boost-*` vs `-crash-replay-*` | Crash boost temporarily raises the endpoint's scheduler weight. Crash replay queues concrete follow-up items. | Keep enabled for exploitability/depth; disable both for broad scans on very crashy targets. |
| `-endpoint-stall-reqs`, `-endpoint-zero-edge-reqs`, `-endpoint-req-share-cap-pct` | All reduce wasted requests, but at different levels: local stall, total zero-edge endpoint, and global request share. | Leave defaults unless one endpoint monopolizes the run or coverage goes flat. |
| `-race-mode` and sequence flags | Sequences build stateful chains; race mode bursts conflicting writes found during those chains. | Keep both for business-logic and authz testing. Reduce them for pure throughput benchmarks. |

### Security campaign profiles

> **Shortcut:** `-profile security` sets the multi-identity + oracle + source-aware bundle below automatically (any explicit flag you add still overrides it). The vulnerability oracles (`-access-probe`, `-injection-oracle`) are **on by default** and are what turn IDOR / broken-auth / mass-assignment / injection into `likely_vuln` findings rather than just 500s — pair them with a real `-auth-file` for cross-identity BOLA detection.

Access-control / authz campaign for IDOR, tenant isolation, missing role checks, guest-auth bypasses:

```bash
docker compose --profile fuzz-go run --rm void \
  -grammar /path/to/grammar \
  -profile security \
  -auth-file ./auth.identities.json \
  -access-probe=true -access-probe-prob 0.75 \
  -sequence-max-depth 5 \
  -sequence-fanout 8 \
  -skip-on-crash \
  -skip-endpoint-on-500 \
  -repro-runs 3 \
  -time-budget 30
```

The cross-identity replay is only as strong as your `-auth-file`: provide at least two real identities (plus the auto guest) so BOLA probes have distinct principals to compare. Findings appear with `access_control: true` and `origin_identity` → `shadow_identity`; mass-assignment findings carry `mass_assignment_privileged_field_accepted`.

Each oracle can be toggled independently under the `-access-probe` master switch: `-probe-bola`, `-probe-auth-bypass`, `-probe-mass-assign`, `-probe-differential`. The auth-bypass probe is self-limiting — it **only** fires on endpoints already observed rejecting unauthenticated access (401/403), so it never flags genuinely public endpoints. Including the auto guest identity (`-identity-include-guest`, on in the `security` profile) helps it learn which endpoints enforce auth faster and raises auth-bypass findings to `likely_vuln_high`.

`-probe-differential` (Top-20 #18) goes a step further: on endpoints with *strong* evidence of auth enforcement, it replays 4 confusion variants with no credentials — a GET reissued as HEAD, the same JSON body declared as `text/plain`, a path with segment casing flipped, and the path-embedded resource id duplicated as a query parameter. Because the plain unauthenticated replay on that same endpoint already failed (that's the precondition), a 2xx on one of these variants means the confusion technique itself — not general laxness — let the request through; findings carry `differential_auth_bypass:<technique>` and a `technique` field (`verb`/`content-type`/`route-case`/`param-location`) in `triage`.

For very noisy targets where you do not want to revisit crash areas, add:

```bash
-crash-replay-count 0 -crash-boost-requests 0
```

Broad discovery campaign for coverage growth and many unique endpoints before deep triage:

```bash
docker compose --profile fuzz-go run --rm void \
  -grammar /path/to/grammar \
  -direct-shm \
  -coverage-interval 4 \
  -concurrency 32 \
  -max-concurrency 96 \
  -sequence-prob 0.35 \
  -skip-on-crash \
  -crash-replay-count 0 \
  -crash-boost-requests 0 \
  -repro-runs 1 \
  -time-budget 60
```

Report-quality triage campaign for cleaner PoCs and stable findings:

```bash
docker compose --profile fuzz-go run --rm void \
  -grammar /path/to/grammar \
  -auth-file ./auth.identities.json \
  -identity-mode weighted \
  -concurrency 8 \
  -request-timeout 5 \
  -crash-triage=true \
  -repro-runs 5 \
  -repro-target 80 \
  -minimize-crash=true \
  -minimize-max-probes 24 \
  -crash-replay-count 0 \
  -time-budget 20
```

### Fast-scan profile (CI — maximize throughput, skip slow analysis)

> **Shortcut:** `-profile fast` disables repro/minimize and the oracles for you. The command below adds the throughput-specific tuning on top.

```bash
docker compose --profile fuzz-go run --rm void \
  -grammar /path/to/grammar \
  -profile fast \
  -direct-shm \
  -time-budget 20 \
  -concurrency 64 -max-concurrency 128 \
  -request-timeout 2.5 -coverage-interval 6 \
  -crash-triage=false \
  -crash-replay-count 0 -crash-boost-requests 0 \
  -no-ui
```

### Full flag reference

See [`void/README.md`](void/README.md) for the complete CLI table with defaults taken from source.

### Build for any platform

See [`void/README.md §Build`](void/README.md#build-for-any-platform) for cross-compilation and Docker buildx instructions.

---

## 9. Real-World Examples

The generic runbook above is the maintained source of truth for instrumentation, grammar generation, auth configuration, SHM wiring, and fuzzer flags. For target-specific setup details, use the current quickstarts that are checked into this repository:

### Bitwarden

See [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md).

Use this target when you want a realistic multi-service API with MSSQL, identity flows, strict validation, and multi-user access-control fuzzing. The quickstart covers JWT acquisition, `auth.identities.json`, and test-data population for cross-identity findings.

### BTCPayServer

See [QUICKSTART_BTCPAYSERVER.md](QUICKSTART_BTCPAYSERVER.md).

Use this target when you want API-key-driven auth and a more complex service graph around the Greenfield API. The quickstart covers API-key generation, Swagger cleanup, and grammar/template export.

### eShopOnWeb

See [QUICKSTART_ESHOP.md](QUICKSTART_ESHOP.md).

Use this target as the smallest end-to-end sample in the repo. It is a good sanity check for instrumentation, SHM coverage, and grammar generation on a straightforward REST API.

### SimplCommerce

See [QUICKSTART_SIMPLCOMMERCE.md](QUICKSTART_SIMPLCOMMERCE.md).

Use this target when you want anti-forgery tokens, cookie-based auth, and a modular monolith with more framework surface area than eShopOnWeb.

### Which quickstart to pick first

- Choose `eShopOnWeb` for the fastest “is my pipeline wired correctly?” verification.
- Choose `Bitwarden` for authz, multi-identity, and deeper business-logic coverage.
- Choose `BTCPayServer` for API-key auth and a larger service graph.
- Choose `SimplCommerce` for cookie auth and anti-forgery-heavy MVC behavior.

---

## 10. Custom Dictionary Format

The `--dict` flag to `compile-grammar.sh` accepts a JSON file that provides domain-specific values to seed the fuzzer's mutation engine. `grammarc/emit_dict.py` writes (and `void/go/store.go` reads) a simple **flat map**: each key is a request field/payload name, each value an array of candidate strings.

### Structure (recommended — what `grammarc` itself emits)

```json
{
  "currencyCode": ["USD", "EUR", "GBP", "JPY"],
  "countryId": ["US", "DE", "GB", "FR"],
  "userId": ["usr-001", "usr-002"],
  "amount": ["0", "1", "100", "99999.99", "-1"]
}
```

Keys are matched to request field/payload names case-insensitively with canonical
normalization (`void/go/store.go::candidatesForKey`) — `currencyCode`, `currency_code`,
and `CurrencyCode` all resolve to the same pool.

### Legacy nested containers (still supported, not required)

For backward compatibility, `void/go/store.go` also special-cases exactly four
RESTler-era nested container names if you hand-write a dictionary using them:

| Key | Description |
|-----|-------------|
| `restler_custom_payload` | Exact string values (quoted in JSON body) |
| `restler_custom_payload_unquoted` | Unquoted values (numbers, booleans) |
| `restler_custom_payload_query` | Values for URL query parameters |
| `restler_custom_payload_header` | Values for HTTP headers |

```json
{
  "restler_custom_payload": {
    "currencyCode": ["USD", "EUR", "GBP", "JPY"]
  }
}
```

`grammarc` never emits this nested shape itself (flat keys are simpler and match the
same lookup path) — but if you pass `--dict` pointing at an old dictionary that uses it,
`grammarc/emit_dict.py::merge_external_dict` flattens it into top-level keys automatically,
so either format works as `--dict` input.

### Tips

- Keys are normalized: `userId`, `user_id`, `UserId`, `user-id` all match the same canonical key.
- Values containing `{{`, `${`, `#{}` are filtered out by the runtime store to avoid injection feedback loops.
- Nested `dictionaries:` wrapper is supported (backward compat with old format).
- **Two paths reach the same pool now.** A field's boundary values land in `dict.json`
  (via `grammarc/boundary.py`) *and*, since Top-20 #14, directly on the segment itself
  (`min_length`/`max_length`/`minimum`/`maximum`/`pattern`/`enum_values` in
  `templates.export.json`) — the mutation engine (`mutation_engine.go`) consults the
  segment's own constraints first for boundary-value candidates, blended additively into
  its existing generic mutation pool; `dict.json` remains the channel for
  runtime-harvested/correlated values and anything from a custom `--dict`. You don't need
  to choose between them — both are populated automatically by `compile-grammar.sh`.
- **400-body responses feed the dictionary too, automatically** (Top-20 #11,
  "CMPLOG-lite"). If a target's validation-error responses follow ASP.NET's standard
  `{"errors":{"Field":["msg"]}}` shape, or a message contains phrasing like `"must be one
  of [...]"`, the engine mines field names/candidate values out of them at runtime and
  feeds them into the same value pool `pickCustomPayloadValue` draws from — no
  configuration needed, this happens for every 4xx response the fuzzer sees.

---

## 10a. Running the E2E regression check locally

Before trusting a change to `grammarc/`, `analyzer/`, or the mutation engine, run the
same check CI runs (`.github/workflows/e2e.yml`) against the bundled planted-bug fixture
(`fixtures/planted-bug-api/`, see its own README.md for what's planted and why):

```bash
./scripts/e2e-test.sh
```

This instruments the fixture, brings up the container, runs `verify-hook.sh`, compiles
the grammar, runs a short live fuzz session, and asserts both that real coverage was
recorded (`coverage_end_edges > 0`) and that the planted bug (a `GET /items?pageSize=`
`ArgumentOutOfRangeException` → 500) was actually detected — not just that every step
exited zero. Takes about 2–3 minutes end to end (Docker build + a 1-minute fuzz run);
tears down its own containers on exit regardless of pass/fail.

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
-time-budget 20
-concurrency 12
-request-timeout 2.5
-sequence-prob 0.55
-sequence-max-depth 5
-sequence-fanout 8
```

**For slow / unstable APIs:**
```bash
-concurrency 6
-request-timeout 5
-sequence-fanout 4
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
| Coverage is flat after warmup | All endpoints exhausted or API too slow | Increase `-sequence-prob`, reduce `-concurrency` |
| Fuzzer exits immediately | Malformed `templates.export.json`/`dict.json` | Regenerate with `compile-grammar.sh` (check its console output for `skipped=N > 0`); validate JSON with `python3 -m json.tool grammars/<project>/templates.export.json > /dev/null` |
| `exec: "python3": executable file not found` inside Void | Only hit against a **pre-migration** grammar directory (has `grammar.py`, no `templates.export.json`) — Void's legacy `export-templates.py` fallback needs `python3` | Regenerate the grammar with the current `compile-grammar.sh` (removes the dependency entirely — the primary path never calls `export-templates.py`), or rebuild `void/Dockerfile.go`, which still bundles `python3` for this fallback |
| Void exits at startup (templates JSON missing / load error) | `-grammar`/`-templates-json` points at a directory without `templates.export.json` | Re-run `compile-grammar.sh <swagger> --out <that directory>`; it writes `templates.export.json` there directly — no separate export step needed |

---

**→ [Back to README](README.md) · [Architecture](ARCHITECTURE.md) · [Authentication](docs/FUZZER_AUTHENTICATION.md) · [Go Fuzzer Reference](void/README.md)**
