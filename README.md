# UpsideFuzz — Coverage-Guided REST API Fuzzer for .NET

> **Automated black-box → grey-box fuzzing for any .NET 8+ web API.**  
> Transforms a standard .NET solution into a coverage-instrumented fuzzing target, then drives it with a Go-based grammar-fed fuzzer with real-time SHM feedback.

---

## How It Works

```
.NET Source + Dockerfile
       │
  fuzz-prep-multi.py        ← copies project, injects SharpFuzz probes into all DLLs,
       │                       adds /shm/create + /shm/coverage endpoints, adapts compose
  Instrumented Copy
       │
  docker compose build && docker compose up -d
       │
  Running API with live SHM coverage bitmap
       │
  compile-grammar.sh swagger.json [--dict dict.json] [--src ./src]
       │                             ← sanitizes swagger, runs RESTler compiler,
  grammar.py + dict.json               enhances with OpenAPI enums + C# constraints
       │
  smartfuzzer-go             ← coverage-guided fuzzing: epoch scheduling, adaptive
       │                        concurrency, MOpt mutations, stateful sequences
  crashes/unique-crashes.jsonl
```

---

## Features

| Category | What it does |
|----------|-------------|
| **Instrumentation** | Multi-project .NET solution support — instruments all business-logic DLLs, skips tests/migrations/generated code |
| **Coverage** | 256KB SHM bitmap shared across all DLLs via reflection — file-backed mmap, zero HTTP overhead in Docker sidecar mode |
| **Grammar** | OpenAPI → RESTler grammar → enhanced with enums, format constraints, C# `[Range]`/`[StringLength]`/FluentValidation, multipart |
| **Fuzzing** | Go engine: Baseline → Deterministic → Havoc → Splicing epochs, MOpt-style weighted mutation categories |
| **Sequences** | Producer→consumer chains (POST→GET→PUT→DELETE), runtime value extraction, configurable fanout |
| **Bug finding** | Crash triage, repro verification, payload minimization, PoC generation, race condition probing, multi-identity auth |
| **Auth** | JWT env var, multi-identity scheduling, anti-forgery token harvesting |

---

## Repository Structure

```
.
├── fuzz-prep-multi.py          Instrument a .NET project for fuzzing
├── compile-grammar.sh          swagger.json → RESTler grammar → enhanced dict
├── enhance-grammar.py          Grammar/dict enricher (called by compile-grammar.sh)
├── sanitize-swagger-for-restler.sh  Fix deepObject/nested params before RESTler
├── deploy-grammar.sh           Copy compiled grammar into smart_fuzzer/
├── run-smart-fuzzer.sh         Quick launcher (host mode, HTTP coverage)
├── run-fuzzer-docker.sh        Launcher for Docker compose sidecar mode
│
├── smart_fuzzer/
│   ├── go/
│   │   ├── main.go             Fuzzer engine: scheduler, mutations, SHM, TUI
│   │   ├── advanced_features.go  Crash triage, minimization, race probing
│   │   └── go.mod
│   ├── export-templates.py     RESTler grammar.py → JSON templates
│   └── Dockerfile.go           Docker image for Go sidecar
│
├── instrumentor/               SharpFuzz instrumentor (C# tool)
│   ├── Program.cs
│   ├── instrument.sh
│   └── instrumentor.csproj
│
├── fuzz-cases-multi.json       Business logic detection config
├── requirements.txt            Python dependencies
├── nuget.config
├── INSTRUCTIONS.md             Step-by-step runbook (new system → fuzzing)
└── ARCHITECTURE.md             Platform internals, diagrams, design decisions
```

> **`restler_bin/` is not included** — `compile-grammar.sh` downloads it automatically from Docker on first run (`mcr.microsoft.com/restlerfuzzer/restler`).  
> **`grammars/` is not included** — generated per-project by `compile-grammar.sh`.

---

## Quick Start

### 1. Prerequisites

```bash
# Required
docker --version        # Docker 24+
docker compose version  # Compose v2+
dotnet --version        # .NET 8+
python3 --version       # 3.10+

pip install -r requirements.txt
```

### 2. Instrument your .NET project

```bash
python3 fuzz-prep-multi.py \
  --src ./my-project \
  --out ./my-project-fuzz \
  --main MyProject.Api        # name of the web API project

cd my-project-fuzz
docker compose build && docker compose up -d
sleep 45  # wait for DB migration + startup
```

### 3. Verify instrumentation

```bash
curl -X POST http://localhost:8080/shm/create
curl http://localhost:8080/shm/coverage  # → {"edges":N,"hits":N}
```

### 4. Compile grammar from Swagger

```bash
cd ..
curl -s http://localhost:8080/swagger/v1/swagger.json -o swagger.json

./compile-grammar.sh swagger.json \
  --dict my-domain-dict.json \   # optional: domain-specific values
  --src ./my-project             # optional: C# source for constraint extraction

./deploy-grammar.sh              # copies grammar.py + dict.json → smart_fuzzer/
```

### 5. Run the fuzzer

**Docker sidecar mode** (recommended — direct SHM, fastest coverage):

```bash
export AUTH_TOKEN="<your-jwt-token>"
docker compose --profile fuzz-go run --rm smartfuzzer-go \
  -direct-shm -time-budget 60
```

**Host mode** (API running natively, coverage via HTTP):

```bash
export TARGET_HOST="http://localhost:8080"
export AUTH_TOKEN="<your-jwt-token>"
./run-smart-fuzzer.sh -time-budget 60
```

### 6. Monitor crashes

```bash
# Live unique crashes
tail -f smart_fuzzer/crashes/unique-crashes-*.jsonl

# Pretty-print
cat smart_fuzzer/crashes/unique-crashes-*.jsonl | \
  python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin]"
```

---

## Fuzzer Key Flags

All bug-finding features are **on by default**. You only need flags to tune or disable:

| Flag | Default | Notes |
|------|---------|-------|
| `-direct-shm` | `false` | Enable in Docker sidecar mode |
| `-time-budget` | `10` min | Set 60–120 for thorough scans |
| `-concurrency` | `10` | Raise to 32–64 for fast APIs |
| `-sequence-prob` | `0.30` | Raise to 0.5 for stateful APIs |
| `-skip-endpoint-on-500` | `false` | Set `true` if infra returns known 500s |
| `-crash-triage=false` | — | Disable for max throughput in CI |
| `-repro-runs 0` | — | Skip repro verification |

Full reference: `./smart_fuzzer/go/smartfuzzergo --help` or [smart_fuzzer/README.md](smart_fuzzer/README.md)

---

## Crash Output Format

Each unique crash in `unique-crashes-*.jsonl`:

```json
{
  "signature": "7ecd321e718f5a26",
  "status_code": 500,
  "method": "PUT",
  "path": "/v1/resource/0",
  "mutation": "sqli",
  "triage": {"classification": "needs_review", "severity_score": 5},
  "repro": {"stable_reproducible": true, "stability_pct": "100.0"},
  "minimized": {"path": "/v1/resource/0", "payload": ""},
  "poc_file": "./crashes/pocs/poc-7ecd321e.sh"
}
```

---

## Documentation

- **[INSTRUCTIONS.md](INSTRUCTIONS.md)** — Full step-by-step runbook: prerequisites, instrumentation, grammar generation, all run profiles, CLI reference, dictionary format, quality gates, troubleshooting
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Platform internals: SHM design, instrumentation pipeline, Go fuzzer components, epoch scheduling, mutation engine
- **[smart_fuzzer/README.md](smart_fuzzer/README.md)** — Go fuzzer: all 60+ flags with defaults, build for any platform, cross-compilation guide
