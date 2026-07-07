# UpsideFuzz — Coverage-Guided REST API Fuzzer for .NET

> **Automated black-box → grey-box fuzzing for any .NET 8+ web API.**  
> Transforms a standard .NET solution into a coverage-instrumented fuzzing target, then drives it with a Go-based grammar-fed fuzzer with real-time SHM feedback.

---

## How It Works / End-to-End Flow Diagram

```mermaid
graph TD
    %% Define Styles
    classDef dotNet fill:#512bd4,stroke:#fff,stroke-width:2px,color:#fff;
    classDef python fill:#ffd43b,stroke:#306998,stroke-width:2px,color:#000;
    classDef go fill:#00add8,stroke:#000,stroke-width:2px,color:#fff;
    classDef output fill:#e8e8e8,stroke:#333,stroke-width:2px,color:#333;
    classDef bash fill:#4EAA25,stroke:#fff,stroke-width:2px,color:#fff;

    A[".NET Source + Dockerfile"]:::dotNet -->|fuzz-prep-multi.py| B
    B["Instrumented Copy (/shm added)"]:::dotNet -->|docker compose up| C
    
    swagger["swagger.json"]:::output -->|compile-grammar.sh| E
    
    C[("Running API + Live SHM Coverage")]:::output
    E["grammar.py + dict.json"]:::python
    
    E -->|deploy-grammar.sh| F
    C -->|Feedback Loop| F
    
    F{"void Fuzzer Engine (Go)"}:::go
    F -->|Requests + Mutations| C
    
    F -->|Outputs| G["unique-crashes.jsonl + Reproducers"]:::output
```

### High-level pipeline:

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
  void             ← coverage-guided fuzzing: epoch scheduling, adaptive
       │                        concurrency, MOpt mutations, stateful sequences
  crashes/unique-crashes.jsonl
```

---

## Quickstarts

Check out our step-by-step guides for instrumenting and fuzzing real-world applications from scratch:

- [eShopOnWeb Quickstart](QUICKSTART_ESHOP.md) (Standard REST API, basic setup)
- [SimplCommerce Quickstart](QUICKSTART_SIMPLCOMMERCE.md) (Modular Monolith, Anti-forgery + Identity Auth injection)

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
├── sanitize-swagger-for-restler.sh  Fix deepObject/nested params before RESTler
│
├── void/
│   ├── go/
│   │   ├── main.go             CLI flags and app bootstrap
│   │   ├── fuzzer.go           Main lifecycle hooks and epoch scheduling
│   │   ├── worker.go           Core HTTP fuzzing loop and coverage tracking
│   │   ├── coverage.go         SHM bitmap parsing and HTTP coverage reader
│   │   ├── sequence.go         Stateful producer/consumer chains
│   │   ├── store.go            Knowledge extraction, ID harvesting, and dedup
│   │   ├── template.go         RESTler grammar parsing and payload rendering
│   │   ├── mutation_engine.go  MOpt-style mutation scheduler and weights
│   │   ├── mutations.go        MOpt payload mutation categories
│   │   ├── crash.go            Triage, dedup, minimization, and PoC generation
│   │   ├── auth.go             JWT extraction and authentication state
│   │   ├── ui.go               Live terminal dashboard
│   │   ├── utils.go            HTTP and string utility functions
│   │   ├── types.go            Core data structures
│   │   └── advanced_features_compat.go Race condition probing, multi-identity
│   ├── export-templates.py     RESTler grammar.py → JSON templates
│   └── Dockerfile.go           Docker image for Go sidecar
│
├── instrumentor/               SharpFuzz instrumentor (C# tool)
│   ├── Program.cs
│   ├── instrument.sh
│   └── instrumentor.csproj
│
├── requirements.txt            Python dependencies
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
```

### 5. Run the fuzzer

**Docker sidecar mode** (recommended — direct SHM, fastest coverage):

```bash
export AUTH_TOKEN="<your-jwt-token>"
docker compose --profile fuzz-go run --rm void \
  -grammar restler_output/Compile \
  -direct-shm -time-budget 60
```

**Host mode** (API running natively, coverage via HTTP):

```bash
export TARGET_HOST="http://localhost:8080"
export AUTH_TOKEN="<your-jwt-token>"
./void/go/void -grammar restler_output/Compile -time-budget 60
```

### 6. Monitor crashes

```bash
# Live unique crashes
tail -f void/crashes/unique-crashes-*.jsonl

# Pretty-print
cat void/crashes/unique-crashes-*.jsonl | \
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

Full reference: `./void/go/void --help` or [void/README.md](void/README.md)

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
- **[void/README.md](void/README.md)** — Go fuzzer: all 60+ flags with defaults, build for any platform, cross-compilation guide
