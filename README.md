# UpsideFuzz: .NET Coverage-Guided Fuzzing Platform

**Automated, coverage-guided fuzzing for any .NET 8+ web API.**

UpsideFuzz transforms a standard .NET solution into a fuzzing target by instrumenting compiled DLLs with SharpFuzz probes and providing real-time coverage feedback through shared memory. A Go-based fuzzer drives the attack using grammar-derived request templates, adaptive concurrency, and structured epoch scheduling.

Successfully used on: **mpt-helpdesk**, **mpt-currency**, **nopCommerce**, eShopOnWeb, CustomerLoyalty.

---

## Documentation

| Document | Description |
|----------|-------------|
| [INSTRUCTIONS.md](INSTRUCTIONS.md) | **Complete runbook** — prerequisites, all steps, examples for every project, CLI reference, dictionary format, quality gates, troubleshooting |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Platform internals — instrumentation pipeline, SHM design, Go fuzzer components, mutation engine, epoch architecture |

---

## Key Features

- **Multi-Project Solution Support** — discovers all projects, instruments business logic across all DLLs
- **Dockerfile Reuse** — adapts the project's existing Dockerfile and compose instead of generating new ones
- **Smart Exclusions** — skips test projects, entry-point code, EF migrations, generated types
- **Business Logic Detection** — Controllers, Services, Repositories, CQRS/MediatR Handlers, DDD aggregates, FastEndpoints
- **Real-time Coverage via SHM** — 64KB bitmap linked across all DLLs via reflection; file-backed mmap for zero-overhead reads
- **Coverage-Guided Fuzzer (Go)** — epoch-based scheduling (Baseline → Deterministic → Havoc → Splicing), adaptive concurrency, MOpt-style mutation categories
- **Deep State Exploration** — producer→consumer dependency chains, runtime value extraction, sequence fanout
- **Crash Triage** — repro, crash minimization, PoC generation, race condition probing, multi-identity auth testing

---

## How It Works (Condensed)

```
.NET Source + Dockerfile
       │
  fuzz-prep-multi.py   ← analyzes, copies, instruments
       │
  Instrumented Copy
  (4-stage Dockerfile, SHM volumes, CoverageExtensions.cs)
       │
  docker compose build && docker compose up -d
       │
  Running API + /shm/create + /shm/coverage endpoints
       │
  compile-grammar.sh swagger.json --src ./src
       │
  grammar.py + dict.json   ← typed request templates + domain tokens
       │
  smartfuzzer-go           ← coverage-guided fuzzing, crash JSONL
```

---

## Project Structure

```
├── fuzz-prep-multi.py          Main tool: analyze, instrument, adapt configs
├── compile-grammar.sh          Compile swagger.json → RESTler grammar
├── enhance-grammar.py          Enrich grammar/dict from OpenAPI + C# source
├── deploy-grammar.sh           Deploy grammar to smart_fuzzer/
├── prepare-nopcommerce.sh      Bootstrap nopCommerce end-to-end
│
├── INSTRUCTIONS.md             Complete runbook
├── ARCHITECTURE.md             Platform internals and diagrams
│
├── smart_fuzzer/
│   ├── go/
│   │   ├── main.go             Go fuzzer engine
│   │   ├── advanced_features.go  Crash triage, race probing, multi-identity
│   │   └── go.mod
│   └── Dockerfile.go           Container image for Go sidecar
│
├── instrumentor/               SharpFuzz instrumentor tool
├── grammars/                   Pre-compiled grammars (eshop, loyalty, helpdesk, nopcommerce)
├── restler_bin/                RESTler compiler binaries
│
├── mpt-helpdesk/               mpt-helpdesk source
├── mpt-currency/               mpt-currency source
├── prepared-helpdesk/          mpt-helpdesk instrumented (ready to fuzz)
└── mpt-prepared/               mpt-currency instrumented (ready to fuzz)
```

---

## Quick Start (New Project)

```bash
# 1. Instrument
python3 fuzz-prep-multi.py --src ./my-project --out ./my-project-prep --main MyApi

# 2. Build & start
cd my-project-prep && docker compose build && docker compose up -d && sleep 45

# 3. Verify instrumentation
curl -X POST http://localhost:8080/shm/create
curl http://localhost:8080/shm/coverage   # → {"edges":N,"hits":N}

# 4. Compile grammar
cd .. && curl -s http://localhost:8080/swagger/v1/swagger.json -o swagger.json
./compile-grammar.sh swagger.json --src ./my-project
mkdir -p grammars/myapi && cp restler_output/Compile/* grammars/myapi/

# 5. Fuzz
cd smart_fuzzer/go
export TARGET_HOST="http://localhost:8080"
export SHM_HOST="http://localhost:8080"
export AUTH_TOKEN="<jwt>"
./smartfuzzergo -grammar ../../grammars/myapi -time-budget 20
```

See [INSTRUCTIONS.md](INSTRUCTIONS.md) for complete commands, all profiles, and troubleshooting.
