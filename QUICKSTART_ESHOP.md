# UpsideFuzz — eShopOnWeb Quick Start

> Run the full coverage-guided fuzzing pipeline on **eShopOnWeb** from scratch on any machine.

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md) · [Docs Index](docs/INDEX.md)**

---

## Prerequisites

```bash
docker --version        # Docker 24+
docker compose version  # Compose v2+
python3 --version       # Python 3.9+
```

---

## Step 1: Clone repositories

```bash
# Clone the fuzzer
git clone https://github.com/malchikserega/upside-fuzzer.git
cd upside-fuzzer

# Clone eShopOnWeb (target application)
git clone https://github.com/dotnet-architecture/eShopOnWeb.git esh
```

---

## Step 2: Instrument the project

```bash
python3 fuzz-prep-multi.py \
  --src ./esh \
  --out ./eshprep \
  --main PublicApi
```

This creates an instrumented copy in `./eshprep/` with:
- SharpFuzz IL instrumentation for all business logic DLLs
- SHM coverage endpoints (`/shm/create`, `/shm/coverage`, `/shm/reset`)
- Docker Compose with tmpfs volume for shared memory bitmap

---

## Step 3: Build and start containers

```bash
cd eshprep
docker compose build
docker compose up -d

# Wait for SQL Server + DB migration
sleep 45
```

**Verify the API is up:**
```bash
curl -s http://localhost:5200/api/catalog-brands
# Should return JSON with Azure, .NET, Visual Studio, etc.
```

> **Note:** Port 5200 is set in `docker-compose.override.yml`. If the port is busy, edit the file.

---

## Step 4: Verify coverage instrumentation

```bash
# Initialize SHM bitmap
curl -s -X POST http://localhost:5200/shm/create
# → {"mode":"file-backed-mmap","size":262144,"status":"synced",...}

# Make a test request
curl -s http://localhost:5200/api/catalog-brands

# Check that coverage edges are > 0
curl -s http://localhost:5200/shm/coverage
# → {"edges":17,"hits":17}  ← coverage is working!
```

---

## Step 5: Compile the grammar

```bash
cd ..  # back to upside-fuzzer root

# Download swagger from the running app
curl -s http://localhost:5200/swagger/v1/swagger.json -o swagger-eshop.json

# Compile grammar (RESTler compiler + source-aware enhancement)
./compile-grammar.sh swagger-eshop.json --src ./esh

# Save grammar files
mkdir -p grammars/eshop
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/eshop/

# Export templates for the Go fuzzer
python3 void/export-templates.py \
  --grammar-dir grammars/eshop \
  --out grammars/eshop/templates.export.json
```

---

## Step 6: Build the fuzzer Docker image

```bash
docker build -t void-fuzzer -f void/Dockerfile.go void/
```

---

## Step 7: Run the fuzzer (Direct SHM mode)

```bash
mkdir -p crashes

docker run -it --rm \
  --network eshprep_default \
  -v eshprep_coverage_shm:/coverage_shm \
  -v $(pwd)/grammars/eshop:/grammar:ro \
  -v $(pwd)/crashes:/fuzzer/crashes \
  -e TARGET_HOST=http://eshprep-eshoppublicapi-1:8080 \
  -e SHM_HOST=http://eshprep-eshoppublicapi-1:8080 \
  -e AUTH_URL=/api/authenticate \
  -e AUTH_BODY='{"username":"admin@microsoft.com","password":"Pass@word1"}' \
  -e AUTH_TOKEN_FIELD=token \
  void-fuzzer \
  -grammar /grammar \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -skip-endpoint-on-500 \
  -time-budget 5 \
  -concurrency 10 \
  -sequence-prob 0.35
```

**What happens:**
- The fuzzer authenticates as admin and automatically attaches the JWT to all requests.
- The fuzzer reads the coverage bitmap directly from the shared `coverage_shm` tmpfs volume.
- No HTTP overhead for coverage — maximum throughput.
- Runs for 5 minutes with 10 parallel workers.

### Longer scan (recommended for thorough testing)

```bash
docker run -it --rm \
  --network eshprep_default \
  -v eshprep_coverage_shm:/coverage_shm \
  -v $(pwd)/grammars/eshop:/grammar:ro \
  -v $(pwd)/crashes:/fuzzer/crashes \
  -e TARGET_HOST=http://eshprep-eshoppublicapi-1:8080 \
  -e SHM_HOST=http://eshprep-eshoppublicapi-1:8080 \
  -e AUTH_URL=/api/authenticate \
  -e AUTH_BODY='{"username":"admin@microsoft.com","password":"Pass@word1"}' \
  -e AUTH_TOKEN_FIELD=token \
  void-fuzzer \
  -grammar /grammar \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -skip-endpoint-on-500 \
  -time-budget 30 \
  -concurrency 16 \
  -sequence-prob 0.40 \
  -sequence-max-depth 4
```

---

## Step 8: View results

```bash
# Unique crashes (deduplicated)
cat crashes/unique-crashes-*.jsonl | \
  python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin]"

# All crashes (raw log)
wc -l crashes/crashes-*.jsonl

# Generated PoC scripts
ls crashes/pocs/
```

### Example finding

In our test run (2 min, 10 workers), the fuzzer found:
- **119 unique code paths** (edges)
- **1 unique bug**: `GET /api/catalog-items?pageSize=-128` → `SqlException`
  - Negative `pageSize` causes `FETCH clause must be greater than zero`
  - 100% reproducible (5/5 repro checks passed)
  - Automatically minimized to the minimal reproducing payload

---

## Cleanup

```bash
cd eshprep
docker compose down

# Remove instrumented copy (optional)
cd .. && rm -rf eshprep
```

---

## Quick Reference

| Step | Command |
|------|---------|
| Instrument | `python3 fuzz-prep-multi.py --src ./esh --out ./eshprep --main PublicApi` |
| Build | `cd eshprep && docker compose build` |
| Start | `docker compose up -d && sleep 45` |
| Verify | `curl -s -X POST http://localhost:5200/shm/create && curl -s http://localhost:5200/shm/coverage` |
| Grammar | `./compile-grammar.sh swagger-eshop.json --src ./esh` |
| Fuzz | `docker run -it --rm --network eshprep_default -v eshprep_coverage_shm:/coverage_shm ... -e AUTH_URL=/api/authenticate ... void-fuzzer -direct-shm -time-budget 5` |
| Results | `cat crashes/unique-crashes-*.jsonl \| python3 -c "..."` |
| Stop | `cd eshprep && docker compose down` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port 5200 busy | Edit `eshprep/docker-compose.override.yml` |
| `edges: 0` | Call `POST /shm/create` first |
| 401/403 on writes | eShop needs auth — fuzzer handles this via `/api/authenticate` |
| `go.sum not found` on Docker build | Use the current repo checkout; `void/go/go.sum` is tracked and should already be present |
| Fuzzer can't connect | Check network name: `docker network ls \| grep eshprep` |

---

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md)**
