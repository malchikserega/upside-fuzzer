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

> **Zero-edit by default** (`--inject-mode hook`): the target's `Program.cs`/`Startup.cs`/`.csproj` are not modified; coverage is wired via `DOTNET_STARTUP_HOOKS` + an ASP.NET hosting-startup assembly. To use the legacy source-injection path instead, append `--inject-mode source`. After the stack is up (Step 3), verify the hook is linked from the host: `curl -s http://localhost:5200/shm/health` → `{"linked_assemblies":N,...}` (port `8080` is only the *container-internal* port; the host-mapped port for this quickstart is `5200`, set in `docker-compose.override.yml`).

This creates an instrumented copy in `./eshprep/` with:
- SharpFuzz IL instrumentation for all business logic DLLs
- SHM coverage endpoints (`/shm/create`, `/shm/coverage`, `/shm/reset`)
- Docker Compose with tmpfs volume for shared memory bitmap

---

## Step 3: Build and start containers

Only `sqlserver` and `eshoppublicapi` are needed for API fuzzing — `eshopwebmvc` (the
Blazor/Razor front-end) is a separate service in the same compose file and isn't
exercised by the grammar, so skip it to save a build.

```bash
cd eshprep
docker compose build eshoppublicapi
docker compose up -d sqlserver eshoppublicapi
```

**Wait for the API to come up** (SQL Server cold start + EF migration/seed takes
roughly 30–90s on first boot; poll instead of guessing a fixed sleep):

```bash
until curl -fsS -o /dev/null "http://localhost:5200/api/catalog-brands"; do
  echo "waiting for API..."; sleep 3
done
echo "API is up."
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

Or run the automated smoke test from the repo root, which checks `/shm/create`,
`/shm/health` (load-time linking), AFL-style bucketed per-request attribution, and
`/shm/coverage` growth from real traffic in one shot:

```bash
cd ..  # repo root
BASE_URL=http://localhost:5200 PROBE=/api/catalog-items ./verify-hook.sh
```

---

## Step 5: Compile the grammar

One command — first-party OpenAPI parser + Roslyn syntax-tree analyzer, no RESTler, no
Docker for this step. Writes `templates.export.json` + `dict.json` directly to
`grammars/eshop/`:

```bash
cd ..  # back to upside-fuzzer root

# Download swagger from the running app
curl -s http://localhost:5200/swagger/v1/swagger.json -o swagger-eshop.json

# Compile grammar (grammarc/ OpenAPI parser + analyzer/ Roslyn syntax-tree analysis of ./esh)
./compile-grammar.sh swagger-eshop.json --src ./esh --out grammars/eshop
```

That's it — no manual `cp`, no separate `export-templates.py` step. Expect output like:
```
[analyzer] Parsed 209 files (0 failed), 194 classes, ... 33 endpoints, ...
[grammarc] operations=8 templates=8 skipped=0 multipart_endpoints=0 roslyn_matched_types=3 dict_keys=25 -> grammars/eshop
```

Two things now happen automatically during the fuzz run below, no extra flags needed: fields
with a real `[Range]`/`[StringLength]` constraint (like `UpdateCatalogItemRequest.Price`) get
**boundary-aware mutation** (exact min-1/max+1 values, not just generic guesses — see
`ARCHITECTURE_REVIEW.md` Top-20 #14), and any 400 validation-error response gets mined for
required field names/valid values, fed straight back into the fuzzer's runtime dictionary
(Top-20 #11, "CMPLOG-lite").

---

## Step 6: Build the fuzzer Docker image

```bash
docker build -t void-fuzzer -f void/Dockerfile.go void/
```

---

## Step 7: Run the fuzzer (Direct SHM mode)

```bash
mkdir -p crashes summaries

docker run --rm \
  --network eshprep_default \
  -v eshprep_coverage_shm:/coverage_shm \
  -v $(pwd)/grammars/eshop:/grammar:ro \
  -v $(pwd)/crashes:/fuzzer/crashes \
  -v $(pwd)/summaries:/fuzzer/summaries \
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

> **Note:** Do not use `-it` unless running interactively in a terminal — it causes `cannot attach stdin to a TTY-enabled container` in CI or scripted environments.

**What happens:**
- The fuzzer authenticates as admin and automatically attaches the JWT to all requests.
- The fuzzer reads the coverage bitmap directly from the shared `coverage_shm` tmpfs
  Docker volume — confirmed working (`edges` climbs into the thousands, not `0`) on
  both Linux and macOS Docker Desktop, since the tmpfs is backed by the single Linux
  VM the Docker daemon runs in either way; the two containers share the same page
  cache for that volume regardless of host OS.
- No HTTP overhead for coverage — maximum throughput.
- Runs for 5 minutes with 10 parallel workers.

### Longer scan (recommended for thorough testing)

```bash
docker run --rm \
  --network eshprep_default \
  -v eshprep_coverage_shm:/coverage_shm \
  -v $(pwd)/grammars/eshop:/grammar:ro \
  -v $(pwd)/crashes:/fuzzer/crashes \
  -v $(pwd)/summaries:/fuzzer/summaries \
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

# Generated PoC scripts (ready-to-run curl repro)
ls crashes/pocs/

# Structured per-run summary (bugs, coverage, request stats) — mounted from
# /fuzzer/summaries inside the container
cat summaries/report-*.json | python3 -m json.tool | less
```

### Example findings

Re-verified end-to-end from a clean clone on 2026-07-22 (3 min budget, 10 workers,
~1.6M requests, ~8,900 req/s, direct-shm `edges` climbed to 1,604 — confirmed nonzero,
see note below). Exact bugs found vary run-to-run since mutation is randomized, but
these five classes reproduce reliably within the first few minutes of fuzzing:

| # | Severity | Method | Endpoint | Root cause | Stable |
|---|----------|--------|----------|-----------|--------|
| 1 | **HIGH** `likely_vuln_high` (score 9) | GET | `/api/catalog-items/1` | BOLA — identical 200 body for the authenticated `default` identity and the unauthenticated `guest` identity | ✅ |
| 2 | MEDIUM `needs_review` | GET | `/api/catalog-items?pageSize=-2&...` | SQL: "The number of rows provided for a FETCH clause must be greater than zero" (negative page size reaches the query unvalidated) | ✅ 100% |
| 3 | MEDIUM `needs_review` | GET | `/api/catalog-items?pageIndex=-1&pageSize=128` | SQL: "The offset specified in a OFFSET clause may not be negative" (negative page index reaches the query unvalidated) | ✅ 100% |
| 4 | MEDIUM `needs_review` | POST | `/api/catalog-items` | EF `SaveChanges` failure — duplicate `name` violates a uniqueness constraint and surfaces as a raw 500 instead of 409 Conflict | ✅ 100% |
| 5 | LOW `needs_review` | PUT | `/api/catalog-items` | `DbUpdateConcurrencyException` — a prior mutation in the same run deleted/changed the row the PUT targets (race/staleness under concurrent fuzzing) | ⚠️ run-dependent |

**Bug 1 (BOLA):** `GET /api/catalog-items/{id}` returns the full catalog item to unauthenticated (`guest`) requests — byte-identical to the authenticated response. The fuzzer's cross-identity oracle flags this automatically by replaying the same request under every configured identity and diffing bodies.

**Bugs 2 & 3 (unvalidated pagination params):** Neither `pageSize` nor `pageIndex` is range-checked before being used to build the SQL `OFFSET`/`FETCH` clause, so out-of-range values reach SQL Server raw and come back as an unhandled 500 with the driver's error message — a minor info-leak (SQL error text) plus a missing-input-validation bug.

**Bug 4 (duplicate item):** Re-`POST`ing a catalog item with a `name` that already exists throws inside `SaveChangesAsync` and is surfaced as a bare 500 instead of a handled 409 Conflict.

> **On `edges` and shared memory:** direct-shm mode has been verified to work correctly
> on macOS Docker Desktop (arm64) — `edges` grows into the thousands over a real run,
> read straight from the `coverage_shm` tmpfs Docker volume shared between the
> `void-fuzzer` and `eshoppublicapi` containers. If you see `edges: 0`, it means the
> bitmap genuinely isn't shared — check that both containers mount the *same* named
> volume (`docker volume ls | grep coverage_shm`, `docker inspect <container> | grep -A3 coverage_shm`)
> and that `-shm-path` matches the path the target mounts it at (`/coverage_shm/bitmap`
> by default). Per-request coverage is also tracked via `X-Coverage-Delta` response
> headers as a fallback signal on requests where it's present (see
> [Troubleshooting](#troubleshooting)), so bug finding is not blocked by a bitmap
> mounting issue either way — but a working bitmap is what drives the coverage-guided
> scheduler, so it's worth confirming.

---

## Cleanup

```bash
cd eshprep
docker compose down

# Remove instrumented copy (optional)
cd .. && rm -rf eshprep
```

---

## The same thing, via the `upsidefuzz` CLI

Steps 2–7 above, as CLI subcommands — verified end to end (2026-07-24) against this exact
target, both natively and through the zero-install Docker launcher. eShopOnWeb only starts
two services (`sqlserver eshoppublicapi`, not the whole compose file), so pass `--services`:

```bash
# Native: python3 upsidefuzz.py ...   |   Zero-install (only Docker needed): ./upsidefuzz ...
upsidefuzz instrument --src ./esh --out ./eshprep --main PublicApi

upsidefuzz up --dir ./eshprep --services sqlserver eshoppublicapi \
  --wait-url http://localhost:5200/api/catalog-brands --wait-timeout 120

upsidefuzz verify --base http://localhost:5200 --probe /api/catalog-items

upsidefuzz grammar http://localhost:5200/swagger/v1/swagger.json --src ./esh --out grammars/eshop

upsidefuzz fuzz --grammar grammars/eshop --target http://localhost:5200 \
  --profile security --time-budget 15

upsidefuzz down --dir ./eshprep
```

Or all at once with `run` (works cleanly here since eShopOnWeb has no non-standard steps —
no swagger patching, no multi-stage bring-up):

```bash
upsidefuzz run --src ./esh --out ./eshprep --main PublicApi \
  --services sqlserver eshoppublicapi \
  --target http://localhost:5200 --probe /api/catalog-items \
  --swagger http://localhost:5200/swagger/v1/swagger.json \
  --profile security --time-budget 15
```

See [docs/CLI.md](docs/CLI.md) for the full subcommand reference, and its "The `localhost`
gotcha" section if you're wondering why `--target`/`--swagger` "just work" in Docker mode
despite the CLI and the target running as separate containers.

---

## Quick Reference

| Step | Command |
|------|---------|
| Instrument | `python3 fuzz-prep-multi.py --src ./esh --out ./eshprep --main PublicApi` |
| Build | `cd eshprep && docker compose build eshoppublicapi` |
| Start | `docker compose up -d sqlserver eshoppublicapi` (then poll `/api/catalog-brands` — see Step 3) |
| Verify hook | `cd .. && BASE_URL=http://localhost:5200 PROBE=/api/catalog-items ./verify-hook.sh` |
| Grammar | `./compile-grammar.sh swagger-eshop.json --src ./esh --out grammars/eshop` (one command, no Docker/RESTler) |
| Build fuzzer | `docker build -t void-fuzzer -f void/Dockerfile.go void/` |
| Fuzz | `docker run --rm --network eshprep_default -v eshprep_coverage_shm:/coverage_shm -v $(pwd)/grammars/eshop:/grammar:ro -v $(pwd)/crashes:/fuzzer/crashes -v $(pwd)/summaries:/fuzzer/summaries -e AUTH_URL=/api/authenticate ... void-fuzzer -grammar /grammar -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode file -time-budget 5` |
| Results | `cat crashes/unique-crashes-*.jsonl \| python3 -c "..."` / `cat summaries/report-*.json` |
| Stop | `cd eshprep && docker compose down` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port 5200 busy | Edit `eshprep/docker-compose.override.yml` |
| `edges: 0` after `POST /shm/create`, or fuzzer reports `edges: 0` the whole run | Direct-shm coverage is confirmed working on both Linux and macOS Docker Desktop — `edges: 0` means the bitmap really isn't shared, not a platform limitation. Check: (1) both containers mount the *same* named volume — `docker volume ls \| grep coverage_shm`; (2) `-shm-path` on the fuzzer matches the mount path in the target (`/coverage_shm/bitmap`); (3) `POST /shm/create` was called at least once so the target has allocated the file-backed mmap (`"mode":"file-backed-mmap"` in the response, not `"heap"`). `X-Coverage-Delta` headers and `/shm/coverage` are independent fallbacks if you need to sanity-check without direct-shm. |
| `X-Coverage-Delta` header missing on a specific request | Expected for streamed (`Transfer-Encoding: chunked`) 200 responses — ASP.NET starts sending the response before the coverage middleware's `finally` runs. Not a bug: `/shm/coverage` and the fuzzer's periodic-poll fallback are unaffected. Reliably present on small/non-chunked responses (404s, empty bodies). See `verify-hook.sh`. |
| `AccessViolationException` at startup | Fixed in instrumentor ≥ 2026-07-22 — `Program` class (global namespace, top-level statements) is now correctly excluded from SharpFuzz instrumentation. Re-run `fuzz-prep-multi.py` and `docker compose build --no-cache eshoppublicapi`. |
| `cannot attach stdin to TTY` | Remove `-it` from `docker run` when running non-interactively (scripts, CI). Use `docker run --rm` instead. |
| 401/403 on writes | eShop needs auth — fuzzer handles this via `/api/authenticate` |
| `go.sum not found` on Docker build | Use the current repo checkout; `void/go/go.sum` is tracked and should already be present |
| Fuzzer can't connect | Check network name: `docker network ls \| grep eshprep` (project name defaults to the `eshprep/` directory name) |
| Want to confirm the hook is wired before a full fuzzing run | `BASE_URL=http://localhost:5200 PROBE=/api/catalog-items ./verify-hook.sh` from the repo root — runs the 5-point smoke test in [Step 4](#step-4-verify-coverage-instrumentation) automatically. |

---

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md)**
