# UpsideFuzz — Bitwarden Quick Start

> Run the full coverage-guided fuzzing pipeline on **Bitwarden** (multi-service password manager backend) from scratch on any machine.

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md)**

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Clone Repositories](#step-1-clone-repositories)
3. [Step 2: Instrument the Project](#step-2-instrument-the-project)
4. [Step 3: Build and Start Containers](#step-3-build-and-start-containers)
5. [Step 4: Generate an Auth Token](#step-4-generate-an-auth-token)
6. [Step 5: Create an Auth Identity File](#step-5-create-an-auth-identity-file)
7. [Step 6: Populate the Database with Test Data](#step-6-populate-the-database-with-test-data)
8. [Step 7: Compile the Grammar](#step-7-compile-the-grammar)
9. [Step 8: Run the Fuzzer](#step-8-run-the-fuzzer)
10. [Step 8b: Web UI Dashboard](#step-8b-web-ui-dashboard)
11. [Step 9: View Results](#step-9-view-results)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

```bash
docker --version        # Docker 24+
docker compose version  # Compose v2+
python3 --version       # Python 3.9+
```

Python dependencies:

```bash
pip install -r requirements.txt
```

> **Apple Silicon / ARM hosts:** Bitwarden's MSSQL container is `linux/amd64` and runs under Rosetta emulation on M-series Macs. Expect slower first-time pull and a longer DB startup window (90–120 s).

---

## Step 1: Clone Repositories

```bash
# Clone the fuzzer
git clone https://github.com/malchikserega/upside-fuzzer.git
cd upside-fuzzer

# Clone Bitwarden server (target application)
git clone https://github.com/bitwarden/server.git bitwarden_src
```

> **Note:** The repository already contains a prepared `bitwarden_prep/` directory with a custom `docker-compose.instrumented.yml` and helper scripts. If you use a fresh Bitwarden checkout, run `fuzz-prep-multi.py` (Step 2) to regenerate it.

---

## Step 2: Instrument the Project

```bash
python3 fuzz-prep-multi.py \
  --src ./bitwarden_src \
  --out ./bitwarden_prep \
  --main src/Api
```

This creates an instrumented copy in `./bitwarden_prep/` with:
- SharpFuzz IL instrumentation for all business logic DLLs
- SHM coverage endpoints (`/shm/create`, `/shm/coverage`, `/shm/reset`)
- Docker Compose with tmpfs volume for shared memory bitmap

> **Tip:** `bitwarden_prep/` in this repository already contains a working instrumented tree. You can skip this step and go directly to Step 3 unless you want to re-instrument from a fresh clone.

---

## Step 3: Build and Start Containers

```bash
cd bitwarden_prep

docker compose -f docker-compose.instrumented.yml up mssql migrator identity api -d

# MSSQL needs time to initialize — wait 90–120 seconds on first run
sleep 90
```

**Verify the API is responding:**

```bash
curl -s http://localhost:4000/alive
# → 200 OK

# Fetch the internal OpenAPI spec
curl -s http://localhost:4000/specs/internal/swagger.json | head -c 200
```

> **Port:** Bitwarden API listens on port `4000` by default. Check `docker-compose.instrumented.yml` if it differs.

**Verify coverage instrumentation:**

```bash
curl -s -X POST http://localhost:4000/shm/create
# → {"status":"synced","mode":"file-backed-mmap","bitmap_size":262144,...}

curl -s http://localhost:4000/shm/coverage
# → {"edges":N,"hits":N}  (edges > 0 confirms instrumentation is active)
```

---

## Step 4: Generate an Auth Token

Bitwarden requires a valid access token. The `get_apikey.py` helper automates the full registration + token flow:

```bash
cd bitwarden_prep
python3 get_apikey.py
```

**What the script does:**

1. Sends `POST /accounts/register/send-verification-email`
2. Completes registration via `POST /accounts/register/finish` (with `kdfIterations: 600000`)
3. Requests an OAuth access token from `POST /connect/token` with the required Bitwarden client headers
4. Writes a `fuzzer.env` file with the auth material

> **SMTP note:** Bitwarden's identity service may try to send a verification email. If your test stand has no SMTP server, start a dummy listener inside the container:
> ```bash
> docker exec -it bitwarden_prep-identity-1 bash -c "apt-get install -y python3 && python3 -m smtpd -n -c DebuggingServer localhost:25 &"
> ```

After running `get_apikey.py`, `fuzzer.env` contains one of:
- `AUTH_TOKEN` — raw JWT (Void sends `Authorization: Bearer <token>`)
- `AUTH_HEADERS_JSON` — JSON object of header → value
- `AUTH_HEADER` — legacy single-header shortcut

All three formats are accepted by Void without modification.

---

## Step 5: Create an Auth Identity File

For access-control fuzzing (finding IDOR, cross-user bugs), create an auth identity file with multiple users. The script below reads `fuzzer.env` and writes `auth.identities.json`:

```bash
cd bitwarden_prep

python3 - <<'PY'
import json
from pathlib import Path

env = {}
for line in Path("fuzzer.env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        env[k] = v.strip().strip('"').strip("'")

identities = [{"name": "guest", "weight": 0.2}]
if env.get("AUTH_TOKEN"):
    identities.insert(0, {"name": "bitwarden-user", "jwt": env["AUTH_TOKEN"], "weight": 2.0})
elif env.get("AUTH_COOKIE"):
    identities.insert(0, {"name": "bitwarden-cookie-user", "cookie": env["AUTH_COOKIE"], "weight": 2.0})
elif env.get("AUTH_HEADERS_JSON"):
    identities.insert(0, {"name": "bitwarden-header-user", "headers": json.loads(env["AUTH_HEADERS_JSON"]), "weight": 2.0})
elif env.get("AUTH_HEADER"):
    name, value = env["AUTH_HEADER"].split(":", 1)
    identities.insert(0, {"name": "bitwarden-header-user", "headers": {name.strip(): value.strip()}, "weight": 2.0})
else:
    raise SystemExit("No supported auth value found in fuzzer.env")

Path("auth.identities.json").write_text(json.dumps({"version": "1", "identities": identities}, indent=2))
print("Written: auth.identities.json")
PY
```

For a multi-user access-control campaign, run `get_apikey.py` for a second user, then manually add a second identity entry. See [`docs/FUZZER_AUTHENTICATION.md`](docs/FUZZER_AUTHENTICATION.md) for the full auth file schema.

---

## Step 6: Populate the Database with Test Data

Bitwarden's business logic requires real objects in the database (folders, ciphers, sends) for `PUT`/`DELETE` endpoints to return anything other than 404. The `populate_data.py` script creates them:

```bash
cd bitwarden_prep

# Populate for all identities in auth.identities.json
python3 populate_data.py --auth-file auth.identities.json

# Single-user fallback (reads fuzzer.env)
python3 populate_data.py
```

**Useful options:**

```bash
# Populate only for one specific identity
python3 populate_data.py --auth-file auth.identities.json --identity bitwarden-user

# Control object counts
python3 populate_data.py --auth-file auth.identities.json --folders 5 --ciphers 30 --sends 10

# Dry-run to preview what would be created
python3 populate_data.py --auth-file auth.identities.json --dry-run
```

The script creates:
- Folders for each authenticated identity
- Cipher records (encrypted vault items) linked to those folders
- Send items (secure sharing links)
- `populated-objects.json` with created object IDs grouped by identity

> Anonymous `guest` identities are skipped automatically. No secrets or tokens are written to `populated-objects.json`.

---

## Step 7: Compile the Grammar

```bash
cd ..  # back to upside-fuzzer root

# Download the internal Swagger spec (includes all API routes)
curl -s http://localhost:4000/specs/internal/swagger.json -o swagger-bitwarden.json

# Sanitize: Bitwarden uses deepObject/nested $ref params unsupported by RESTler
cd bitwarden_prep
python3 sanitize_swagger.py internal_swagger.json
cd ..

# Compile grammar (RESTler + source-aware enhancement)
./compile-grammar.sh bitwarden_prep/internal_swagger.json --src ./bitwarden_src

# Save grammar files
mkdir -p grammars/bitwarden
cp restler_output/Compile/grammar.py restler_output/Compile/dict.json grammars/bitwarden/

# Export templates for the Go fuzzer
python3 void/export-templates.py \
  --grammar-dir grammars/bitwarden \
  --out grammars/bitwarden/templates.export.json
```

> **Tip:** If you have a security-specific dictionary overlay (`dict.security.json`), merge it with the generated `dict.json` before exporting templates. The security overlay adds Bitwarden-specific payloads for `returnUrl`, `redirect_uri`, device identifiers, base64url tokens, and GUID-heavy paths.

---

## Step 8: Run the Fuzzer

### Standard run (using `fuzzer.env`)

```bash
cd bitwarden_prep
docker compose -f docker-compose.instrumented.yml --profile fuzz up smartfuzzer --build -d
```

### Recommended security run (with auth identity file)

```bash
docker compose -f docker-compose.instrumented.yml --profile fuzz run --build --rm \
  -p 13377:13377 \
  -v "$PWD/src:/src:ro" \
  -v "$PWD/auth.identities.json:/auth/auth.identities.json:ro" \
  smartfuzzer \
  -grammar /grammar \
  -templates-json /grammar/templates.export.json \
  -src /src \
  -auth-file /auth/auth.identities.json \
  -identity-mode weighted \
  -identity-include-guest=true \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -coverage-bitmap-size 262144 \
  -time-budget 30 \
  -concurrency 16 \
  -min-concurrency 8 \
  -max-concurrency 40 \
  -request-timeout 4.0 \
  -coverage-interval 4 \
  -sequence-prob 0.45 \
  -sequence-max-depth 5 \
  -sequence-fanout 8 \
  -race-prob 0.08 \
  -race-burst 3 \
  -skip-endpoint-on-500 \
  -skip-on-crash \
  -skip-on-crash \
  -web-ui
```

**What to look for in the logs (when `-no-ui` is omitted):**

```
Authenticated (jwt auth available)
Identities loaded: 3 (mode=weighted guest=true auth_file=true)
Coverage after reset: 0 edges
Templates loaded: 142
Baseline corpus seeded: 142
```

The metrics `edges`, `corpus`, and `crashes` should start increasing within the first minute.

> **Many 401/403 responses are expected and beneficial.** They prove the fuzzer is testing authorization boundaries by using fuzzed IDs, which stress-tests resource-based access control even when the underlying resource doesn't exist.

---

## Step 8b: Web UI Dashboard

When launched with `-web-ui`, the fuzzer starts an embedded HTTP server on port `13377` (configurable via `-web-ui-port`).

**Access the dashboard:** Open `http://localhost:13377` in your browser.

### Dashboard Features

| Area | What it shows |
|------|---------------|
| **Header** | Live req/s, avg latency, concurrency threads, time progress bar |
| **Stats Cards** | Requests, edges, crashes (total + unique), corpus size, new edges, avg latency |
| **Fuzzer Engine** | Epoch progress (Baseline → Deterministic → Havoc → Splicing), active mutations, animated packet flow |
| **Crash List** | Scrollable list of up to 20 recent unique crashes, color-coded by status, with method badges and exception types |
| **Crash Popup** | Click any crash to see: endpoint, status, mutation, signature, identity, triage score/classification, formatted response body, request payload, auth context |
| **Coverage Bitmap** | Live visualization of the shared memory coverage bitmap |
| **Event Log** | Color-coded live event stream (crashes = 🔴, new edges = 🟢, auth blocks = 🟡, concurrency adaptation = 🟣) |
| **Run Info** | Identity count, auth-blocked endpoints, coverage saturation % |

> **Note:** The Web UI uses Server-Sent Events (SSE) for real-time streaming — no WebSocket or polling required. Stats refresh every 200ms.

### Port mapping in Docker

When using `docker compose run`, you must expose the port explicitly:

```bash
docker compose -f docker-compose.instrumented.yml --profile fuzz run --rm \
  -p 13377:13377 \
  ... \
  smartfuzzer -web-ui
```

---

## Step 9: View Results

```bash
# Live log (one line per crash)
docker logs -f bitwarden_prep-smartfuzzer-1

# Unique crashes (deduplicated)
cat ../crashes/unique-crashes-*.jsonl | \
  python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin]"

# Generated PoC scripts for manual reproduction
ls ../crashes/pocs/
```

Crash records and PoC scripts have sensitive auth headers redacted. Set `AUTH_TOKEN` before replaying a PoC:

```bash
export AUTH_TOKEN="eyJhbGciOi..."
bash ../crashes/pocs/poc-<signature>.sh
```

> ⚠️ **Responsible use:** Fuzzing and vulnerability analysis must be conducted strictly within authorized, self-hosted test environments. Do not run against production or third-party systems.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| MSSQL takes too long | Increase `sleep` to 120 s; check `docker logs bitwarden_prep-mssql-1` |
| `edges: 0` after requests | Call `POST /shm/create` first |
| Identity service rejects login | Start a dummy SMTP listener inside `bitwarden_prep-identity-1` (see Step 4 note) |
| `get_apikey.py` fails | Check API is on port 4000; check `docker compose logs api` for startup errors |
| Grammar has 0 endpoints | Verify swagger was downloaded with content; re-run sanitize step |
| All writes are 401/403 | Token may have expired; re-run `get_apikey.py` |

---

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md) · [Architecture](ARCHITECTURE.md)**
