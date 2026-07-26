# UpsideFuzz — Bitwarden Quick Start

> Run the full coverage-guided fuzzing pipeline on **Bitwarden** (multi-service password manager backend) from scratch on any machine.

> **⚠️ Steps 4-7 below (`get_apikey.py`/`populate_data.py`/`sanitize_swagger.py`) were not
> re-verified on 2026-07-25's fresh-clone run** and may be stale — Bitwarden's `server`
> repo had by then moved .NET 8 → .NET 10 and changed its Swagger route
> (`/swagger/v1/swagger.json` → `/specs/{documentName}/swagger.json`) since the
> 2026-07-23 pass this note used to describe. That 2026-07-25 run used a different,
> now-preferred approach — Bitwarden's own official `util/SeederApi` tool for data
> population instead of the custom scripts below, and an API-key (`client_credentials`)
> login flow instead of `get_apikey.py`'s registration flow. **See
> [BITWARDEN_FUZZ_RUNBOOK.md](BITWARDEN_FUZZ_RUNBOOK.md) Steps 1-6 for the current,
> fully-verified procedure** (compose file, data population, dict/auth setup) before
> following Steps 4-7 here. Steps 1-3 and 8-9 below (clone/instrument/build, run/results)
> were not affected by the drift and remain accurate.

> **Re-verified end-to-end from a completely fresh clone on 2026-07-23**: `git clone` → `fuzz-prep-multi.py` → `docker compose build --no-cache` → bring up → `verify-hook.sh` → `compile-grammar.sh` → fuzz, twice (once in each run mode below). Grammar output was byte-for-byte identical to prior runs (595 operations, 599 templates, 0 skipped). This pass also found and fixed two real fuzzer-engine bugs (a path-quoting leak and a malformed-auth-token leak on unauthenticated probes) — see `ARCHITECTURE_REVIEW.md`'s Inconsistencies section for the writeups. Every command below is exactly what was run, not aspirational.

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md)**

> **Already have a working `bitwarden_prep/` checkout?** Use [BITWARDEN_FUZZ_RUNBOOK.md](BITWARDEN_FUZZ_RUNBOOK.md) instead — it skips straight to bring-up/iterate/re-run and documents every gotcha found during setup. Come back to *this* guide for a fresh, from-scratch setup or if you're setting Bitwarden up for the first time.

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
9. [Step 8: Run the Fuzzer](#step-8-run-the-fuzzer) — two modes: [Host mode](#mode-a-host-mode-no-image-build-http-coverage) (no image build) and [Docker sidecar](#mode-b-docker-sidecar-direct-shm-fastest-coverage) (direct-shm)
10. [Step 8b: Web UI Dashboard](#step-8b-web-ui-dashboard)
11. [Step 9: View Results](#step-9-view-results)
12. [The same thing, via the `upsidefuzz` CLI](#the-same-thing-via-the-upsidefuzz-cli)
13. [Troubleshooting](#troubleshooting)

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

> **Note:** `bitwarden_prep/` (created in Step 2 below) doesn't exist yet after this step — that's expected. Everything below works from a bare `bitwarden_src/` checkout with nothing pre-generated.

---

## Step 2: Instrument the Project

```bash
python3 fuzz-prep-multi.py \
  --src ./bitwarden_src \
  --out ./bitwarden_prep \
  --main src/Api
```

> **Zero-edit by default** (`--inject-mode hook`): the target's `Program.cs`/`Startup.cs`/`.csproj` are not modified; coverage is wired via `DOTNET_STARTUP_HOOKS` + an ASP.NET hosting-startup assembly. Because `StartupHook.Initialize()` binds the SHM pointer *before* `Main` and links each assembly as it loads, this also avoids the startup-time `AccessViolationException` class of failures seen with source injection on multi-service apps — **including for `Bit.Core.Utilities`**, which historically needed `--exclude-namespaces` to avoid a crash; that's no longer necessary (re-verified 2026-07-22 end-to-end from a fresh clone: the API boots cleanly with `Bit.Core.Utilities` fully instrumented). To use the legacy source-injection path instead, append `--inject-mode source`. Verify after startup: `curl -s http://localhost:4000/shm/health`.

**Why `--main src/Api`?** Bitwarden is a complex multi-project solution with many entry points (Api, Identity, Admin, Scim). This tells the instrumentor which project's Dockerfile to adapt and treat as the fuzzing target.

**No `--exclude-namespaces` needed.** The tool auto-detects that none of Bitwarden's own root namespaces (`Bit.*`) collide with the hardcoded framework-prefix denylist (`System.`, `Microsoft.`, ...) used by `--instrument-all-user-code`, and automatically prefers that mode over the namespace-allowlist path — it's strictly more complete (every non-framework/generated type gets instrumented, not just the ones whose files happen to match a `*Controller.cs`/`*Service.cs`/etc. naming convention). You'll see `Instrumentation scope: --instrument-all-user-code` in the tool's output confirming this. If you ever need to exclude a specific namespace (e.g. a third-party plugin assembly with its own static-init quirks), `--exclude-namespaces` still works — it forces the namespace-allowlist path instead.

This creates an instrumented copy in `./bitwarden_prep/` with:
- SharpFuzz IL instrumentation for all business logic DLLs, chosen via `--instrument-all-user-code` (falls back to a source-derived namespace allowlist only if your fork's root namespace collides with the framework denylist, or if you pass `--exclude-namespaces`)
- SHM coverage endpoints (`/shm/create`, `/shm/coverage`, `/shm/reset`)
- Docker Compose with tmpfs volume for shared memory bitmap

> **Current upstream Bitwarden note:** `src/Api/Dockerfile` (and the other services) publish as a self-contained single-file bundle (`/p:PublishSingleFile=true`), which packs every managed DLL into one native executable — nothing left on disk for SharpFuzz/Cecil to rewrite. `fuzz-prep-multi.py` detects and strips this automatically for the instrumented build variant (look for `Detected PublishSingleFile=true — disabled...` in the tool's output); the target's real release Dockerfile on disk is never modified.

> **Important:** The auto-generated `docker-compose.instrumented.yml` only contains the API service — Bitwarden requires a full stack (Database, Identity server, Migrator). You must add a hand-written compose file. **Note the Dockerfile paths below matter**: `fuzz-prep-multi.py` adapts each project's *own* Dockerfile in place (`src/Api/Dockerfile`, `src/Identity/Dockerfile`, ...) inside your `--out` directory — it does not generate standalone `Dockerfile.instrumented`/`Dockerfile.migrator`/`Dockerfile.identity` files at the prep root. Only `--main`'s project (`src/Api`) gets coverage instrumentation; `identity` runs from its own copied-but-uninstrumented Dockerfile, which is fine since the fuzzer only needs coverage feedback from the service it's actually fuzzing. Expand the section below to view and save the required file — this is the exact file verified working end-to-end on 2026-07-23.

<details>
<summary><b>Click here to view the full <code>docker-compose.instrumented.yml</code> for Bitwarden</b></summary>

Save this as `docker-compose.instrumented.yml` inside your `bitwarden_prep` directory:

```yaml
services:
  mssql:
    image: mcr.microsoft.com/mssql/server:2022-latest
    platform: linux/amd64
    environment:
      ACCEPT_EULA: "Y"
      MSSQL_SA_PASSWORD: "FuzzP@ssw0rd123!"
      MSSQL_PID: Developer
    ports:
      - "1433:1433"
    volumes:
      - mssql_data:/var/opt/mssql
    healthcheck:
      test: /opt/mssql-tools18/bin/sqlcmd -S localhost -U SA -P "FuzzP@ssw0rd123!" -Q "SELECT 1" -C -b
      interval: 10s
      timeout: 15s
      retries: 20
      start_period: 240s

  # Uses the real MsSqlMigratorUtility project's own Dockerfile (ships with Bitwarden,
  # under util/) instead of a hand-rolled entrypoint script — robust, no `|| true`
  # silently swallowing a real migration failure. Exits 0 on success; api/identity
  # wait for that via `service_completed_successfully` below.
  migrator:
    build:
      context: .
      dockerfile: util/MsSqlMigratorUtility/Dockerfile
    depends_on:
      mssql:
        condition: service_healthy
    environment:
      MSSQL_CONN_STRING: "Server=mssql,1433;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"

  api:
    build:
      context: .
      dockerfile: src/Api/Dockerfile
    ports:
      - "4000:5000"
    depends_on:
      mssql:
        condition: service_healthy
      migrator:
        condition: service_completed_successfully
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      ASPNETCORE_URLS: http://+:5000
      globalSettings__selfHosted: "true"
      globalSettings__disableUserRegistration: "false"
      globalSettings__sqlServer__connectionString: "Server=mssql,1433;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"
      globalSettings__installation__id: "b4545580-0a88-4682-9653-af8e00e84b80"
      globalSettings__installation__key: "00000000000000000000000000000000"
      globalSettings__baseServiceUri__vault: "http://localhost:4000"
      globalSettings__baseServiceUri__api: "http://localhost:4000"
      globalSettings__baseServiceUri__identity: "http://identity:5000"
      globalSettings__baseServiceUri__internalIdentity: "http://identity:5000"
      globalSettings__identityServer__certificateThumbprint: ""
      globalSettings__dataProtection__certificateThumbprint: ""
      globalSettings__mail__smtp__host: "localhost"
      globalSettings__mail__smtp__port: "25"
      globalSettings__enableEmailVerification: "false"
      globalSettings__enableNewDeviceVerification: "false"
    volumes:
      - /dev/shm:/dev/shm
      - coverage_shm:/coverage_shm
      - core_data:/etc/bitwarden/core

  identity:
    build:
      context: .
      dockerfile: src/Identity/Dockerfile
    ports:
      - "33656:5000"
    depends_on:
      mssql:
        condition: service_healthy
      migrator:
        condition: service_completed_successfully
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      ASPNETCORE_URLS: http://+:5000
      globalSettings__selfHosted: "true"
      globalSettings__sqlServer__connectionString: "Server=mssql,1433;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"
      globalSettings__installation__id: "b4545580-0a88-4682-9653-af8e00e84b80"
      globalSettings__installation__key: "00000000000000000000000000000000"
      globalSettings__baseServiceUri__vault: "http://localhost:4000"
      globalSettings__baseServiceUri__api: "http://api:5000"
      globalSettings__baseServiceUri__identity: "http://localhost:33656"
      globalSettings__baseServiceUri__internalIdentity: "http://identity:5000"
      globalSettings__identityServer__certificateThumbprint: ""
      globalSettings__dataProtection__certificateThumbprint: ""
      globalSettings__mail__smtp__host: "localhost"
      globalSettings__mail__smtp__port: "25"
      globalSettings__enableEmailVerification: "false"
      globalSettings__enableNewDeviceVerification: "false"
      # appsettings.Development.json sets developmentDirectory to "../../dev", a path
      # relative to a local repo checkout (for `dotnet run` from src/Identity/) that
      # resolves to the literal /dev inside this container (WORKDIR=/app) — IdentityServer
      # then fails to persist its dev signing key there. Redirect to a writable path.
      globalSettings__developmentDirectory: "/tmp"
    volumes:
      - core_data:/etc/bitwarden/core

volumes:
  mssql_data:
  core_data:
  coverage_shm:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=4m
```
</details>

**Explanation of the Compose Services:**
- `mssql`: The SQL Server database used by Bitwarden.
- `migrator`: A short-lived container (built from Bitwarden's own `util/MsSqlMigratorUtility/`) that runs the EF Core migrations to build the `vault_fuzz` database schema. `api`/`identity` won't start until it exits 0.
- `api`: The main instrumented Bitwarden API, configured with test credentials, dummy certificates, and fake SMTP to bypass external dependencies.
- `identity`: Bitwarden's Identity Server (OAuth provider). The Fuzzer needs this to authenticate and issue valid JWT tokens for API requests.

No `smartfuzzer` service here deliberately — see **Step 8** below for both ways to actually run the fuzzer against this stack (as a container, or directly on your host).

---

## Step 3: Build and Start Containers

Bring the stack up in stages — this is more debuggable than starting everything at once,
and matches exactly what was verified on 2026-07-23:

```bash
cd bitwarden_prep

# 1. Build everything (no cache, to mirror a genuinely fresh CI-style run — drop
#    --no-cache for faster iterative rebuilds once you've done this once)
docker compose -f docker-compose.instrumented.yml build --no-cache mssql migrator api identity

# 2. Database first — wait for it to actually report healthy, not a fixed sleep
docker compose -f docker-compose.instrumented.yml up -d mssql
until [ "$(docker inspect -f '{{.State.Health.Status}}' $(docker compose -f docker-compose.instrumented.yml ps -q mssql) 2>/dev/null)" = "healthy" ]; do
  sleep 5
done
echo "mssql healthy"

# 3. Migrations — creates the vault_fuzz database. Must complete before api/identity
#    start (the compose file's `service_completed_successfully` condition enforces
#    this even if you bring everything up with one `up -d` instead).
docker compose -f docker-compose.instrumented.yml up migrator

# 4. API + Identity
docker compose -f docker-compose.instrumented.yml up -d api identity
```

> **Apple Silicon:** step 2's healthcheck can take 90–240 s under Rosetta emulation the
> first time — the `until` loop above waits for however long that actually takes instead
> of guessing with a fixed `sleep`.

**Verify the API is responding:**

```bash
curl -s http://localhost:4000/alive
# → 200 OK

# Fetch the internal OpenAPI spec
curl -s http://localhost:4000/specs/internal/swagger.json | head -c 200
```

> **Port:** Bitwarden API listens on port `4000` by default. Check `docker-compose.instrumented.yml` if it differs.

**Verify coverage instrumentation (do this every time — it catches silently-broken coverage):**

Use the root-level `verify-hook.sh` — it's the more thorough check (8 assertions: SHM
linking, per-request bucketed attribution, real-endpoint edge growth), and is what was
actually used to validate this exact run:

```bash
cd ..  # repo root
BASE_URL=http://localhost:4000 PROBE=/api/accounts/profile ./verify-hook.sh
# → ALL CHECKS PASSED (8 ok) — zero-edit hook instrumentation + bucketed coverage verified.
```

Expect `linked_assemblies=1` and `total_classes` in the hundreds (verified run: 882) —
that's the number of instrumented types SharpFuzz actually linked to the shared bitmap.

Manual equivalent, if you just want a quick edges-only check:
```bash
curl -s -X POST http://localhost:4000/shm/create
curl -s http://localhost:4000/shm/coverage      # → {"edges":N,"hits":N} (N > 0 = active)
```

> **Instrumentation completeness:** the build now uses `--instrument-all-user-code` (every non-framework type in the target's own DLLs), not a `namespaces.json` allowlist — so no business namespace is silently dropped. If `verify-hook.sh` reports `edges=0`, check the build log for `[instrumentor] Done: instrumented=0` (a no-op instrument) before running the fuzzer.

---

## Step 4: Generate an Auth Token

Bitwarden requires a valid access token. The `get_apikey.py` helper automates the full registration + token flow:

```bash
cd bitwarden_prep
python3 ../examples/bitwarden/get_apikey.py
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
python3 ../examples/bitwarden/populate_data.py --auth-file auth.identities.json

# Single-user fallback (reads fuzzer.env)
python3 ../examples/bitwarden/populate_data.py
```

**Useful options:**

```bash
# Populate only for one specific identity
python3 ../examples/bitwarden/populate_data.py --auth-file auth.identities.json --identity bitwarden-user

# Control object counts
python3 ../examples/bitwarden/populate_data.py --auth-file auth.identities.json --folders 5 --ciphers 30 --sends 10

# Dry-run to preview what would be created
python3 ../examples/bitwarden/populate_data.py --auth-file auth.identities.json --dry-run
```

The script creates:
- Folders for each authenticated identity
- Cipher records (encrypted vault items) linked to those folders
- Send items (secure sharing links)
- `populated-objects.json` with created object IDs grouped by identity

> Anonymous `guest` identities are skipped automatically. No secrets or tokens are written to `populated-objects.json`.

---

## Step 7: Compile the Grammar

RESTler is retired — grammar compilation is now one first-party command (`grammarc/` +
`analyzer/`), no Docker involved. The sanitize step below is **still needed**: it's not
a RESTler-specific workaround, it's because `grammarc/oas.py` doesn't yet decompose
`style: deepObject`/object-shaped query parameters into multiple keys (a disclosed,
open gap — see `ARCHITECTURE_REVIEW.md`) — Bitwarden's spec uses this shape in several
places.

```bash
cd ..  # back to upside-fuzzer root

# Download the internal Swagger spec (includes all API routes)
curl -s http://localhost:4000/specs/internal/swagger.json -o swagger-bitwarden.json

# Sanitize: Bitwarden uses deepObject/nested $ref query params grammarc doesn't yet decompose
cd bitwarden_prep
python3 ../examples/bitwarden/sanitize_swagger.py internal_swagger.json
cd ..

# Compile grammar (grammarc/ OpenAPI parser + analyzer/ Roslyn syntax-tree analysis) — one
# command, writes templates.export.json + dict.json directly to grammars/bitwarden/
./compile-grammar.sh bitwarden_prep/internal_swagger.json --src ./bitwarden_src --out grammars/bitwarden
```

Expect output like (verified 2026-07-23 against a fresh `bitwarden_src` clone, ~3,864 `.cs`
files, 5 seconds total, no Docker):
```
[analyzer] Parsed 3864 files (0 failed), 3757 classes, ... 750 endpoints, ...
[grammarc] operations=595 templates=599 skipped=0 multipart_endpoints=4 roslyn_matched_types=284 dict_keys=845 -> grammars/bitwarden
```
599 templates matches the previous RESTler-based grammar's template count exactly — same
coverage, now with type/property-scoped Roslyn constraints on 284 of the 595 operations
(vs. global-name-collision-prone regex extraction before) and zero external dependency.

> **Tip:** If you have a security-specific dictionary overlay (`dict.security.json`), pass it directly: `./compile-grammar.sh ... --dict dict.security.json`. The security overlay adds Bitwarden-specific payloads for `returnUrl`, `redirect_uri`, device identifiers, base64url tokens, and GUID-heavy paths.

> **Also automatic, no extra flags:** the 284 Roslyn-constrained operations above get
> **boundary-aware mutation** during the fuzz run (exact min/max/length/enum-derived values,
> not just generic guesses — Top-20 #14), and every 400 validation-error response gets mined
> for required field names/valid values fed back into the runtime dictionary (Top-20 #11,
> "CMPLOG-lite") — genuinely useful on an API this validation-heavy.

---

## Step 8: Run the Fuzzer

There are **two ways to run the fuzzer** against the stack you just brought up. Both read
the same grammar and hit the same `http://localhost:4000` API — the only difference is
*where the fuzzer process itself runs* and *how it reads the coverage bitmap*.

| | Mode A — Host mode | Mode B — Docker sidecar (direct-shm) |
|---|---|---|
| Where the fuzzer runs | Directly on your machine (`go build` + run the binary) | As its own container, networked with the stack |
| Coverage read path | HTTP polling (`/shm/coverage`) | Direct mmap read of the shared `coverage_shm` tmpfs volume |
| Best for | Iterating on the fuzzer's own Go code (no image rebuild needed), quick ad-hoc runs, exactly what was used to validate this guide | Long unattended campaigns, CI, when you want the fuzzer's resource usage/network isolated in its own container |
| Setup cost | Lower (just `go build`) | Higher (build the `void-fuzzer` image first) |

Both modes accept the same CLI flags (see [void/README.md](void/README.md) for the full
reference) — pick whichever fits your workflow. You don't need to run both.

### Mode A — Host mode (no image build, HTTP coverage)

```bash
cd ../void/go && go build -o /tmp/smartfuzzergo .
cd ../../bitwarden_prep

export $(cat fuzzer.env | xargs)   # loads AUTH_TOKEN
mkdir -p ../crashes ../summaries

TARGET_HOST=http://localhost:4000 SHM_HOST=http://localhost:4000 AUTH_TOKEN="$AUTH_TOKEN" \
  /tmp/smartfuzzergo \
  -grammar ../grammars/bitwarden \
  -profile security \
  -skip-endpoint-on-500 \
  -time-budget 15 \
  -unique-crash-file ../crashes/unique-crashes-bitwarden.jsonl \
  -summary-file ../summaries/summary-bitwarden.json \
  -poc-dir ../crashes/pocs \
  -timeline-dir ../crashes/timelines
```

For the multi-identity / access-control campaign (Step 5/6's `auth.identities.json` +
populated data), add `-auth-file ../bitwarden_prep/auth.identities.json -identity-mode
weighted -identity-include-guest=true -sequence-prob 0.45` and drop the bare `AUTH_TOKEN`
env var (the auth file takes over identity scheduling). `-no-ui` disables the live
terminal dashboard if you're piping output to a file.

### Mode B — Docker sidecar (direct-shm, fastest coverage)

```bash
cd ..  # repo root
docker build -t void-fuzzer -f void/Dockerfile.go void/
mkdir -p crashes summaries

docker run --rm \
  --network bitwarden_prep_default \
  -v bitwarden_prep_coverage_shm:/coverage_shm \
  -v $(pwd)/grammars/bitwarden:/grammar:ro \
  -v $(pwd)/crashes:/fuzzer/crashes \
  -v $(pwd)/summaries:/fuzzer/summaries \
  -e AUTH_TOKEN="$(grep AUTH_TOKEN bitwarden_prep/fuzzer.env | cut -d= -f2)" \
  void-fuzzer \
  -grammar /grammar \
  -direct-shm \
  -shm-path /coverage_shm/bitmap \
  -shm-read-mode file \
  -profile security \
  -skip-endpoint-on-500 \
  -time-budget 15
```

> **Network/volume names** follow Docker Compose's `<project-dir-name>_<resource-name>`
> convention — if your `bitwarden_prep/` directory has a different name, adjust
> `bitwarden_prep_default`/`bitwarden_prep_coverage_shm` to match (check with
> `docker network ls` / `docker volume ls`). `--network` must match so the fuzzer
> container can resolve `api`/`mssql` by service name if needed, though this command
> talks to the API via the host-mapped port through the shared network either way.

For the full security-campaign flag set (multi-identity, sequence tuning, web UI),
add `-p 13377:13377 -v $(pwd)/bitwarden_prep/auth.identities.json:/auth/auth.identities.json:ro`
to the `docker run` line and `-auth-file /auth/auth.identities.json -identity-mode weighted
-identity-include-guest=true -sequence-prob 0.45 -sequence-max-depth 5 -sequence-fanout 8
-race-prob 0.08 -race-burst 3 -web-ui` to the flags — see Step 8b below for the dashboard.

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

### Port mapping

**Mode A (host mode):** no mapping needed — the binary runs directly on your machine, so
`-web-ui-port 13377` (the default) is already `http://localhost:13377`.

**Mode B (Docker sidecar):** add `-p 13377:13377` to the `docker run` command from Step 8:

```bash
docker run --rm -p 13377:13377 \
  --network bitwarden_prep_default \
  -v bitwarden_prep_coverage_shm:/coverage_shm \
  ... \
  void-fuzzer -grammar /grammar -direct-shm -web-ui
```

---

## Step 9: View Results

```bash
# Mode A: the terminal dashboard/log is already in your foreground shell.
# Mode B: docker logs -f <container-id-or-name>  (find it with `docker ps`)

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

### Example findings

Re-verified end-to-end from a **completely fresh clone** on 2026-07-23 (Mode A, host
mode, `-profile security`, single `AUTH_TOKEN`, no auth-file/populated-data yet — see
Step 5/6 for the fuller multi-identity setup): 3 min budget, ~45k requests,
`coverage_end_edges` climbed to ~51,500 (real, nonzero — confirmed via `verify-hook.sh`
in Step 3 first). 107 crashes, 104 unique after dedup: 4 `likely_vuln_high` (severity 9),
12 `confirmed_unhandled_exception`, 82 `needs_review`, 11 `noise`, 2 `target_misconfiguration`.
Exact bugs vary run-to-run (randomized mutation, and richer with a longer time budget /
multi-identity auth file), but the oracle classes below fire reliably run after run:

| Severity | Method | Endpoint | Oracle | Signal |
|---|---|---|---|---|
| **HIGH** (9) | DELETE | `/accounts` | injection | `sqli_time_based` |
| **HIGH** (9) | PUT | `/accounts/verify-devices` | injection | `sqli_time_based` |
| **HIGH** (9) | POST | `/settings/domains` | injection | `ssrf_metadata_reflected` |
| **HIGH** (9) | PUT | `/settings/domains` | injection | `ssrf_metadata_reflected` |

`DELETE /accounts` (sqli_time_based) and `PUT /accounts/verify-devices` (sqli_time_based)
have now reproduced across multiple independent from-scratch runs (2026-07-13 and
2026-07-23) — the strongest of the recurring signals. `/settings/domains` accepting an
SSRF-style URL into `equivalentDomains` and reflecting it back unmodified is a newer
recurring signal as of this run.

Treat time-based SQLi/SSRF oracle hits as **leads, not confirmed vulns** — verify manually via the generated PoC before reporting (see `crash_layer`/`exploitation_signals` in the crash record, and the honest `needs_review` vs `likely_vuln[_high]` classification split above). The point of this run was to confirm the *pipeline* works end-to-end with full, non-hardcoded instrumentation — not to certify these specific findings.

> **This 2026-07-23 pass also found and fixed two real bugs in the fuzzer engine itself**
> (not in Bitwarden): a path-quoting leak that made GUID-shaped path parameters render as
> `/organizations/"<guid>"/...` (guaranteed-malformed URLs, pure noise — was inflating the
> `needs_review`/`noise` counts above with fake "Unrecognized Guid format" clusters), and a
> malformed-bearer-token leak where unauthenticated probes and the `guest` identity sent a
> literal, unresolved `Bearer TOKEN` placeholder instead of true no-credentials, muddying
> the auth-bypass oracle's own signal. Both are fixed as of this doc's revision — if you're
> running an older checkout, `git pull` first. See `ARCHITECTURE_REVIEW.md`'s
> Inconsistencies section for the full writeups.

---

## The same thing, via the `upsidefuzz` CLI

Bitwarden's bring-up is genuinely multi-stage (mssql healthcheck → migrator run-to-completion
→ *then* api/identity) — that dependency chain isn't representable by a single `up` call, so
**Step 3's bring-up stays exactly as documented above** (plain `docker compose` commands).
Steps 2, 3's verify, and 7's grammar compile map onto CLI subcommands; Steps 4-6 (auth token,
identity file, DB population) and Step 7's `sanitize_swagger.py` patch are Bitwarden-specific
helper scripts with no generic CLI equivalent — keep running those exactly as documented,
then hand their output to the CLI subcommands:

```bash
# Native: python3 upsidefuzz.py ...   |   Zero-install (only Docker needed): ./upsidefuzz ...

# Step 2:
upsidefuzz instrument --src ./bitwarden_src --out ./bitwarden_prep --main src/Api

# Step 3's bring-up stays manual (the multi-stage dependency chain above) -- then verify:
upsidefuzz verify --base http://localhost:4000 --probe /api/accounts/profile

# Steps 4-6 (get_apikey.py, auth identity file, DB population) stay manual -- see above.

# Step 7's sanitize_swagger.py patch stays manual too; feed the CLI the already-sanitized file:
upsidefuzz grammar bitwarden_prep/internal_swagger.json --src ./bitwarden_src --out grammars/bitwarden

# Step 8, Mode A (host mode) equivalent:
export $(cat bitwarden_prep/fuzzer.env | xargs)   # loads AUTH_TOKEN
upsidefuzz fuzz --grammar grammars/bitwarden --target http://localhost:4000 \
  --profile security --skip-endpoint-on-500 --time-budget 15 \
  --auth-file bitwarden_prep/auth.identities.json   # if you built one in Step 5

upsidefuzz down --dir ./bitwarden_prep --volumes
```

Mode B (Docker sidecar, direct-shm) has no CLI equivalent yet — `upsidefuzz fuzz` always runs
`void` directly against the target's published port (like Mode A), not as a separate
networked sidecar container reading the shared-memory volume directly. Use the manual Mode B
command in Step 8 above if you specifically want that faster read path. See
[docs/CLI.md](docs/CLI.md) for the full subcommand reference.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| MSSQL takes too long | Use the `until` healthcheck-poll loop in Step 3, not a fixed `sleep` — under Apple Silicon emulation it can genuinely take 90–240 s; check `docker logs bitwarden_prep-mssql-1` if it never becomes healthy |
| `docker compose up migrator` exits non-zero, or `api`/`identity` never start | Migrations failed — read the migrator's own output (it's run in the foreground in Step 3, not detached), fix the underlying issue, then re-run `docker compose -f docker-compose.instrumented.yml up migrator` before bringing up api/identity |
| `edges: 0` after requests | Call `POST /shm/create` first; if still 0, check the build log for `[instrumentor] Done: instrumented=0` |
| Identity service rejects login | Start a dummy SMTP listener inside `bitwarden_prep-identity-1` (see Step 4 note) |
| `get_apikey.py` fails | Check API is on port 4000; check `docker compose logs api` for startup errors |
| Grammar has 0 endpoints | Verify swagger was downloaded with content; re-run sanitize step |
| All writes are 401/403 | Token may have expired; re-run `get_apikey.py` |
| `identity` container exits with `UnauthorizedAccessException`/`DirectoryNotFoundException` writing `/dev/signingkey.jwk` | Unrelated to instrumentation — `ASPNETCORE_ENVIRONMENT=Development` loads `appsettings.Development.json`'s `developmentDirectory: "../../dev"`, which resolves to the literal `/dev` inside the container. Add `globalSettings__developmentDirectory: "/tmp"` to the `identity` service's environment (already included in the compose file above). |
| `get_apikey.py` registration step logs a 500 with `MailKit...Connection refused` | Expected without a real SMTP server — the welcome email fails to send, but the user is still created and the OAuth token request right after still succeeds. Not a failure; ignore unless `Generated Token:` is also missing. |
| Rebuilding after a fresh `bitwarden_src` clone and the API build fails to find `Api.dll`/`Core.dll`/etc. to instrument (`skipped` on every DLL) | Your `fuzz-prep-multi.py` predates the `PublishSingleFile`-stripping and multi-line `-o`-detection fixes (2026-07-22). Pull latest and regenerate — the tool now prints `Detected PublishSingleFile=true — disabled...` and the instrumentation RUN commands should reference the real publish dir (e.g. `out/Api.dll`, not a guessed `/app/publish/Api.dll`). |
| Api build fails with `MSBUILD : error MSB1003: Specify a project or solution file` | `bitwarden_src` (or your `--src`) is missing a `.sln`/`.slnx` at the root — `dotnet restore`/`build` inside the generated Dockerfile need one to auto-discover the multi-project solution. A real `git clone` of `bitwarden/server` already has one; this only bites custom/stripped-down checkouts. |
| Api build fails with `CS8802: Only one compilation unit can have top-level statements` | Only relevant if you're instrumenting a *different*, flat (non-nested) single-project target, not Bitwarden itself — see `fixtures/planted-bug-api/README.md` for the full explanation if you hit this on a custom target. |
| Lots of `needs_review`/`noise` crashes with "Unrecognized Guid format" and a literal `"` inside the path (e.g. `/organizations/"CIP-0042"/delete`) | Fixed 2026-07-23 (`grammarc/body_serializer.py`'s path/query/header segments were reusing the JSON-body quoting logic). `git pull` and regenerate the grammar (Step 7) if you still see this. |
| A large fraction of API log lines show `SecurityTokenMalformedException: IDX14100: JWT is not well formed` | Fixed 2026-07-23 (`worker.go` was leaving the grammar's literal `Bearer TOKEN` placeholder on unauthenticated/guest-identity requests instead of removing it). `git pull` and rebuild the fuzzer binary/image if you still see this. |
| Fuzzer exits immediately with `run failed: coverage instrumentation degraded: ...` | Added 2026-07-23 (Top-20 #4) — the engine now sends a real warm-up probe at startup and refuses to run if the coverage bitmap doesn't move. This means instrumentation is genuinely broken (not a false alarm): re-check Step 3's `verify-hook.sh` output, confirm `api`/`identity` were rebuilt from the latest `fuzz-prep-multi.py`, and don't just pass `-allow-degraded-coverage` — that run would complete but find nothing. |

---

**→ [Back to README](README.md) · [Full Runbook](INSTRUCTIONS.md) · [Authentication Guide](docs/FUZZER_AUTHENTICATION.md) · [Architecture](ARCHITECTURE.md)**
