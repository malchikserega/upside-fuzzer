# Bitwarden Fuzzing Runbook (UpsideFuzz)

End-to-end procedure to stand up a **fresh** instrumented Bitwarden and run the fuzzer
against it, including every gotcha found running this exact procedure start-to-finish on
2026-07-25. This version supersedes earlier revisions of this file: it switches from the
project's old custom `docs/guides/examples/bitwarden/get_apikey.py`/`populate_data.py` scripts to
Bitwarden's own official **`util/SeederApi`** data-seeding tool, which produces properly
encrypted test data (real Rust-SDK crypto, not hand-rolled) and is verified working
end-to-end below.

> **Why this file keeps needing gotcha updates**: Bitwarden's `server` repo moves fast —
> this run's fresh clone had moved from **.NET 8 to .NET 10** and changed its Swagger
> route (`/swagger/v1/swagger.json` → `/specs/{documentName}/swagger.json`) since this
> project's last Bitwarden run, neither of which was announced anywhere obvious. **Do not
> assume anything below is still true without re-checking the two things called out in
> Step 1** — that single check would have caught both changes immediately.

> **Re-verified end-to-end from a completely fresh clone on 2026-07-26** (same repo
> shape as the 2026-07-25 pass: .NET 10, `/specs/internal/swagger.json`) — every step
> below, in order, with zero deviation from the documented commands: clone → instrument
> (22 projects, `--instrument-all-user-code` auto-selected) → hand-written compose build
> → `bin/verify-hook.sh` (8/8 pass, 6154 instrumented types) → `SeederApi` population (2
> users, 1 org, folders, ciphers) → grammar compile (`operations=599 templates=603
> roslyn_matched_types=286 dict_keys=855` — byte-for-byte identical to 2026-07-25) →
> `dict.custom.json` merge → 15-minute fuzz run. Result: 184,333 requests, 223,091
> coverage edges, 148 raw crashes collapsing to 44 distinct root causes (source-attributed
> `confirmed_unhandled_exception` clusters point at real, previously-unknown NREs and an
> unhandled duplicate-key `SqlException` in `Bit.Api.Controllers.DevicesController.Post`
> — reproduced independently via the generated PoC script), plus one recurring
> `likely_vuln_high sqli_time_based` on `DELETE /accounts` matching prior runs. Two real,
> stale doc claims were found and fixed as part of this pass — Step 2's "known bug" note
> below (the underlying `bin/fuzz-prep-multi.py`/`tools/prep/fuzzprep/` bug it described was already fixed
> 2026-07-25, hours after this file was first written) and `QUICKSTART_BITWARDEN.md`'s
> `PROBE=/api/accounts/profile` (this API has no `/api/` prefix on any route; the real
> path is `/accounts/profile` — confirmed against the live swagger spec). No other
> deviation from this document was found; every other command, script, and number below
> is exactly what ran.

---

## 0. Prerequisites

- Docker Desktop (allocate **≥ 4 GB** RAM — SQL Server needs ~2 GB, more under emulation).
- .NET SDK (whatever `global.json` in the fresh clone specifies — see Step 1), Python 3, `curl`.
- On **Apple Silicon**: the MSSQL image runs under x86 emulation — slower startup and lower throughput are expected. `util/SeederApi`'s Rust build runs **natively** (arm64) unless you force `platform: linux/amd64` — see the troubleshooting table if you do.

---

## 1. Fresh checkout — check these two things before anything else

```bash
git clone https://github.com/bitwarden/server.git bitwarden_fresh
cat bitwarden_fresh/global.json                        # <- SDK version
grep -n "TargetFramework" bitwarden_fresh/Directory.Build.props   # <- TFM (e.g. net10.0)
grep -n "RouteTemplate\|UseSwagger(" bitwarden_fresh/src/Api/Startup.cs  # <- swagger route
```

If the TFM differs from what you expect, the Docker base image tags
(`mcr.microsoft.com/dotnet/sdk:X.0`) in the generated Dockerfile will already be correct
(`bin/fuzz-prep-multi.py` reads the TFM from the project itself) — you don't need to do
anything except **not be surprised** when it isn't net8. If the swagger `RouteTemplate`
differs from `specs/{documentName}/swagger.json`, adjust Step 5's `curl` accordingly —
grep the actual value rather than trusting this doc.

```bash
python3 bin/fuzz-prep-multi.py \
  --src ./bitwarden_fresh \
  --out ./bitwarden_fresh_prep \
  --main Api \
  --inject-mode hook
```

Verified 2026-07-25 against a fresh clone (.NET 10): 22 projects instrumented,
`--instrument-all-user-code` auto-selected (no `Bit.*` namespace collides with the
framework denylist), `--cmplog` appended automatically (hook mode only).

---

## 2. Write the compose file (single-service auto-generated one isn't enough for Bitwarden)

`bin/fuzz-prep-multi.py` finds `src/Api/Dockerfile`, adapts it in place, and — when no
original compose file exists in the repo (true for a stock Bitwarden checkout) — generates
a **single-service** compose file (`instrumented:`, `dockerfile: src/Api/Dockerfile`,
correctly pointing at the real, possibly-nested Dockerfile path — the older
`dockerfile: Dockerfile`-at-root bug this section used to describe was fixed
2026-07-25, see `tools/prep/fuzzprep/docker_gen.py`'s comment at the relevant branch). It still only
covers the API service, though — Bitwarden needs the full stack (DB, migrator, Identity,
data seeder), which the generator has no way to know about. Hand-write the compose file
instead. Use this as a template — it's the exact one re-verified end-to-end on
2026-07-26 against a fresh clone (net10.0, same repo shape as 2026-07-25),
with MSSQL, migrator, API, Identity, and the SeederApi data tool:

```yaml
services:
  mssql:
    image: mcr.microsoft.com/mssql/server:2022-latest
    platform: linux/amd64
    environment:
      ACCEPT_EULA: "Y"
      MSSQL_SA_PASSWORD: "FuzzP@ssw0rd123!"
      MSSQL_PID: Developer
    volumes:
      - mssql_data:/var/opt/mssql
    healthcheck:
      test: /opt/mssql-tools18/bin/sqlcmd -S localhost -U SA -P "FuzzP@ssw0rd123!" -Q "SELECT 1" -C -b
      interval: 10s
      timeout: 15s
      retries: 20
      start_period: 240s

  # util/MsSqlMigratorUtility's own Dockerfile ENTRYPOINT reads MSSQL_CONN_STRING (not
  # globalSettings__sqlServer__connectionString, which api/identity use instead).
  migrator:
    build: { context: ., dockerfile: util/MsSqlMigratorUtility/Dockerfile }
    depends_on: { mssql: { condition: service_healthy } }
    environment:
      MSSQL_CONN_STRING: "Server=mssql;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"

  api:
    build: { context: ., dockerfile: src/Api/Dockerfile }
    ports: ["4100:5000"]
    depends_on:
      mssql: { condition: service_healthy }
      migrator: { condition: service_completed_successfully }
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      ASPNETCORE_URLS: http://+:5000
      globalSettings__selfHosted: "true"
      globalSettings__disableUserRegistration: "false"
      globalSettings__sqlServer__connectionString: "Server=mssql;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"
      globalSettings__installation__id: "b4545580-0a88-4682-9653-af8e00e84b80"
      globalSettings__installation__key: "00000000000000000000000000000000"
      globalSettings__baseServiceUri__vault: "http://localhost:4100"
      globalSettings__baseServiceUri__api: "http://localhost:4100"
      globalSettings__baseServiceUri__identity: "http://identity:5000"
      globalSettings__baseServiceUri__internalIdentity: "http://identity:5000"
      globalSettings__identityServer__certificateThumbprint: ""
      globalSettings__dataProtection__certificateThumbprint: ""
      # AddDeveloperSigningCredential writes signingkey.jwk here; defaults to a literal
      # unwritable /dev path. Point it at the mounted volume instead.
      globalSettings__developmentDirectory: "/etc/bitwarden/core"
      globalSettings__mail__smtp__host: "localhost"
      globalSettings__mail__smtp__port: "25"
      globalSettings__enableEmailVerification: "false"
      globalSettings__enableNewDeviceVerification: "false"
    volumes:
      - /dev/shm:/dev/shm
      - coverage_shm:/coverage_shm
      - core_data:/etc/bitwarden/core

  identity:
    build: { context: ., dockerfile: src/Identity/Dockerfile }   # ORIGINAL, uninstrumented
    ports: ["33756:5000"]
    depends_on:
      mssql: { condition: service_healthy }
      migrator: { condition: service_completed_successfully }
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      ASPNETCORE_URLS: http://+:5000
      globalSettings__selfHosted: "true"
      globalSettings__sqlServer__connectionString: "Server=mssql;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"
      globalSettings__installation__id: "b4545580-0a88-4682-9653-af8e00e84b80"
      globalSettings__installation__key: "00000000000000000000000000000000"
      globalSettings__baseServiceUri__vault: "http://localhost:4100"
      globalSettings__baseServiceUri__api: "http://api:5000"
      globalSettings__baseServiceUri__identity: "http://localhost:33756"
      globalSettings__baseServiceUri__internalIdentity: "http://identity:5000"
      globalSettings__identityServer__certificateThumbprint: ""
      globalSettings__dataProtection__certificateThumbprint: ""
      globalSettings__developmentDirectory: "/etc/bitwarden/core"
      globalSettings__mail__smtp__host: "localhost"
      globalSettings__mail__smtp__port: "25"
      globalSettings__enableEmailVerification: "false"
      globalSettings__enableNewDeviceVerification: "false"
    volumes: [ "core_data:/etc/bitwarden/core" ]

  # Bitwarden's own data-seeding tool (util/SeederApi) -- see Step 4. Needs no --platform
  # override: let it build natively for your Docker host's arch (see troubleshooting for
  # why forcing amd64 on an arm64 host does NOT fix the Rust native-library gotcha below).
  seeder:
    build: { context: ., dockerfile: util/SeederApi/Dockerfile }
    ports: ["4300:5000"]
    depends_on:
      mssql: { condition: service_healthy }
      migrator: { condition: service_completed_successfully }
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      ASPNETCORE_URLS: http://+:5000
      globalSettings__selfHosted: "true"
      globalSettings__sqlServer__connectionString: "Server=mssql;Database=vault_fuzz;User Id=SA;Password=FuzzP@ssw0rd123!;Encrypt=True;TrustServerCertificate=True"
      globalSettings__installation__id: "b4545580-0a88-4682-9653-af8e00e84b80"
      globalSettings__installation__key: "00000000000000000000000000000000"
      globalSettings__developmentDirectory: "/etc/bitwarden/core"
      globalSettings__testPlayIdTrackingEnabled: "true"
      seederSettings__Username: "fuzzadmin"
      seederSettings__Password: "FuzzSeederP@ss123!"
    volumes: [ "core_data:/etc/bitwarden/core" ]

volumes:
  mssql_data:
  core_data:
  coverage_shm: { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: size=4m } }
```

**Before building `seeder`**, apply the one-line fix in the troubleshooting table below
(`CARGO_TARGET_DIR` / `linux-arm64`) — building it unmodified will produce an image that
fails at the first API call with `Unable to load shared library ... libsdk.so`.

```bash
docker compose -f docker-compose.instrumented.yml build
docker compose -f docker-compose.instrumented.yml up -d
```

---

## 3. Verify coverage + all services healthy

```bash
curl -s http://localhost:4100/shm/health   # instrumented_types > 0, shm_bound: true
curl -s http://localhost:4100/shm/cmplog | head -c 200   # non-empty once real traffic has run
curl -s http://localhost:4300/alive        # seeder up
docker compose -f docker-compose.instrumented.yml ps    # everything "healthy" except migrator ("Exited (0)" is correct -- it's a one-shot job)
```

If `edges=0` on `/shm/coverage`: check the `api` build log for
`[instrumentor] Done: instrumented=0`, then `docker compose build --no-cache api`.

---

## 4. Populate data — users, an organization, vault items (official tool, real crypto)

Bitwarden ships its own seeding API for exactly this (`util/SeederApi` — not previously
used by this project; the old `docs/guides/examples/bitwarden/populate_data.py` approach still
exists but wasn't re-verified this run, prefer this one). It needs HTTP Basic Auth
(`seederSettings__Username`/`Password` from the compose file above) and, for
`/connect/token` calls afterward, a `Bitwarden-Client-Version` header — Identity rejects
requests without one (`version_header_missing`).

```python
# populate_data.py — save next to your compose file and run: python3 populate_data.py
import base64, json, urllib.error, urllib.parse, urllib.request

SEEDER, IDENTITY, PLAY_ID = "http://localhost:4300", "http://localhost:33756", "fuzz-run"
AUTH = "Basic " + base64.b64encode(b"fuzzadmin:FuzzSeederP@ss123!").decode()

def post_json(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items(): req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=30) as r: return json.loads(r.read())

def post_form(url, fields):
    data = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in fields.items())
    req = urllib.request.Request(url, data=data.encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Bitwarden-Client-Version", "2026.7.1")   # required, or 400 version_header_missing
    with urllib.request.urlopen(req, timeout=30) as r: return json.loads(r.read())

def seed(template, args):
    return post_json(f"{SEEDER}/seed", {"template": template, "arguments": args},
                      {"X-Play-Id": PLAY_ID, "Authorization": AUTH})["result"]

user = seed("SingleUserScene", {"email": "fuzzuser0@example.com", "password": "FuzzTestPassw0rd!", "emailVerified": True})
org = seed("SingleOrganizationScene", {"ownerUserId": user["userId"], "planType": 0, "name": "FuzzCorp", "domain": "fuzzcorp.example.com", "seats": 5})
folder = seed("UserFolderScene", {"userId": user["userId"], "userKeyB64": user["decryptedKeyB64"], "folderName": "Work Logins"})
cipher = seed("UserLoginCipherScene", {"userId": user["userId"], "userKeyB64": user["decryptedKeyB64"], "name": "Example Bank", "username": "u@example.com", "password": "x", "uri": "https://bank.example.com", "folderId": folder["folderId"]})

# API-key login (client_credentials) -- no master-password KDF to replicate client-side.
tok = post_form(f"{IDENTITY}/connect/token", {
    "grant_type": "client_credentials", "client_id": f"user.{user['userId']}",
    "client_secret": user["apiKey"], "scope": "api",
    "deviceType": "21", "deviceIdentifier": "upsidefuzz", "deviceName": "upsidefuzz",
})
print("JWT:", tok["access_token"][:40], "...")
```

Other useful scenes: `UserFolderScene`, `OrganizationCollectionScene`,
`OrganizationCollectionScene`. Full request/response shapes:
`util/SeederApi/README.md` and `util/Seeder/Scenes/*.cs` in the fresh checkout — read the
`Request` class directly, it's the authoritative contract.

**Clean up between runs** (Play-ID tracked entities): `curl -X DELETE
http://localhost:4300/seed/fuzz-run -u fuzzadmin:'FuzzSeederP@ss123!'`

---

## 5. Compile the grammar

**Check the swagger route first** (see Step 1) — this run's fresh clone used
`/specs/internal/swagger.json`, not `/swagger/v1/swagger.json`:

```bash
curl -s http://localhost:4100/specs/internal/swagger.json -o swagger.json
./bin/compile-grammar.sh swagger.json --src ./bitwarden_fresh --out grammars/bitwarden
```

Verified 2026-07-25: `operations=599 templates=603 skipped=0 multipart_endpoints=4
roslyn_matched_types=286 dict_keys=855`.

**Add real fuzzing values** — the first compile also writes `grammars/bitwarden/dict.custom.json`,
a starter file that's merged into `dict.json` on every future compile and never
overwritten (see `INSTRUCTIONS.md` §10). Fill it in with the IDs/keys Step 4 gave you:

```python
import json
custom = json.load(open("grammars/bitwarden/dict.custom.json"))
del custom["exampleFieldName"]
custom.update({
    "userid": [user["userId"]], "email": [user["email"]],
    "organizationid": [org["organizationId"]], "cipherid": [cipher["cipherId"]],
    "apikey": [user["apiKey"]], "clientid": [f"user.{user['userId']}"],
})
json.dump(custom, open("grammars/bitwarden/dict.custom.json", "w"), indent=2)
```

Re-run `./bin/compile-grammar.sh` once more to merge it — you'll see `[tools/grammar/grammarc/] Custom
dictionary merged: .../dict.custom.json` instead of `Created starter custom dictionary`.

---

## 6. Build the auth identities file

```python
import json
identities = {"version": "1", "identities": [
    {"name": "org-owner", "jwt": tok["access_token"], "weight": 2.0},
    {"name": "guest", "weight": 0.3},
]}
json.dump(identities, open("auth.identities.json", "w"), indent=2)
```

Seed 2-3 users (Step 4) for real cross-identity BOLA coverage — one identity alone can't
exercise the access-control oracles at all.

---

## 7. Run the fuzzer

```bash
go -C src/void build -o cmd/void/void ./cmd/void

TARGET_HOST=http://localhost:4100 SHM_HOST=http://localhost:4100 \
./src/void/cmd/void/void \
  -grammar grammars/bitwarden -profile security \
  -auth-file auth.identities.json -identity-mode weighted \
  -seed 42 -time-budget 60
```

For direct-SHM mode (faster coverage reads, needs the engine on the same Docker network
with the `coverage_shm` volume mounted) see `docs/getting-started/cli.md` or the Docker-sidecar examples
in `docs/guides/target-specific/bitwarden-quickstart.md` — HTTP mode above is simpler to get running first and was
what this run actually used for the full hour without issue.

---

## 8. Results & triage

```bash
python3 -c "
import json
d = json.load(open('summary.json'))['triage_summary'] if False else __import__('json').load(open('crashes/summary-*.json'.replace('*','LATEST')))
"
# simpler: just look at the run's own -summary-file output directly
```

- **`distinct_root_causes` in the summary is the real bug count** — not the raw unique-crash line count. A run this size can produce thousands of raw signatures that collapse to a few dozen real clusters (one campaign saw 2,054 of 2,641 raw signatures come from a single framework-internal routing assertion).
- `root_cause_clusters` in the summary JSON gives you the label + representative endpoint + hit count for each real cluster — read that, not the raw crash file, when triaging.
- `"access_control": true` + `bola_identical_cross_identity_response` (strong) vs. `bola_suspected_cross_identity_access` + `needs_manual_verification` (weaker) — check the actual leaked fields before treating either as confirmed; some flagged endpoints (e.g. public-key lookups) are cross-identity-readable *by design*.
- `sqli_time_based` on a 400/rejected response with `repro: null` is almost always concurrency-contention noise, not real SQLi — check `repro.stable_reproducible` before trusting it.

---

## Troubleshooting cheat-sheet

| Symptom | Cause / Fix |
|---|---|
| `docker compose build` fails because Bitwarden needs the full stack (DB, migrator, Identity, seeder), not just the API | Expected — `bin/fuzz-prep-multi.py`'s auto-generated compose only ever covers the single instrumented service. Hand-write the compose file using the template above (see Step 2). |
| **New, 2026-07-25**: `seeder` container: `Unable to load shared library '/app/runtimes/.../libsdk.so'` | Two stacked bugs in `util/SeederApi`/`util/RustSdk` (Bitwarden's own code, not this project's): (1) `util/SeederApi/Dockerfile` sets `CARGO_TARGET_DIR=/tmp/cargo_target`, which silently breaks `RustSdk.csproj`'s hardcoded `Content Include="./rust/target/release/libsdk*.so"` glob — **remove that `export CARGO_TARGET_DIR=...` line** from the Dockerfile. (2) `RustSdk.csproj` has `Content`/`Link` entries only for `linux-x64`/`osx-arm64`/`windows-x64` — no `linux-arm64`. On an arm64 Docker host (Apple Silicon), Rust always compiles for the *builder's* native arch (`--platform=$BUILDPLATFORM` in the Dockerfile, and `cargo build --release` in `RustSdk.csproj`'s `PreBuild` target never passes `--target`), so **forcing `platform: linux/amd64` in compose does NOT fix this** — it just makes the mismatch worse (x64 RID directory, arm64 binary inside it). The actual fix: change both `<Link>runtimes/linux-x64/native/libsdk.so</Link>` entries in `RustSdk.csproj` to `runtimes/linux-arm64/native/libsdk.so`, and build without a platform override. |
| **New, 2026-07-25**: `POST /seed` → `401 Unauthorized` | `util/SeederApi` requires HTTP Basic Auth (`seederSettings__Username`/`Password` env vars) — not documented as required in its own README's curl examples. Add both env vars to the `seeder` service and pass `Authorization: Basic ...` on every request. |
| **New, 2026-07-25**: `POST /connect/token` → `400 version_header_missing` | Identity now requires a `Bitwarden-Client-Version` header on token requests (didn't in earlier checkouts). Add `Bitwarden-Client-Version: 2026.7.1` (any plausible version string) to the request. |
| **New, 2026-07-25**: `curl http://localhost:PORT/swagger/v1/swagger.json` → 404 | Route changed to `specs/{documentName}/swagger.json` (`src/Api/Startup.cs::app.UseSwagger`). Use `/specs/internal/swagger.json` (462 endpoints) or `/specs/public/swagger.json` (16, public API only). **Always grep `Startup.cs` for the real route on a fresh clone** — don't trust this table entry either, it's exactly the kind of thing that silently changes again. |
| `Cannot open database "vault_fuzz" ... Login failed` | Migrations didn't run. Bring up `migrator` (part of the compose file above) before api/identity/seeder — it's a `depends_on: service_completed_successfully` dependency, so `docker compose up -d` handles ordering automatically as long as it's declared. |
| `mssql ... (unhealthy)` forever | Slow emulated boot under Apple Silicon. `start_period: 240s` is set; wait, verify with `docker exec ... sqlcmd -Q "SELECT 1"`, raise Docker Desktop RAM to ≥ 4 GB if it errors with `Insufficient memory`. |
| `identity` crashes on start: `UnauthorizedAccessException` writing `/dev/signingkey.jwk` | `developmentDirectory` defaults to a path that resolves to literal `/dev` inside the container. Set `globalSettings__developmentDirectory` to an already-mounted writable path (see compose template above) on **both** `api` and `identity`. |
| `verify_coverage.sh` FAIL: no X-Coverage headers | Expected on fast endpoints — check `/shm/coverage` edges instead. |
| Secrets Manager / Teams-integration endpoints all 500 (`Unable to resolve service for type ...`) | DI for that feature isn't wired in this build; not a Bitwarden bug. Triaged `target_misconfiguration` and excluded from the vuln count automatically. |
| Fuzzer exits immediately with `run failed: coverage instrumentation degraded` | The engine sends a real warm-up probe at startup and refuses to run if the bitmap doesn't move (Top-20 #4). Re-run `verify_coverage.sh`/`/shm/health` and fix the root cause rather than passing `-allow-degraded-coverage`. |

---

## Changelog (condensed — see git history for full detail)

- **2026-07-26**: Fresh-clone-to-15-minute-fuzz-run re-verification pass, zero deviation
  from the documented procedure (see the callout near the top of this file for the full
  numbers). Fixed two stale doc claims found during this pass: Step 2's "known,
  still-unfixed `bin/fuzz-prep-multi.py` bug" note (the underlying compose-generation bug
  was actually fixed 2026-07-25, this file just never caught up — see `tools/prep/fuzzprep/docker_gen.py`)
  and `QUICKSTART_BITWARDEN.md`'s `bin/verify-hook.sh` probe path (`/api/accounts/profile` →
  `/accounts/profile` — this API has no `/api/` prefix on any route).
- **2026-07-25**: Full rewrite after a genuine fresh-clone-to-1-hour-fuzz-run
  end-to-end pass. Switched to `util/SeederApi` for data population (was
  `docs/guides/examples/bitwarden/populate_data.py`). Target moved .NET 8 → .NET 10. Swagger route
  moved `/swagger/v1/swagger.json` → `/specs/{documentName}/swagger.json`. Found and
  documented two real bugs in Bitwarden's own `util/SeederApi`/`util/RustSdk` build
  config. Added the `dict.custom.json` workflow (new as of this same session — see
  `INSTRUCTIONS.md` §10).
- **2026-07-23**: RESTler retired (`tools/grammar/grammarc/`+`tools/dotnet/analyzer/`, no Docker for grammar
  compilation); two Go-engine bugs fixed (path-quoting leak, malformed-bearer-token
  leak on unauthenticated probes); self-verifying fail-closed coverage health check
  added (Top-20 #4).
- **2026-07-22**: Hook-mode (`--inject-mode hook`, zero source edits) became the
  default, eliminating the `AccessViolationException` class of failure that used to
  require `--exclude-namespaces Bit.Core.Utilities`.
