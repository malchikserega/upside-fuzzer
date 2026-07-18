# Bitwarden Fuzzing Runbook (UpsideFuzz)

End-to-end procedure to stand up an instrumented Bitwarden and run the fuzzer,
including every gotcha discovered during setup. **Work in the existing
`bitwarden_prep/` directory** — it is the correctly-wired instrumented copy.

> Do NOT regenerate Bitwarden with `fuzz-prep-multi.py`: the auto-generator
> mis-detects the main project (writes `CoverageExtensions.cs` into Scim, not Api)
> and targets `Program.cs` instead of Bitwarden's `Startup.cs`, so coverage ends
> up unwired. The hand-crafted `bitwarden_prep/` already has it correct.

All commands below are run from `bitwarden_prep/` unless noted. `restler_output/`,
`grammars/`, `void/`, `compile-grammar.sh` live in the **repo root** (one level up).

---

## 0. Prerequisites

- Docker Desktop (allocate **≥ 4 GB** RAM — SQL Server needs ~2 GB, more under emulation).
- .NET SDK 8/10, Python 3, `curl`, `jq` (optional).
- On **Apple Silicon**: the MSSQL image runs under x86 emulation — slower startup and lower throughput are expected.

---

## 1. Bring up the stand (correct order matters)

```bash
cd bitwarden_prep

# 1a. Database first
docker compose -f docker-compose.instrumented.yml up -d mssql
watch docker compose -f docker-compose.instrumented.yml ps      # wait for mssql = healthy

# 1b. Run migrations — CREATES the vault_fuzz database (skipping this = "Cannot open database" errors)
docker compose -f docker-compose.instrumented.yml up --build migrator
docker compose -f docker-compose.instrumented.yml logs migrator | tail

# 1c. API + identity
docker compose -f docker-compose.instrumented.yml up -d --build identity api
docker compose -f docker-compose.instrumented.yml logs -f api    # confirm no startup crash; Ctrl-C
```

**mssql stuck `(unhealthy)`?** Under Apple Silicon emulation SQL Server can take
minutes to boot. The healthcheck already has `start_period: 240s`. Verify the DB is
actually alive:

```bash
docker exec bitwarden_prep-mssql-1 /opt/mssql-tools18/bin/sqlcmd \
  -S localhost -U SA -P "FuzzP@ssw0rd123!" -Q "SELECT 1" -C -b
```

If `SELECT 1` returns `1`, it is just timing — wait for healthy. If it errors with
`Insufficient memory`, raise Docker Desktop RAM to ≥ 4 GB.

---

## 2. Verify coverage (mandatory — catches silently-broken instrumentation)

```bash
chmod +x verify_coverage.sh && ./verify_coverage.sh
# → OK: coverage is active (edges=N)
```

The reliable signal is `/shm/coverage` (edges > 0). A missing per-response
`X-Coverage-*` header on a fast endpoint like `/alive` is normal (ASP.NET starts the
response before the middleware's finally) — the fuzzer falls back to SHM polling.

Manual equivalent:
```bash
curl -s -X POST http://localhost:4000/shm/create
curl -s http://localhost:4000/shm/coverage      # {"edges":N,...}
```

If `edges=0`: check the api build log for `[instrumentor] Done: instrumented=0`, then
rebuild with `docker compose ... build --no-cache api`.

---

## 3. Create two users + auth file (needed for real BOLA)

```bash
: > fuzzer.env                                   # drop stale creds (avoids a 401-spamming "default" identity)
python3 make_bola_identities.py                  # user-a, user-b, guest -> auth.identities.json
python3 populate_data.py --auth-file auth.identities.json
```

BOLA needs **two distinct authenticated users** plus the guest. Populating data means
responses aren't empty — without real objects the BOLA oracle produces false positives
on identical empty bodies.

---

## 4. Compile the grammar (only if `grammars/bitwarden/` lacks it)

```bash
# Need: ../grammars/bitwarden/{grammar.py,dict.json,templates.export.json}
curl -s http://localhost:4000/specs/internal/swagger.json -o swagger.json
python3 sanitize_swagger.py swagger.json
../compile-grammar.sh swagger.json --dict ../grammars/bitwarden/dict.json --src ./src

# Output lands in the REPO ROOT restler_output/ — note the ../
cp ../restler_output/Compile/grammar.py ../restler_output/Compile/dict.json ../grammars/bitwarden/
python3 ../void/export-templates.py --grammar-dir ../grammars/bitwarden --out ../grammars/bitwarden/templates.export.json

ls -la ../grammars/bitwarden/                    # grammar.py, dict.json, templates.export.json
```

---

## 5. Build only the fuzzer and run

```bash
# Build ONLY the fuzzer image (void engine) — does not rebuild Bitwarden
docker compose -f docker-compose.instrumented.yml build smartfuzzer
```

### Run with WebUI (browser dashboard at http://localhost:13377)

```bash
docker compose -f docker-compose.instrumented.yml --profile fuzz run --rm --no-deps \
  -p 13377:13377 \
  -v "$PWD/auth.identities.json:/auth/auth.identities.json:ro" \
  smartfuzzer \
  -grammar /grammar -profile security \
  -auth-file /auth/auth.identities.json \
  -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode file \
  -skip-endpoint-on-500 \
  -web-ui -web-ui-port 13377 -no-ui -time-budget 20
```

### Run with terminal dashboard

```bash
docker compose -f docker-compose.instrumented.yml --profile fuzz run --rm --no-deps -it \
  -v "$PWD/auth.identities.json:/auth/auth.identities.json:ro" \
  smartfuzzer \
  -grammar /grammar -profile security \
  -auth-file /auth/auth.identities.json \
  -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode file \
  -skip-endpoint-on-500 \
  -time-budget 20
```

`--no-deps` = don't touch the already-running stand. `-profile security` enables the
oracles (BOLA/auth-bypass/mass-assign/injection) + multi-identity + guest.

To push raw throughput for a test: add `-concurrency 32 -max-concurrency 128`.

---

## 6. Results

```bash
ls -t ../crashes/unique-crashes-*.jsonl | head -1
```

What to look for in `unique-crashes-*.jsonl` / the final report:
- `distinct_root_causes` + `root_cause_clusters` — many raw signatures collapsed to a few real bugs.
- records with `"access_control": true`, `origin_identity` → `shadow_identity` — BOLA / auth-bypass.
- `mass_assignment_privileged_field_accepted` — mass assignment.
- classifications: `likely_vuln[_high]` (real exploitation signal) vs `confirmed_unhandled_exception` (robustness 500) vs `target_misconfiguration` (excluded) vs `needs_review`.

---

## 7. Iterating on the engine only

When you change Go code, rebuild just the fuzzer — never the stand:

```bash
# locally first (no Go toolchain in the sandbox):
( cd ../void/go && go test ./... )
# then:
docker compose -f docker-compose.instrumented.yml build smartfuzzer
docker compose -f docker-compose.instrumented.yml --profile fuzz run --rm --no-deps smartfuzzer <flags>
```

---

## Troubleshooting cheat-sheet

| Symptom | Cause / Fix |
|---|---|
| `Cannot open database "vault_fuzz" ... Login failed` (in make_bola_identities / api) | Migrations didn't run. Bring up `migrator` (step 1b) before api. |
| `mssql ... (unhealthy)` forever | Slow emulated boot. `start_period: 240s` is set; wait, verify with `SELECT 1`, raise Docker RAM to ≥ 4 GB. |
| `System.AccessViolationException` at `Bit.Api.Program+<>c..cctor` on api start | `--instrument-all-user-code` instruments entry-point static-init types whose probes fire before SHM is bound. Bitwarden uses the `namespaces.json` allowlist instead (already reverted in `Dockerfile.instrumented`). |
| RESTler: `Cannot deserialize mutations dictionary ... Unexpected token: StartArray` | `restler_custom_payload_uuid4_suffix` values must be single strings, not arrays. Fixed in `compile-grammar.sh` (final `uniq()` no longer splits the string). |
| `cp restler_output/... No such file` | `restler_output/` is in the repo root — use `../restler_output/...` from `bitwarden_prep`. |
| `export-templates.py: error: required: --grammar-dir, --out` | Use named args + a directory: `--grammar-dir ../grammars/bitwarden --out .../templates.export.json`. |
| `verify_coverage.sh` FAIL: no X-Coverage headers | Expected on fast endpoints — check `/shm/coverage` edges instead (the script now does). |
| Secrets Manager endpoints all 500 (`Unable to resolve service for type 'Bit.Commercial...'`) | Commercial SM DI is not wired in this build; not a Bitwarden bug. Tagged `target_misconfiguration` and excluded from the vuln count. `-skip-endpoint-on-500` stops the spam. |
| ~100 req/s (lower than before) | Not a regression: with real auth + populated data, requests execute real DB logic (slow under emulated SQL) instead of failing fast on 500s. Deeper, not worse. |

---

## Why not re-run `fuzz-prep-multi.py` for Bitwarden

`fuzz-prep-multi.py` targets conventional single-entry ASP.NET apps. For Bitwarden's
multi-project + `Startup.cs` layout it (a) picks the wrong main project and writes the
coverage helper into Scim, and (b) injects into `Program.cs` which Bitwarden doesn't use
for the pipeline. The `bitwarden_prep/` tree is the hand-wired, working setup — keep using it.
