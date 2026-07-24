# Bitwarden Fuzzing Runbook (UpsideFuzz)

End-to-end procedure to stand up an instrumented Bitwarden and run the fuzzer,
including every gotcha discovered during setup. **Work in the existing
`bitwarden_prep/` directory** — it is the correctly-wired instrumented copy.

> **No `bitwarden_prep/` yet, or want a guaranteed-fresh setup?** Use
> [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md) instead — it walks through cloning,
> instrumenting, and standing everything up from scratch, with the same current commands.
> Come back to *this* runbook once you have a working checkout and want to iterate,
> re-run, or troubleshoot without redoing setup from zero.

> **Note on regenerating:** `fuzz-prep-multi.py --src ./bitwarden_src --out ./bitwarden_prep --main src/Api` regenerates cleanly with **no `--exclude-namespaces` needed** — re-verified 2026-07-22 end-to-end from a fresh `bitwarden/server` clone. Two things changed since this runbook was first written: (1) hook-mode (`--inject-mode hook`, the default) binds the SHM pointer via `DOTNET_STARTUP_HOOKS` *before* `Main` runs, which eliminates the `AccessViolationException` class of failure that used to require excluding `Bit.Core.Utilities` — that flag is now legacy/optional, not required; (2) since no root namespace in Bitwarden's own code (`Bit.*`) collides with the hardcoded framework-prefix denylist, the tool now auto-selects `--instrument-all-user-code` over the namespace-allowlist path, which is strictly more complete (no `BUSINESS_PATTERNS`-naming-convention gaps — confirmed `skipped_no_match=0` on every instrumented DLL, vs. hundreds per DLL under the old allowlist path). The script only generates a basic single-service `docker-compose` file; for the full Bitwarden stack (MSSQL, Identity, Migrator) you still need a hand-written compose — see `docker-compose.instrumented.yml` in `bitwarden_prep/`, or the equivalent in [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md).
>
> Also note: current upstream Bitwarden (`src/Api/Dockerfile`) publishes as a self-contained single-file bundle (`/p:PublishSingleFile=true`), which packs every managed DLL into one native executable with nothing left on disk for SharpFuzz/Cecil to rewrite. `fuzz-prep-multi.py` now detects and strips this automatically for the instrumented build variant (prints `Detected PublishSingleFile=true — disabled...`) — the target's own release Dockerfile is not touched.

> **Grammar compilation (2026-07-23):** RESTler has been retired (Top-20 #9/#10) —
> `compile-grammar.sh` now runs `grammarc/` (first-party OpenAPI parser) + `analyzer/`
> (real `Microsoft.CodeAnalysis.CSharp` syntax-tree analyzer), no Docker involved in this
> step at all. Re-verified end-to-end against a fresh `bitwarden_src` clone: 3,864 `.cs`
> files parsed in the analyzer, 599 templates generated (matching the old RESTler-based
> grammar's count exactly), 0 skipped, 284 of 595 operations gained real type/property-scoped
> C# constraints — all in ~5 seconds. See Section 4 below for the exact command.

> **Fuzzer engine fixes (2026-07-23):** a full from-scratch rerun this session found and
> fixed two real bugs in the Go engine (not in Bitwarden): a path-quoting leak
> (`grammarc/body_serializer.py` was rendering string-typed path/query/header parameters
> with literal `"` characters, e.g. `/organizations/"CIP-0042"/delete` — guaranteed-
> malformed URLs, pure noise) and a malformed-bearer-token leak (`worker.go` left the
> grammar's literal `Bearer TOKEN` placeholder on unauthenticated probes and the `guest`
> identity instead of removing it, so ~16-26% of traffic hit
> `SecurityTokenMalformedException` server-side instead of a clean 401). Both fixed; `git
> pull` before your next run if you're on an older checkout. See `ARCHITECTURE_REVIEW.md`'s
> Inconsistencies section for the full writeups.

All commands below are run from `bitwarden_prep/` unless noted. `grammars/`, `void/`,
`compile-grammar.sh` live in the **repo root** (one level up).

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

RESTler is retired (`grammarc/` + `analyzer/` — Top-20 #9/#10) — one command, no Docker,
writes `templates.export.json` + `dict.json` directly:

```bash
# Need: ../grammars/bitwarden/{templates.export.json,dict.json}
curl -s http://localhost:4000/specs/internal/swagger.json -o swagger.json
python3 sanitize_swagger.py swagger.json   # still needed: grammarc/oas.py doesn't yet
                                            # decompose deepObject/object-shaped query params
../compile-grammar.sh swagger.json --dict ../grammars/bitwarden/dict.json --src ./src --out ../grammars/bitwarden

ls -la ../grammars/bitwarden/                    # templates.export.json, dict.json
```

Verified 2026-07-23 against a fresh `bitwarden_src` clone: `operations=595 templates=599
skipped=0 multipart_endpoints=4 roslyn_matched_types=284` — 599 templates, matching the
old RESTler-generated grammar's count exactly, in ~5 seconds with no Docker involved.

---

## 5. Run the fuzzer — two modes

Same two options as [QUICKSTART_BITWARDEN.md Step 8](QUICKSTART_BITWARDEN.md#step-8-run-the-fuzzer);
repeated here with paths adjusted for working inside `bitwarden_prep/` against an
already-running stand. Pick one — you don't need both.

### Mode A — Host mode (no image build, HTTP coverage)

Fastest to iterate with: no Docker image to rebuild when you change the Go engine.

```bash
( cd ../void/go && go build -o /tmp/smartfuzzergo . )

TARGET_HOST=http://localhost:4000 SHM_HOST=http://localhost:4000 \
  /tmp/smartfuzzergo \
  -grammar ../grammars/bitwarden -profile security \
  -auth-file auth.identities.json \
  -skip-endpoint-on-500 \
  -time-budget 20
```

### Mode B — Docker sidecar (direct-shm, fastest coverage)

```bash
# Build ONLY the fuzzer image (void engine) — does not rebuild Bitwarden
docker build -t void-fuzzer -f ../void/Dockerfile.go ../void/
```

**Run with WebUI (browser dashboard at http://localhost:13377):**

```bash
docker run --rm --network bitwarden_prep_default \
  -p 13377:13377 \
  -v bitwarden_prep_coverage_shm:/coverage_shm \
  -v "$PWD/../grammars/bitwarden:/grammar:ro" \
  -v "$PWD/auth.identities.json:/auth/auth.identities.json:ro" \
  void-fuzzer \
  -grammar /grammar -profile security \
  -auth-file /auth/auth.identities.json \
  -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode file \
  -skip-endpoint-on-500 \
  -web-ui -web-ui-port 13377 -no-ui -time-budget 20
```

**Run with terminal dashboard** (drop `-p`/`-web-ui`, add `-it`):

```bash
docker run --rm -it --network bitwarden_prep_default \
  -v bitwarden_prep_coverage_shm:/coverage_shm \
  -v "$PWD/../grammars/bitwarden:/grammar:ro" \
  -v "$PWD/auth.identities.json:/auth/auth.identities.json:ro" \
  void-fuzzer \
  -grammar /grammar -profile security \
  -auth-file /auth/auth.identities.json \
  -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode file \
  -skip-endpoint-on-500 \
  -time-budget 20
```

> Network/volume names follow Docker Compose's `<project-dir>_<resource>` convention —
> adjust `bitwarden_prep_default`/`bitwarden_prep_coverage_shm` if your directory has a
> different name (`docker network ls` / `docker volume ls` to check).

Both modes: `-profile security` enables the oracles (BOLA/auth-bypass/mass-assign/injection)
+ multi-identity + guest. To push raw throughput for a test: add `-concurrency 32
-max-concurrency 128`.

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

## 8. The same thing, via the `upsidefuzz` CLI

Sections 2, 4, and 5's host-mode invocation map onto CLI subcommands (from the repo root,
one level up from `bitwarden_prep/`) — the multi-stage bring-up in §1 stays manual (mssql
healthcheck → migrator → api/identity isn't representable by a single CLI call), and §3's
auth-file creation script stays manual too:

```bash
# Native: python3 upsidefuzz.py ...   |   Zero-install (only Docker needed): ./upsidefuzz ...
upsidefuzz verify --base http://localhost:4000 --probe /api/accounts/profile

upsidefuzz grammar bitwarden_prep/swagger.json --src ./bitwarden_src --out grammars/bitwarden

export $(cat bitwarden_prep/fuzzer.env | xargs)   # loads AUTH_TOKEN, if you're using single-auth
upsidefuzz fuzz --grammar grammars/bitwarden --target http://localhost:4000 \
  --profile security --skip-endpoint-on-500 --time-budget 15 \
  --auth-file bitwarden_prep/auth.identities.json   # if you built one in §3
```

Full walkthrough, including the fresh-clone setup steps and the Docker-sidecar (direct-shm)
mode this CLI doesn't yet cover: [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md#the-same-thing-via-the-upsidefuzz-cli).
Full subcommand reference: [docs/CLI.md](docs/CLI.md).

---

## Troubleshooting cheat-sheet

| Symptom | Cause / Fix |
|---|---|
| `Cannot open database "vault_fuzz" ... Login failed` (in make_bola_identities / api) | Migrations didn't run. Bring up `migrator` (step 1b) before api. |
| `mssql ... (unhealthy)` forever | Slow emulated boot. `start_period: 240s` is set; wait, verify with `SELECT 1`, raise Docker RAM to ≥ 4 GB. |
| `System.AccessViolationException` at `Bit.Api.Program+<>c..cctor` on api start | Was a real issue under `--inject-mode source` (or `--instrument-all-user-code` combined with source injection) — static-init types could execute before SHM was bound. **Fixed by hook mode** (the default since this was written): `DOTNET_STARTUP_HOOKS` binds the SHM pointer before `Main` runs at all, so this no longer happens even with `Bit.Core.Utilities` fully instrumented via `--instrument-all-user-code` — re-verified 2026-07-22, no `--exclude-namespaces` needed. If you still hit this, confirm the image was built with `--inject-mode hook` (the default; check for `DOTNET_STARTUP_HOOKS=/coverage/UpsideFuzz.Coverage.dll` in the Dockerfile) rather than a stale `--inject-mode source` image. |
| `identity` crashes on start: `UnauthorizedAccessException`/`DirectoryNotFoundException` writing `/dev/signingkey.jwk` (or `/tmp/.../signingkey.jwk`) | Unrelated to instrumentation. `src/Identity/appsettings.Development.json` sets `developmentDirectory: "../../dev"`, a path meant for `dotnet run` from `src/Identity/` on a local checkout. Inside the container (`WORKDIR=/app`) it resolves to the literal `/dev`. With `ASPNETCORE_ENVIRONMENT=Development` set (as this runbook does), override it to a real writable path: add `globalSettings__developmentDirectory: "/tmp"` to the `identity` service's environment. |
| *(historical, resolved by the #9 migration)* RESTler: `Cannot deserialize mutations dictionary ... Unexpected token: StartArray` | Was a `restler_custom_payload_uuid4_suffix` quirk in the old RESTler-based pipeline (values had to be single strings, not arrays). RESTler is retired as of 2026-07-23 (`grammarc/`) — this bug class is now structurally impossible, since `grammarc` never uses RESTler's dictionary format at all. Kept here as institutional memory of a real bug that was fixed. |
| `verify_coverage.sh` FAIL: no X-Coverage headers | Expected on fast endpoints — check `/shm/coverage` edges instead (the script now does). |
| Secrets Manager endpoints all 500 (`Unable to resolve service for type 'Bit.Commercial...'`) | Commercial SM DI is not wired in this build; not a Bitwarden bug. Tagged `target_misconfiguration` and excluded from the vuln count. `-skip-endpoint-on-500` stops the spam. |
| ~100 req/s (lower than before) | Not a regression: with real auth + populated data, requests execute real DB logic (slow under emulated SQL) instead of failing fast on 500s. Deeper, not worse. |
| Fuzzer exits immediately with `run failed: coverage instrumentation degraded: ...` | Added 2026-07-23 (Top-20 #4, `void/go/coverage.go::checkCoverageHealth`) — the engine sends a real warm-up probe at startup and refuses to run if the shared coverage bitmap doesn't gain any new edges, even if `/shm/health` reports `shm_bound=true`. This means instrumentation is genuinely broken (wrong image, stale build, or a namespace excluded via `--exclude-namespaces`) — re-run `verify-hook.sh` and fix the root cause rather than passing `-allow-degraded-coverage`, which would let the run complete while finding nothing. |

---

