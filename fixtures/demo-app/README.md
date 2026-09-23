# TeamFlow — the flagship demo target for UpsideFuzz

Everything this project's fuzzer can find — BOLA, mass assignment, broken/differential
auth, SQL injection, SSTI, reflected XSS, path traversal, SSRF, a .NET deserialization
gadget surface, race conditions, response-schema drift, plain unhandled-exception
crashes, **and** three bugs specifically engineered to be invisible to a black-box
fuzzer and findable *only* through this project's coverage-guided mechanisms — lives
in one small, realistic, multi-project ASP.NET Core solution. Every bug below was
built, run, and manually confirmed to actually fire (real stack traces, real
cross-tenant data leaks, real file writes outside the intended directory, real balance
corruption) — nothing here is aspirational.

Run this first. It's the ~15-minute proof that the whole approach works, end to end,
using nothing but this repo's own tooling exactly as documented.

## Architecture

A small multi-tenant project/task-tracking SaaS ("TeamFlow"), structured like a real
application — three projects, not one flat `Program.cs`:

```
fixtures/demo-app/
├── TeamFlow.sln
├── src/
│   ├── TeamFlow.Api/              ASP.NET Core Web API — 16 controllers, 57 endpoints
│   │   ├── Controllers/
│   │   ├── Middleware/            the legacy path-based auth gate (bug #8)
│   │   ├── Properties/
│   │   │   └── launchSettings.json   fixed port (5299) + auto-opens Swagger UI on `dotnet run`
│   │   └── Program.cs             JWT bearer auth, Swashbuckle, DI, auto-seed
│   ├── TeamFlow.Core/              Entities, DTOs (DataAnnotations constraints for
│   │                                Top-20 #14's boundary-mutation demo)
│   └── TeamFlow.Infrastructure/    EF Core + Sqlite, seeding, the services
│                                    (including every deliberately-vulnerable one)
├── swagger.json                    committed OpenAPI snapshot (see Bring-up below)
├── auth.identities.example.json    5-identity template (see "Collecting identity tokens")
└── README.md                       this file
```

**Domain**: Organizations → Users (role: Member/Manager/Admin) → Teams (role:
Member/Lead) → Projects → Tasks (with a separate approval-workflow state machine),
Comments, Documents, Webhooks; plus org-level Invitations, per-user API Keys and
Notifications, password-reset tokens, and a Subscription/quota model per organization
— multi-tenancy gives natural, realistic surface for BOLA/IDOR the same way
Bitwarden's organizations/ciphers model does (this repo's own architecture docs use
Bitwarden as the reference example throughout), and the invitation/approval/API-key/
password-reset flows exist specifically to give **multi-step, sequence-only**
vulnerabilities (findable only through a real POST→PUT→POST-shaped chain, never a
single request) a realistic home alongside the original single-request bug classes.

**Seed data** (auto-created on first run, no migration step): **4 organizations**, **24
users**, **8 teams**, **12 projects**, **~76 tasks**, plus comments, notifications,
invitations, API keys, and one subscription per organization — enough real volume for
list/search/BOLA-enumeration endpoints to have something substantial to return, not
just illustrative examples. The original 5 identities are preserved exactly as
before (same ids, same roles, same organizations) since `auth.identities.example.json`
and the rest of this README reference them by name — everything else is new:

| Email | Org | Role |
|---|---|---|
| `alice@acme.test` | Acme (1) | Admin |
| `bob@acme.test` | Acme (1) | Manager |
| `carol@acme.test` | Acme (1) | Member |
| `dave@globex.test` | Globex (2) | Admin |
| `erin@globex.test` | Globex (2) | Member |
| `admin@initech.test` / `manager@initech.test` / `member{1..4}@initech.test` | Initech LLC (3) | Admin / Manager / Member |
| `admin@umbrella.test` / `manager@umbrella.test` / `member{1..4}@umbrella.test` | Umbrella Group (4) | Admin / Manager / Member |

Every seeded user shares password `Passw0rd!23`. Each organization also gets 2 teams
(Engineering/Design) with memberships, 3 projects with 6 tasks each (plus the original
projects/tasks under Acme/Globex), a Free/Pro/Enterprise subscription, one Pending and
one Revoked invitation, and API keys for its first two users — real cross-tenant data
for BOLA probes to actually have something to steal, at a scale meant for honest
fuzzer-vs-fuzzer comparison rather than a handful of illustrative rows.

**Instrumentation-compatibility choices**, applied deliberately from lessons learned
building and fuzzing real targets this project has already been run against:
- **Controller-based MVC, not minimal-API lambdas.** Every action is a named method
  on a named class, so `tools/dotnet/instrumentor/Program.cs::ShouldInstrument`'s `+<>c`-closure
  exclusion (needed to prevent a real `AccessViolationException` static-init crash
  class found on Bitwarden) never silently zeroes out coverage.
- **Nested under `src/TeamFlow.Api/`**, not flat at `fixtures/demo-app/` root — avoids the
  `CS8802` top-level-statements collision documented in
  `fixtures/planted-bug-api/README.md`.
- **`net8.0`** everywhere, matching `tools/dotnet/instrumentor/instrumentor.csproj`'s own TFM.
- Response DTOs are strongly typed (`ActionResult<T>` / `[ProducesResponseType]`) so
  Swashbuckle infers `response_schemas` automatically — except deliberately on one
  endpoint (`GET /api/users/me`), where the declared and actual shapes diverge on
  purpose.

## Bring-up

Everything here runs in Docker — that's not a limitation, it's what makes shared-memory
coverage between the target and the fuzzer possible at all (a `tmpfs` volume both
containers mount). There is no supported non-Docker path for actually fuzzing this app;
`dotnet run` below is only for a quick manual look before you commit to the full pipeline.

### 0. Quick look (optional, needs the .NET 8 SDK, not part of the fuzzing pipeline)

```bash
cd fixtures/demo-app
DOTNET_ROLL_FORWARD=Major dotnet run --project src/TeamFlow.Api
```

`src/TeamFlow.Api/Properties/launchSettings.json` pins the port to
`http://localhost:5299` and auto-opens Swagger UI. Log in
(`curl -X POST http://localhost:5299/api/auth/login -H "Content-Type: application/json" -d '{"email":"alice@acme.test","password":"Passw0rd!23"}'`)
and paste the token into Swagger's "Authorize" button to poke around. Skip straight to
step 1 if you don't have the SDK installed — Docker is all you actually need.

### 1. Bring up the app via Docker Compose (no .NET SDK required)

```bash
cd fixtures/demo-app
docker compose up -d --build
curl http://localhost:5299/health   # -> "ok"
```

This builds and runs the **plain, uninstrumented** image straight from
`fixtures/demo-app/Dockerfile` + `fixtures/demo-app/docker-compose.yml` — the fastest way to get a
browsable `http://localhost:5299/swagger` with zero local tooling beyond Docker. It's
not instrumented (no coverage, no CmpLog) — step 2 below builds the real, fuzzable
image. `docker compose down` when you're done.

`fixtures/demo-app/swagger.json` is a committed snapshot of the OpenAPI contract (48 paths, 57
operations) for a static read without running anything; regenerate it with
`curl http://localhost:5299/swagger/v1/swagger.json -o fixtures/demo-app/swagger.json` after
any endpoint change, since grammar compilation always needs the live spec.

### 2. Instrument + run the target in Docker

```bash
cd /path/to/upside-fuzzer
python3 bin/fuzz-prep-multi.py --src fixtures/demo-app --out /tmp/teamflow-prep --main TeamFlow.Api
cd /tmp/teamflow-prep
docker compose build && docker compose up -d
curl http://localhost:5299/health        # wait for this to return "ok"
```

`bin/fuzz-prep-multi.py` finds `fixtures/demo-app/Dockerfile` and `fixtures/demo-app/docker-compose.yml`
(the same files from step 1) and **adapts them in place** in the `--out` copy — it
injects a SharpFuzz/CmpLog instrumentation stage, wires the zero-edit coverage hook
(`DOTNET_STARTUP_HOOKS`) into the runtime stage, and adds the `coverage_shm` tmpfs
volume to the compose file — rather than generating a fresh Dockerfile from scratch
(that's the fallback path used for targets with no pre-existing Docker setup; see
"Three real bugs" below for what building this exposed in that logic too). The
container keeps fixtures/demo-app's own port (`5299`) and service name (`teamflow`); the compose
project name is the `--out` directory's basename (`teamflow-prep`), which is why the
network and volume below are named `teamflow-prep_default`/`teamflow-prep_coverage_shm`
— adjust both if you pick a different `--out` path.

Sanity-check instrumentation actually took (not just that the container started):

```bash
./verify_coverage.sh http://localhost:5299 /health   # -> "OK: coverage is active (edges=N)"
```

### 3. Grammar + auth tokens

```bash
curl http://localhost:5299/swagger/v1/swagger.json -o /tmp/teamflow-swagger.json
cd /path/to/upside-fuzzer
./bin/compile-grammar.sh /tmp/teamflow-swagger.json --out grammars/teamflow \
  --src fixtures/demo-app   # --src pulls in the Roslyn constraint extraction (tools/dotnet/analyzer/)
                   # for #14's demo endpoint; bin/compile-grammar.sh has no --main flag
                   # (that's a bin/fuzz-prep-multi.py-only flag -- don't mix them up)
```

This project doesn't (yet) auto-login for multi-identity fuzzing — `auth.identities.json`
needs real, pre-obtained JWTs pasted in (see the repo root `README.md`'s own
`-auth-file` note for why). Every seed password is the same (`Passw0rd!23`), so
collecting all five is one loop:

```bash
python3 - <<'EOF'
import json, urllib.request

base = "http://localhost:5299"
users = ["alice@acme.test", "bob@acme.test", "carol@acme.test", "dave@globex.test", "erin@globex.test"]
names = ["acme-admin", "acme-manager", "acme-member", "globex-admin", "globex-member"]
weights = [1.5, 1.2, 1.0, 1.2, 1.0]

identities = []
for email, name, weight in zip(users, names, weights):
    req = urllib.request.Request(
        f"{base}/api/auth/login",
        data=json.dumps({"email": email, "password": "Passw0rd!23"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    token = json.load(urllib.request.urlopen(req))["token"]
    identities.append({"name": name, "jwt": token, "weight": weight})
identities.append({"name": "guest", "weight": 0.3})

with open("fixtures/demo-app/auth.identities.json", "w") as f:
    json.dump({"version": "1", "identities": identities}, f, indent=2)
print("wrote fixtures/demo-app/auth.identities.json")
EOF
```

`fixtures/demo-app/auth.identities.example.json` is the template this fills in; the real,
token-populated file it writes is untracked (gitignore covers it — tokens expire in
12h anyway).

### 4. Run the fuzzer in Docker, over shared memory

Build the fuzzer image once (from this repo's own `deployments/docker/Dockerfile.void`; the
build context is the repo root, not the `deployments/docker/` directory, since the Go
module (`go.mod`) lives at the root):

```bash
cd /path/to/upside-fuzzer
docker build -t void-fuzzer -f deployments/docker/Dockerfile.void .
```

Run it as a container attached to the target's network and its `coverage_shm` tmpfs
volume — `-direct-shm` reads the coverage bitmap straight from that shared file, no
HTTP polling:

> **⚠️ Pass `-shm-read-mode mmap`, not `file`.** `mmap` only activates on Linux
> (`shouldUseMmap()`, `src/void/internal/engine/coverage.go`) — which this container is. Without it, every
> coverage check re-reads *and re-scans* the **entire** multi-MB bitmap file from scratch
> via a fresh syscall, called ~2x per request. Measured on a real target: `file` mode was
> actually **slower overall (229 req/s) than plain HTTP-mode coverage polling (266–302
> req/s)** — HTTP mode fetches one pre-computed integer from the target instead of
> re-reading/re-scanning a multi-MB buffer in Go on every call. `mmap` gives a persistent
> zero-copy view with no such per-call cost — without it, "no HTTP polling" above doesn't
> actually translate into more throughput, only more setup complexity.

```bash
mkdir -p crashes summaries
docker run --rm \
  --network teamflow-prep_default \
  -v teamflow-prep_coverage_shm:/coverage_shm \
  -v "$(pwd)/grammars/teamflow:/grammar:ro" \
  -v "$(pwd)/fixtures/demo-app/auth.identities.json:/auth/auth.identities.json:ro" \
  -v "$(pwd)/crashes:/fuzzer/crashes" \
  -v "$(pwd)/summaries:/fuzzer/summaries" \
  -e TARGET_HOST=http://teamflow:8080 \
  -e SHM_HOST=http://teamflow:8080 \
  void-fuzzer \
  -grammar /grammar -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode mmap \
  -profile security -auth-file /auth/auth.identities.json -time-budget 3 \
  -crash-file /fuzzer/crashes/unique-crashes.jsonl \
  -summary-file /fuzzer/summaries/summary.json
```

`TARGET_HOST`/`SHM_HOST` use the **service name** (`teamflow`) and **container port**
(`8080`), not `localhost:5299` — the fuzzer container reaches the target over the
compose network, not through the host's published port mapping. Crash/summary output
lands in `./crashes/`/`./summaries/` on the host via the bind mounts, exactly as if
`void` had run natively. **`-time-budget` is minutes, not seconds**
(`src/void/internal/config/flags.go`'s `TimeBudgetMinutes`) — `3` here is a real ~3-minute run,
which is what keeps this whole demo inside its "~15 minutes end to end" framing; raise
it (e.g. `20`–`30`) for a longer exploratory run, but budget your own time accordingly.
This exact command is what produced the numbers in [HISTORY.md](HISTORY.md)'s
verification-run sections — verified, not just documented.

An equivalent `docker compose`-native alternative: uncomment the `# smartfuzzer:`
service block that `bin/fuzz-prep-multi.py` writes into `/tmp/teamflow-prep/docker-compose.yml`,
fill in `-grammar`/`-auth-file` mounts and flags (it ships with neither by default —
only the `--direct-shm --time-budget 2` smoke-test flags), then
`docker compose up smartfuzzer`. The `docker run` form above is more explicit about
exactly what's mounted where, which is why it's the one actually verified end to end
for this README.

If you have Go installed and just want a fast local loop without the extra
container-build step, `void` also runs directly on the host against the same
Dockerized target — swap `TARGET_HOST`/`SHM_HOST` to `http://localhost:5299`, drop
`-direct-shm` (falls back to polling `/shm/coverage` over HTTP, slightly slower but
needs no shared volume mount), and run `./src/void/cmd/void/void` (built with
`go -C src/void build -o cmd/void/void ./cmd/void`, or `make build`, from the repo root) with the same
`-grammar`/`-auth-file`/`-profile` flags.

## The same thing, via the `upsidefuzz` CLI

Steps 2–4 above, as CLI subcommands instead of four separate tools — verified end to
end against this exact target. fixtures/demo-app is single-service (no `--services` needed,
unlike eShopOnWeb's `sqlserver`+API split) but does need a real token collected from
the running container before fuzzing authenticated endpoints, so unlike eShopOnWeb's
one-shot `run`, it's shown here as individual subcommands with the token-collection
step in between:

```bash
# Native: python3 bin/compatibility/upsidefuzz.py ...   |   Zero-install (only Docker needed): ./upsidefuzz ...
upsidefuzz instrument --src fixtures/demo-app --out /tmp/teamflow-prep --main TeamFlow.Api

upsidefuzz up --dir /tmp/teamflow-prep --wait-url http://localhost:5299/health --wait-timeout 120

# Collect tokens (same python3 snippet as "Grammar + auth tokens" above,
# now hitting the CLI-managed container instead of one you brought up by hand):
python3 - <<'EOF'
import json, urllib.request
base = "http://localhost:5299"
users = ["alice@acme.test", "bob@acme.test", "carol@acme.test", "dave@globex.test", "erin@globex.test"]
names = ["acme-admin", "acme-manager", "acme-member", "globex-admin", "globex-member"]
weights = [1.5, 1.2, 1.0, 1.2, 1.0]
identities = []
for email, name, weight in zip(users, names, weights):
    req = urllib.request.Request(f"{base}/api/auth/login",
        data=json.dumps({"email": email, "password": "Passw0rd!23"}).encode(),
        headers={"Content-Type": "application/json"})
    token = json.load(urllib.request.urlopen(req))["token"]
    identities.append({"name": name, "jwt": token, "weight": weight})
identities.append({"name": "guest", "weight": 0.3})
json.dump({"version": "1", "identities": identities}, open("fixtures/demo-app/auth.identities.json", "w"), indent=2)
EOF

upsidefuzz verify --base http://localhost:5299 --probe /health

upsidefuzz grammar http://localhost:5299/swagger/v1/swagger.json --src fixtures/demo-app \
  --out /tmp/teamflow-prep/grammar

upsidefuzz fuzz --grammar /tmp/teamflow-prep/grammar --target http://localhost:5299 \
  --profile security --time-budget 3 --auth-file fixtures/demo-app/auth.identities.json

upsidefuzz down --dir /tmp/teamflow-prep --volumes
```

`instrument`/`up` wrap `bin/fuzz-prep-multi.py`/`docker compose` exactly as documented
above — `up` correctly finds fixtures/demo-app's adapted `docker-compose.yml` (auto-discovered
by plain `docker compose`, no `-f` flag needed, since `bin/fuzz-prep-multi.py`'s "adapt an
existing compose file" path preserves the original filename rather than always writing
`docker-compose.instrumented.yml`). `fuzz` resolves `src/void/cmd/void/void` automatically (or
tells you to `go build` it, or to switch to `./upsidefuzz` for the zero-install path)
and sets `TARGET_HOST`/`SHM_HOST` for you — no manual `export` needed the way the
plain-`void`-binary alternative above requires.

One honest caveat found while verifying this: `verify`'s synthetic-404-attribution
check (`Δ2 should be ≤ Δ1 on an idle, sequential repeat`) is flaky against this
target — occasionally fails with a small positive delta on the second probe, not
because instrumentation is broken (all the other checks, including cumulative edge
monotonicity, consistently pass), but because fixtures/demo-app's own background async work
(EF Core connection/disposal paths, GC finalizing async state machines) is now fully
instrumented too (see the async-coverage fix above) and can tick over an edge between
the two probe requests independent of the probe itself — a visible instance of this
project's own documented "concurrency-smeared attribution" limitation
(`docs/development/architecture-review.md` §2, "No per-*input* path novelty"), not a new bug. `verify`'s overall exit code is still 0
when this happens.

There is no one-shot `run` example here for the reason above (`run` doesn't have a
step for collecting per-identity tokens mid-pipeline) — if you only need the `guest`
identity or don't care about authenticated-endpoint coverage, `run --src fixtures/demo-app --out
/tmp/teamflow-prep --main TeamFlow.Api --target http://localhost:5299 --swagger
http://localhost:5299/swagger/v1/swagger.json --profile security --time-budget 3`
works standalone, same caveat as eShopOnWeb's own `run` example: fine for targets (or
partial-auth runs) with no non-standard steps in between.

See [docs/getting-started/cli.md](../../docs/getting-started/cli.md) for the full subcommand reference and the zero-install
`./upsidefuzz` Docker launcher's own notes (in particular the `localhost` →
`host.docker.internal` rewriting it does automatically when running that way).

## Full vulnerability catalog

42 planted bugs across 57 endpoints, mapped to the exact oracle/mechanism that finds
each one. `#` matches the inline `// Vulnerability #N` comment at each bug's actual
implementation. Bugs #24 onward were added specifically to grow the sequence-only
category (a chain of 2-4 requests where no single request in isolation demonstrates
anything wrong) beyond the original #16 — see "Sequence-only vulnerabilities" below the
table for the full list and why each one requires real multi-step chaining, not just
single-request mutation.

| # | Endpoint | Bug | Oracle / mechanism |
|---|---|---|---|
| 1 | `POST /api/auth/register` | **Mass assignment** — `role` bound straight from client JSON | mass-assignment oracle (`-probe-mass-assign`) |
| 2 | `POST /api/auth/login` | *(clean — issues JWT)* | baseline for the auth flow |
| 3 | `GET /api/users/me` | **Undeclared sensitive field** — declares `UserPublicDto` (`id/email/role/organizationId`), returns the full entity incl. `passwordHash`/`internalNotes` | schema-conformance oracle, `schema_undeclared_sensitive_field:passwordHash` (`-schema-conformance`) |
| 4 | `GET /api/users/{id}` | **BOLA** — no self/org check | cross-identity replay (`-probe-bola`) |
| 5 | `PUT /api/users/{id}` | **BOLA + mass assignment** — binds `role`/`organizationId`, no ownership check | both oracles, same endpoint |
| 6 | `GET /api/organizations/{id}` | **BOLA** — cross-tenant read | BOLA |
| 7 | `GET /api/organizations/{id}/projects` | **BOLA** — cross-tenant listing | BOLA |
| 8 | `POST /api/organizations/{id}/projects` | **Differential auth bypass** — legacy case-sensitive path gate, routing itself is case-insensitive | differential/parser-confusion oracle, `differential_auth_bypass:route-case` (`-probe-differential`) |
| 9 | `GET /api/projects/{id}` | **BOLA** | BOLA |
| 10 | `GET /api/projects/{id}/tasks?search=` | **SQL injection** — raw, string-concatenated `Microsoft.Data.Sqlite` query | crash/triage (`confirmed_unhandled_exception`, real `SqliteException`) — see note below |
| 11 | `POST /api/projects/{id}/tasks` | *(clean)* — `[Required]`/`[StringLength]`/`[Range]` DTO constraints | Top-20 #14 boundary-mutation demo target |
| 12 | `GET /api/tasks/{id}` | **BOLA** | BOLA |
| 13 | `PUT /api/tasks/{id}` | *(clean)* — drives task state for #16/#21 | sequence producer/consumer chaining |
| 14 | `DELETE /api/tasks/{id}` | **Broken authentication** — `[AllowAnonymous]` where every sibling write endpoint requires `[Authorize]` | auth-bypass oracle, no-credential replay (`-probe-auth-bypass`) |
| 15 | `GET /api/tasks/{id}/preview?format=` | **SSTI** (Scriban evaluates `task.Description`) **+ reflected XSS** (`format=html` writes it back unescaped) | `ssti_evaluated`, `xss_reflected_unescaped` (injection oracle) |
| 16 | `POST /api/tasks/{taskId}/restore` | **Stateful sequence-gated crash** — NREs whenever a task reached `Archived`, because the assumed archive-metadata invariant is never actually populated by the only code path that sets that status | ⭐ **coverage-guided-only** — see below |
| 17 | `POST /api/projects/{id}/documents` | **Path traversal** — `fileName` used raw in `Path.Combine`, no sanitization | crash/traversal signal + real out-of-directory write |
| 18 | `GET /api/documents/{id}/download` | *(clean)* — DB-resolved path, no raw traversal | contrast case: same endpoint shape, correctly implemented |
| 19 | `POST /api/organizations/{id}/webhooks/test` | **SSRF** — server-side fetch of a caller-supplied URL, no allowlist | `ssrf_metadata_reflected` — see "Verifying SSRF locally" below |
| 20 | `POST /api/organizations/{id}/coupons/redeem` | **Hardcoded backdoor constant** deep in `CouponService`, triggers a `decimal`→`long` `OverflowException` | ⭐ **coverage-guided-only** — see below |
| 21 | `POST /api/tasks/{taskId}/unlock` | **4-level nested numeric/string range gate**, `IndexOutOfRangeException` at one specific value inside an already-narrow band | ⭐ **coverage-guided-only** — see below |
| 22 | `POST /api/import/legacy` | **.NET deserialization gadget surface** — `Newtonsoft.Json` with `TypeNameHandling.Objects` | `json_dotnet_deser` mutation category; surfaces as a real `JsonSerializationException` crash, not claimed as a full RCE chain |
| 23 | `POST /api/organizations/{id}/credits/withdraw` | **Race condition** — check-then-act balance deduction, no locking, artificial 150ms window | `-race-mode` burst probing |
| — | `GET /api/projects/{id}/tasks/stats?bucketSize=` | **Baseline crash** — divide-by-zero at `bucketSize=0`, no sequencing needed | plain crash/triage, the simplest case in the catalog (mirrors `fixtures/planted-bug-api`'s own planted bug) |
| 24 | `POST /api/teams/{id}/members` | **BOLA + missing self-role-check** — target `userId` isn't checked against the team's own organization, and the caller isn't checked to already hold `Lead` before granting `Lead` to someone else | BOLA + privilege-escalation |
| 25 | `PUT /api/teams/memberships/{membershipId}` | **Self-role-escalation** — a Member can PUT their own membership row to `Lead`, no check of the caller's current role at all | BOLA + privilege-escalation |
| 26 | `POST /api/invitations/{token}/accept` | **BOLA** — no check that the accepting caller's own email matches the invitation's `email`; anyone can accept anyone's pending invitation | BOLA |
| 27 | `PUT /api/invitations/{id}` | **Privilege escalation, ⛓ sequence-only** — a still-Pending invitation's `role` can be raised with no check against the caller's own role; only observable 3 requests later via invite→update-role→accept | producer/consumer sequence chaining, `-sequence-prob` |
| 28 | `POST /api/invitations/{token}/accept` | **Race condition, ⛓ sequence-only** — check-then-act `Status` transition, no lock; two concurrent accepts of one invitation can both succeed, creating duplicate accounts | `-race-mode` burst probing, only reachable via invite→accept×2 |
| 29 | `POST /api/tasks/{taskId}/comments` | **Mass assignment** — `authorUserId` bound straight from client JSON | mass-assignment oracle |
| 30 | `PUT /api/comments/{id}` / `DELETE /api/comments/{id}` | **BOLA** — no ownership check before editing/deleting another user's comment | BOLA |
| 31 | `GET /api/users/{userId}/notifications` | **BOLA** — no self-check; any authenticated user can read any other user's notification feed | BOLA |
| 32 | `POST /api/api-keys/{id}/revoke` | **Stale-cache bypass, ⛓ sequence-only** — a process-wide "already validated" cache is populated on first use and never invalidated on revoke; only observable via create→use→revoke→use | producer/consumer sequence chaining against a stateful credential |
| 33 | `GET /api/users/{userId}/api-keys` | **BOLA** — no self-check; any authenticated user can list any other user's API-key metadata | BOLA |
| 34 | `POST /api/auth/reset-password` | **Token replay, ⛓ sequence-only** — `UsedAt` is set but never checked; the same reset token works forever until it expires. Only observable via forgot→reset→reset-again (same token) | producer/consumer sequence chaining |
| 35 | `POST /api/auth/forgot-password` | **BOLA + account takeover, ⛓ sequence-only** — the reset token is returned directly in the response (no mail server in this demo) with no proof the caller owns the email; a 2-step forgot→reset chain against any known email is a full account takeover | producer/consumer sequence chaining, response-value reuse |
| 36 | `POST /api/organizations/{id}/subscription/change-plan` | **Business-logic flaw** — downgrading never reconciles `usedQuota` against the new (smaller) `quota`, leaving the subscription permanently over quota | business-logic / state-consistency oracle |
| 37 | `POST /api/organizations/{id}/subscription/consume` | **Race condition** — check-then-act quota consumption, no lock, artificial 150ms window (identical shape to #23) | `-race-mode` burst probing |
| 38 | `POST /api/tasks/{taskId}/approve` | **Missing state-machine validation** — Approve never checks `ApprovalStatus == PendingReview` first; a task can be approved without ever being submitted | business-logic / state-consistency oracle |
| 39 | `POST /api/tasks/{taskId}/approve` | **Duplicate side effect, ⛓ sequence-only** — the same missing check lets Approve run twice, crediting the organization's balance a second time for work approved only once. Only observable via submit→approve→approve-again | producer/consumer sequence chaining, before/after balance comparison |
| 40 | `POST /api/projects/{id}/tasks/bulk-update` | **Mass assignment** — each item's `assignedUserId` isn't checked against the target project's own organization; a single call can hand tasks to a user in a different tenant | mass-assignment oracle |
| 41 | `POST /api/projects/{id}/tasks/bulk-delete` | **BOLA** — `taskIds` aren't filtered by the route's own `{id}` project; any task id from any project/organization deletes successfully | BOLA |

Every row above was manually curled against a real running instance while building
this demo and genuinely reproduces (see git history for the exact verification
transcript) — not just plausible-looking.

### Sequence-only vulnerabilities (⛓): the honest test for a *stateful* fuzzer

A single-request, black-box mutation fuzzer cannot find any of the six bugs marked ⛓
above by construction — each one requires binding a value produced by one response
into a *later*, different request, in the correct order, sometimes with real
concurrency. This is the same producer→consumer chaining
`src/void/internal/engine/sequence.go`/`resource_graph.go`'s resource-state-graph is built around
(see `docs/research/design-notes/resource-state-graph-report.md`), and the same shape RESTler's own
dependency-inference targets — which makes this set a genuinely fair, apples-to-apples
comparison point between the two:

- **#16** (original) — create → archive (via generic status update) → restore.
- **#27** — invite (role=Member) → update role (role=Admin) → accept.
- **#28** — invite → accept **concurrently, twice** (race, not just ordering).
- **#32** — create API key → use it → revoke it → use it again.
- **#34** — forgot-password → reset-password → reset-password again (same token).
- **#35** — forgot-password (response leaks the token) → reset-password (using that
  token) — the account-takeover only exists across these two specific requests.
- **#39** — submit-for-review → approve → approve again (duplicate credit, only
  visible by diffing organization balance before/after the *second* call).

### Honest caveats, found while verifying this demo

- **#10 (SQLi)** genuinely crashes with a real `Microsoft.Data.Sqlite.SqliteException`
  (`"unrecognized token"` on a bare `'`), and will be caught as a
  `confirmed_unhandled_exception` crash. It will **not** get the specific
  `sqli_error_reflected` tag: `src/void/internal/engine/identity.go::exploitationSignals`'s SQLi
  markers are written for MySQL/Postgres/MSSQL/Oracle error phrasing
  (`"syntax error at or near"`, `"sqlite3.operationalerror"`, ...), which don't
  literally match .NET's own SQLite error text. The bug is 100% real either way —
  this is a disclosed gap in the oracle's marker list, not in this demo's endpoint.
- **#19 (SSRF)** — `src/void/internal/engine/mutations.go`'s built-in SSRF payloads target the three
  real cloud-metadata addresses (`169.254.169.254`, `metadata.google.internal`,
  `100.100.100.200`), which only resolve to anything when this app actually runs
  inside a real cloud VM. See "Verifying SSRF locally" below for how to prove the
  vulnerable code path is real without one, and how to seed the fuzzer's own
  dictionary so automated local discovery works too.

### Verifying SSRF locally

`GET /api/internal/aws-metadata-stub/latest/meta-data/iam/security-credentials/demo-role`
is a local stand-in for a real AWS IMDS response, shaped exactly like what
`exploitationSignals`'s markers (`accesskeyid`, `secretaccesskey`, `sessiontoken`)
look for:

```bash
curl -X POST http://localhost:5299/api/organizations/1/webhooks/test \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:5299/api/internal/aws-metadata-stub/latest/meta-data/iam/security-credentials/demo-role"}'
# -> {"fetchedStatusCode":200,"bodySnippet":"{...AccessKeyId...SecretAccessKey...}"}
```

That proves the code path is real. To make the fuzzer's *own* automated SSRF payload
set try this local URL too (rather than only the three real cloud addresses),
add it to `grammars/teamflow/dict.custom.json` (see
[docs/getting-started/quickstart.md](../../docs/getting-started/quickstart.md)'s
"10. Custom Dictionary Format" section for the convention — it's merged into `dict.json`
on every future grammar compile and never overwritten):

```json
{
  "url": ["http://teamflow:8080/api/internal/aws-metadata-stub/latest/meta-data/iam/security-credentials/demo-role"]
}
```

Use the **service name** (`teamflow:8080`), not `localhost:5299` — the fuzzer resolves
this URL from inside the Docker network (see "Run the fuzzer in Docker" above), same
as `TARGET_HOST`/`SHM_HOST`.

## Bugs only coverage-guided fuzzing finds

The rest of the catalog is real, but a sufficiently patient black-box fuzzer with no
coverage feedback at all could eventually stumble onto most of it (BOLA/mass-assignment
just need the right resource id or field name; SQLi/SSTI/XSS just need a payload from
a stock list). These three are different — built specifically so they're reachable
*only* because this project's fuzzer watches coverage, not despite it.

### #20 — the magic backdoor constant

```csharp
private const string InternalQaBypassCode = "QA-INTERNAL-BYPASS-58f3";
private static bool IsBackdoorCode(string code) => code == InternalQaBypassCode;
// RedeemAsync: if (IsBackdoorCode(code)) { /* triggers the overflow crash */ }
```

A random fuzzer mutating the `code` field has ~0 probability of ever generating this
exact 19-character string. It's only discoverable because it's a **literal constant
sitting in the compiled IL** of this one comparison:
- `tools/dotnet/instrumentor/Program.cs::ConstantExtractor` (Top-20+ #22) reads it directly out of
  the IL at instrument time — no execution required at all — and feeds it into
  `src/void/internal/engine/mutation_engine.go`'s `mutateStringCategorized` candidate pool.
- CmpLog (Top-20+ #21, `tools/dotnet/instrumentor/Program.cs::CmpLogInstrumentor`) would also
  recover it live, the first time *any* string gets compared against it, by recording
  the real operand of the `String.Equals`/`op_Equality` call.

Neither mechanism exists in a fuzzer with no access to the target's own compiled
binary — this is a capability genuinely unique to grey-box, coverage-instrumented
fuzzing. The comparison is factored into `IsBackdoorCode`, a plain non-`async`
method, rather than written inline inside `async Task RedeemAsync(...)` — originally
required for ConstantExtractor/CmpLog to see it at all (async method bodies used to
be invisible to both), now just a legible-code habit since that limitation was fixed
at the source — see "Three real bugs this demo exposed in the fuzzer itself" below.

### #21 — the nested range gate

```csharp
private static bool PassesUnlockGate(int verificationLevel, string? region, string? unlockCode, out int slot)
{
    slot = -1;
    if (verificationLevel < 41 || verificationLevel > 44) return false;
    if (!string.Equals(region, "EU-WEST", StringComparison.Ordinal)) return false;
    if (unlockCode is null || unlockCode.Length != 6) return false;
    slot = verificationLevel - 41;
    return true;
}
// TryUnlockAsync: if (PassesUnlockGate(...)) { var buckets = new[]{"a","b","c"}; _ = buckets[slot]; }
```

No single constant to extract — the vulnerable region is a *combination* of
independently-checked conditions nested three levels deep, plus an off-by-one
boundary inside the innermost branch (only `verificationLevel == 44` overruns the
3-slot array). A stateless random fuzzer has to satisfy an exact region string, a
4-value integer band, and an exact-length code simultaneously — vanishingly unlikely
in one shot. Coverage-guided search doesn't need luck: each nested `if` reached for
the first time is its own new coverage edge, so `src/void/internal/engine/worker.go`'s corpus
retention keeps and mutates *any* input that got one level deeper, closing in on the
full path incrementally — classic AFL-style greybox exploration, demonstrated
concretely. Once inside the `verificationLevel` band, Top-20 #14's boundary-aware
integer mutation (`{min-1, min, min+1, max-1, max, max+1}` candidates) finds the one
crashing value fast. Like #20, the gate is factored into a plain non-`async` method
(`PassesUnlockGate`) — originally required for the coverage probes to see it branch
by branch, now just a style choice since that limitation was fixed at the source.

### #16 — the stateful sequence-gated crash

`Restore` assumes every `Archived` task went through a (never-actually-implemented)
dedicated archive workflow that would have populated real metadata. The *only* way to
reach `Archived` in this codebase is the generic `PUT /api/tasks/{id}` status update,
which never sets that metadata — so the assumption is unconditionally false, and
`Restore` always throws on a genuinely archived task.

A single-request fuzzer can never trigger this: it requires (1) creating a task,
(2) a *prior* request that transitions it to `Archived` and supplies the id used in
step 3, (3) *then* calling restore with that id. `src/void/internal/engine/sequence.go`'s
producer/consumer chaining plus Top-20 #12's state-reward search — which specifically
rewards reaching a never-before-seen *workflow shape*, not just a new coverage edge —
is what builds and keeps exploring exactly this 2-3 step chain.

## History

Bugs the *building* of this demo exposed in the fuzzer pipeline itself, and results
from past fuzzing runs against it (verified numbers, not projections), are kept
separately in [HISTORY.md](HISTORY.md) — dated material that isn't needed to bring
the demo up or run it.

