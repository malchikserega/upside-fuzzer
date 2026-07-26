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
demo_app/
├── TeamFlow.sln
├── src/
│   ├── TeamFlow.Api/              ASP.NET Core Web API — 9 controllers, 26 endpoints
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

**Domain**: Organizations → Users (role: Member/Manager/Admin) → Projects → Tasks,
Documents, Webhooks — multi-tenancy gives natural, realistic surface for BOLA/IDOR the
same way Bitwarden's organizations/ciphers model does (this repo's own architecture
docs use Bitwarden as the reference example throughout).

**Seed data** (auto-created on first run, no migration step): two organizations —
Acme Corp (id 1) and Globex Inc (id 2) — and five users, all with password
`Passw0rd!23`:

| Email | Org | Role |
|---|---|---|
| `alice@acme.test` | Acme (1) | Admin |
| `bob@acme.test` | Acme (1) | Manager |
| `carol@acme.test` | Acme (1) | Member |
| `dave@globex.test` | Globex (2) | Admin |
| `erin@globex.test` | Globex (2) | Member |

Plus 2-3 projects with tasks and a document per organization — real cross-tenant data
for BOLA probes to actually have something to steal.

**Instrumentation-compatibility choices**, applied deliberately from lessons learned
building and fuzzing real targets this project has already been run against:
- **Controller-based MVC, not minimal-API lambdas.** Every action is a named method
  on a named class, so `instrumentor/Program.cs::ShouldInstrument`'s `+<>c`-closure
  exclusion (needed to prevent a real `AccessViolationException` static-init crash
  class found on Bitwarden) never silently zeroes out coverage.
- **Nested under `src/TeamFlow.Api/`**, not flat at `demo_app/` root — avoids the
  `CS8802` top-level-statements collision documented in
  `fixtures/planted-bug-api/README.md`.
- **`net8.0`** everywhere, matching `instrumentor.csproj`'s own TFM.
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
cd demo_app
DOTNET_ROLL_FORWARD=Major dotnet run --project src/TeamFlow.Api
```

`src/TeamFlow.Api/Properties/launchSettings.json` pins the port to
`http://localhost:5299` and auto-opens Swagger UI. Log in
(`curl -X POST http://localhost:5299/api/auth/login -H "Content-Type: application/json" -d '{"email":"alice@acme.test","password":"Passw0rd!23"}'`)
and paste the token into Swagger's "Authorize" button to poke around. Skip straight to
step 1 if you don't have the SDK installed — Docker is all you actually need.

### 1. Bring up the app via Docker Compose (no .NET SDK required)

```bash
cd demo_app
docker compose up -d --build
curl http://localhost:5299/health   # -> "ok"
```

This builds and runs the **plain, uninstrumented** image straight from
`demo_app/Dockerfile` + `demo_app/docker-compose.yml` — the fastest way to get a
browsable `http://localhost:5299/swagger` with zero local tooling beyond Docker. It's
not instrumented (no coverage, no CmpLog) — step 2 below builds the real, fuzzable
image. `docker compose down` when you're done.

`demo_app/swagger.json` is a committed snapshot of the OpenAPI contract (22 paths, 26
operations) for a static read without running anything; regenerate it with
`curl http://localhost:5299/swagger/v1/swagger.json -o demo_app/swagger.json` after
any endpoint change, since grammar compilation always needs the live spec.

### 2. Instrument + run the target in Docker

```bash
cd /path/to/upside-fuzzer
python3 fuzz-prep-multi.py --src demo_app --out /tmp/teamflow-prep --main TeamFlow.Api
cd /tmp/teamflow-prep
docker compose build && docker compose up -d
curl http://localhost:5299/health        # wait for this to return "ok"
```

`fuzz-prep-multi.py` finds `demo_app/Dockerfile` and `demo_app/docker-compose.yml`
(the same files from step 1) and **adapts them in place** in the `--out` copy — it
injects a SharpFuzz/CmpLog instrumentation stage, wires the zero-edit coverage hook
(`DOTNET_STARTUP_HOOKS`) into the runtime stage, and adds the `coverage_shm` tmpfs
volume to the compose file — rather than generating a fresh Dockerfile from scratch
(that's the fallback path used for targets with no pre-existing Docker setup; see
"Three real bugs" below for what building this exposed in that logic too). The
container keeps demo_app's own port (`5299`) and service name (`teamflow`); the compose
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
./compile-grammar.sh /tmp/teamflow-swagger.json --out grammars/teamflow \
  --src demo_app   # --src pulls in the Roslyn constraint extraction (analyzer/)
                   # for #14's demo endpoint; compile-grammar.sh has no --main flag
                   # (that's a fuzz-prep-multi.py-only flag -- don't mix them up)
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

with open("demo_app/auth.identities.json", "w") as f:
    json.dump({"version": "1", "identities": identities}, f, indent=2)
print("wrote demo_app/auth.identities.json")
EOF
```

`demo_app/auth.identities.example.json` is the template this fills in; the real,
token-populated file it writes is untracked (gitignore covers it — tokens expire in
12h anyway).

### 4. Run the fuzzer in Docker, over shared memory

Build the fuzzer image once (from this repo's own `void/Dockerfile.go`):

```bash
docker build -t void-fuzzer -f void/Dockerfile.go void/
```

Run it as a container attached to the target's network and its `coverage_shm` tmpfs
volume — `-direct-shm` reads the coverage bitmap straight from that shared file, no
HTTP polling:

```bash
mkdir -p crashes summaries
docker run --rm \
  --network teamflow-prep_default \
  -v teamflow-prep_coverage_shm:/coverage_shm \
  -v "$(pwd)/grammars/teamflow:/grammar:ro" \
  -v "$(pwd)/demo_app/auth.identities.json:/auth/auth.identities.json:ro" \
  -v "$(pwd)/crashes:/fuzzer/crashes" \
  -v "$(pwd)/summaries:/fuzzer/summaries" \
  -e TARGET_HOST=http://teamflow:8080 \
  -e SHM_HOST=http://teamflow:8080 \
  void-fuzzer \
  -grammar /grammar -direct-shm -shm-path /coverage_shm/bitmap -shm-read-mode file \
  -profile security -auth-file /auth/auth.identities.json -time-budget 30 \
  -crash-file /fuzzer/crashes/unique-crashes.jsonl \
  -summary-file /fuzzer/summaries/summary.json
```

`TARGET_HOST`/`SHM_HOST` use the **service name** (`teamflow`) and **container port**
(`8080`), not `localhost:5299` — the fuzzer container reaches the target over the
compose network, not through the host's published port mapping. Crash/summary output
lands in `./crashes/`/`./summaries/` on the host via the bind mounts, exactly as if
`void` had run natively. This exact command (with `-time-budget 30` swapped up to `3`
for a quick check) is what produced the "Expected results" numbers below — verified,
not just documented.

An equivalent `docker compose`-native alternative: uncomment the `# smartfuzzer:`
service block that `fuzz-prep-multi.py` writes into `/tmp/teamflow-prep/docker-compose.yml`,
fill in `-grammar`/`-auth-file` mounts and flags (it ships with neither by default —
only the `--direct-shm --time-budget 2` smoke-test flags), then
`docker compose up smartfuzzer`. The `docker run` form above is more explicit about
exactly what's mounted where, which is why it's the one actually verified end to end
for this README.

If you have Go installed and just want a fast local loop without the extra
container-build step, `void` also runs directly on the host against the same
Dockerized target — swap `TARGET_HOST`/`SHM_HOST` to `http://localhost:5299`, drop
`-direct-shm` (falls back to polling `/shm/coverage` over HTTP, slightly slower but
needs no shared volume mount), and run `./void/go/void` (built with `go build` inside
`void/go/`) with the same `-grammar`/`-auth-file`/`-profile` flags.

## Full vulnerability catalog

24 planted bugs across 26 endpoints, mapped to the exact oracle/mechanism that finds
each one. `#` matches the inline `// Vulnerability #N` comment at each bug's actual
implementation.

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

Every row above was manually curled against a real running instance while building
this demo and genuinely reproduces (see git history for the exact verification
transcript) — not just plausible-looking.

### Honest caveats, found while verifying this demo

- **#10 (SQLi)** genuinely crashes with a real `Microsoft.Data.Sqlite.SqliteException`
  (`"unrecognized token"` on a bare `'`), and will be caught as a
  `confirmed_unhandled_exception` crash. It will **not** get the specific
  `sqli_error_reflected` tag: `void/go/identity.go::exploitationSignals`'s SQLi
  markers are written for MySQL/Postgres/MSSQL/Oracle error phrasing
  (`"syntax error at or near"`, `"sqlite3.operationalerror"`, ...), which don't
  literally match .NET's own SQLite error text. The bug is 100% real either way —
  this is a disclosed gap in the oracle's marker list, not in this demo's endpoint.
- **#19 (SSRF)** — `void/go/mutations.go`'s built-in SSRF payloads target the three
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
add it to `grammars/teamflow/dict.custom.json` (see `INSTRUCTIONS.md §10` for the
convention — it's merged into `dict.json` on every future grammar compile and never
overwritten):

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
- `instrumentor/Program.cs::ConstantExtractor` (Top-20+ #22) reads it directly out of
  the IL at instrument time — no execution required at all — and feeds it into
  `void/go/mutation_engine.go`'s `mutateStringCategorized` candidate pool.
- CmpLog (Top-20+ #21, `instrumentor/Program.cs::CmpLogInstrumentor`) would also
  recover it live, the first time *any* string gets compared against it, by recording
  the real operand of the `String.Equals`/`op_Equality` call.

Neither mechanism exists in a fuzzer with no access to the target's own compiled
binary — this is a capability genuinely unique to grey-box, coverage-instrumented
fuzzing. The comparison itself is deliberately factored into `IsBackdoorCode`, a
plain non-`async` method, rather than written inline inside `async Task
RedeemAsync(...)` — see "Three real bugs this demo exposed in the fuzzer itself" below
for why that placement matters, not just style.

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
the first time is its own new coverage edge, so `void/go/worker.go`'s corpus
retention keeps and mutates *any* input that got one level deeper, closing in on the
full path incrementally — classic AFL-style greybox exploration, demonstrated
concretely. Once inside the `verificationLevel` band, Top-20 #14's boundary-aware
integer mutation (`{min-1, min, min+1, max-1, max, max+1}` candidates) finds the one
crashing value fast. Like #20, the gate is factored into a plain non-`async` method
(`PassesUnlockGate`) for the coverage probes to actually see it branch by branch.

### #16 — the stateful sequence-gated crash

`Restore` assumes every `Archived` task went through a (never-actually-implemented)
dedicated archive workflow that would have populated real metadata. The *only* way to
reach `Archived` in this codebase is the generic `PUT /api/tasks/{id}` status update,
which never sets that metadata — so the assumption is unconditionally false, and
`Restore` always throws on a genuinely archived task.

A single-request fuzzer can never trigger this: it requires (1) creating a task,
(2) a *prior* request that transitions it to `Archived` and supplies the id used in
step 3, (3) *then* calling restore with that id. `void/go/sequence.go`'s
producer/consumer chaining plus Top-20 #12's state-reward search — which specifically
rewards reaching a never-before-seen *workflow shape*, not just a new coverage edge —
is what builds and keeps exploring exactly this 2-3 step chain.

## Three real bugs this demo exposed in the fuzzer itself

Building this demo against the actual pipeline (not just reading the code) surfaced
three genuine bugs in `fuzz-prep-multi.py`/`instrumentor/Program.cs` — all now fixed,
and all worth knowing about since none are specific to TeamFlow:

1. **Non-main projects shipped uninstrumented ("generate from scratch" Dockerfile
   path).** For a solution with no pre-existing Dockerfile at all,
   `fuzz-prep-multi.py` builds the whole solution with `dotnet build`, which leaves
   every project with its own `bin/` folder and a *separate, pre-instrumentation*
   copy of every other referenced project's DLL (MSBuild's copy-local mechanism,
   executed before instrumentation runs). Each `RUN instrumentor ...` step
   instrumented the DLL sitting in *that DLL's own* project folder — but the final
   image only ever copied the *main* project's folder, which still held the stale,
   never-instrumented copy of every dependency. Confirmed empirically: an early
   version of this same demo (before it had its own `Dockerfile`) shipped
   `TeamFlow.Infrastructure.dll` — holding nearly all of the planted vulnerabilities —
   with **zero** SharpFuzz/CmpLog instrumentation despite the build log claiming
   otherwise. Fixed by syncing each non-main project's freshly-instrumented DLL (and
   its `.upsidefuzz_constants.jsonl`/`.upsidefuzz_instrumented.jsonl` metadata) into
   the main project's own output folder before the final `COPY`. Demo_app now ships
   its own `Dockerfile`/`docker-compose.yml` (see Bring-up above), so its own
   pipeline run actually exercises bug #3 below instead of this one — this fix still
   matters for any other target without a pre-existing Dockerfile.
2. **Async method bodies invisible to CmpLog/ConstantExtractor.** The instrumentor
   has always excluded C#'s compiler-generated `async`/`await` state-machine types
   (`<Method>d__N`) from every IL pass — coverage probes, CmpLog, and
   ConstantExtractor alike (`instrumentor/Program.cs`'s `d__` check,
   `ARCHITECTURE.md` §3) — a deliberate, documented tradeoff to avoid an
   `AccessViolationException` class of startup crash. The practical effect: a literal
   string comparison or a nested `if` chain written directly inside an `async Task`
   method (the idiomatic way to write almost anything in modern ASP.NET Core) is as
   invisible to the fuzzer as it would be to a black-box one — the exact opposite of
   this demo's premise. `CouponService.IsBackdoorCode` and
   `TaskLifecycleService.PassesUnlockGate` are written as small, ordinary
   (non-`async`) methods on their classes specifically because of this — pulling the
   decision logic out of the `async` wrapper is what makes bugs #20/#21 genuinely
   discoverable by ConstantExtractor/CmpLog/per-branch coverage reward rather than
   only in theory. Worth remembering if you write new planted bugs here, or fuzz any
   other target: a hidden constant or narrow branch buried directly inside `async
   Task Foo()` gets no benefit from this fuzzer's coverage-guided machinery today.
3. **`_detect_last_stage` misidentified the runtime stage whenever it was unnamed
   ("adapt an existing Dockerfile" path).** This is the path demo_app's own
   `Dockerfile` actually exercises, once it had one. `_detect_last_stage` was meant
   to find the runtime/final stage's name so instrumentation stages get inserted
   *before* it — but it searched for `FROM ... AS X` and returned the **last match
   found anywhere in the file**, not the last stage specifically. When the actual
   final stage is unnamed — an extremely common pattern (no later stage ever needs
   to reference it by name); true of demo_app's own `Dockerfile`, and, checked while
   fixing this, of both `btcpayserver/Dockerfile` and `simplcommerce/Dockerfile` in
   this repo's own fixture set too — it silently returned an *earlier* stage's name
   (typically the SDK/build stage) instead. The caller then inserted the
   instrumentation stage (`FROM {that_earlier_stage} AS instrumentation`) **before**
   that stage's own definition in the file, producing a Dockerfile invalid enough
   that Docker tried to pull an image literally named after the stage
   (`pull access denied ... docker.io/library/build:latest`) instead of building it.
   Reproduced concretely while wiring up demo_app's Docker Compose bring-up. Fixed by
   having `_detect_last_stage` return `None` (triggering the existing, already-correct
   "no named runtime stage" fallback) whenever the truly last `FROM` in the file has
   no `AS name` — plus handling BuildKit flags like `--platform=$BUILDPLATFORM`
   before the image reference, which the original regex would have also silently
   dropped a real stage name for.

## Expected results (from an actual verification run)

The numbers below are from the exact `docker run void-fuzzer ... -direct-shm
-shm-path /coverage_shm/bitmap -profile security -time-budget 3` command in "Run the
fuzzer in Docker" above, against the real instrumented container over the real shared
`coverage_shm` volume — not a prediction, and not a host-binary run. Coverage
bootstrapped correctly across all three assemblies, then grew from a 0-edge baseline
to **1199 edges** (baseline-ceiling reported as 6175, i.e. the mutation engine kept
finding new edges throughout — this number reflects however much of the app's actual
branch space a 3-minute run reaches, not a fixed target). In 180 seconds: **169,190
requests**, **1859 crashes**, deduplicating to **16 unique signatures across 9 distinct
root-cause clusters**, plus **134 access-control findings** (150 total triaged
findings). The sequence engine (state-reward search, Top-20 #12) found **135 new
workflow states** and persisted **3 unique multi-step workflows** — direct evidence the
producer/consumer chaining behind bug #16 is genuinely exercised, not just plausible in
theory. Confirmed present in `unique-crashes-*.jsonl`:

- `System.DivideByZeroException` at `ProjectsController.TaskStats` — the baseline crash.
- A `GET /api/projects/{id}/tasks?search=...` 500 — bug #10's SQLi endpoint,
  reproducing the same `Microsoft.Data.Sqlite.SqliteException: "unrecognized token"`
  seen in manual verification, tagged `server_error`/`backend_exception` — **not**
  `sqli_error_reflected` (empirically confirms the marker-mismatch caveat above, not
  just the theory behind it).
- `System.InvalidOperationException: "Empty legacy import payload."` at
  `LegacyImportService.ImportAsync` — bug #22's endpoint is reachable and crashing,
  though this run's fuzzer hit the null-payload guard clause first rather than a
  `$type`-gadget-shaped crash; both are real crashes proving the same unsafe
  `TypeNameHandling.Objects` configuration is live.
- `schema_undeclared_sensitive_field:passwordHash` on `GET /api/users/me` — bug #3,
  exactly as designed.
- `differential_auth_bypass:route-case` on the case-varied `/Api/Organizations/...`
  path — bug #8, exactly as designed.
- A `stateful_trigger` finding on `POST /api/tasks/{id}/restore` — a live signal that
  the multi-request archive→restore chain behind bug #16 was actually built and
  exercised during this run, not just reachable in principle.
- `bola_identical_cross_identity_response` (102 instances) and
  `bola_suspected_cross_identity_access` (24) across the BOLA endpoints (#4/#6/#7/#9/#12).
- Several **incidental, non-catalogued** findings the fuzzer found on its own beyond
  the 24-bug catalog: `System.IO.IOException: "...being used by another process"` in
  `FileStorageService.SaveAsync`/`ReadAsync` (concurrent fuzz workers racing the same
  upload filename — a real, unplanned concurrency bug distinct from #23);
  `System.UnauthorizedAccessException` in the same `SaveAsync`, this time from an
  SSRF-shaped `fileName` payload (`http:/0x7f000001/...`) that `Path.Combine` turns
  into an attempted directory write the OS itself refuses — a second, differently-shaped
  symptom of the same #17 path-traversal root cause; and `System.FormatException` in
  `DocumentsController.Download` (an earlier fuzzed upload stored a malformed
  `Content-Type`, later crashing `ControllerBase.File(...)` when reflected into a
  response header). None of this is the ceiling of what the fuzzer finds here.

Bugs #20 (backdoor constant) and #21 (nested unlock gate) did **not** fire within this
particular 3-minute budget — both were independently, manually confirmed to crash
deterministically with the right input (see "Bugs only coverage-guided fuzzing finds"
above), and the mechanism that's supposed to find them is now confirmed live end to end
in this exact Docker Compose stack (the extracted-constants dictionary shipped in the
image contains `QA-INTERNAL-BYPASS-58f3` and `EU-WEST`, and CmpLog reported 1 live
string- and 1 live int-comparison site in `TeamFlow.Infrastructure.dll` at build time —
see the previous section). They're the two hardest bugs in the catalog by design;
converging on an exact 19-character string or an exact 4-value/6-character-length
combination out of a large candidate pool takes materially longer than 3 minutes of
mutation. A longer run (or a fixed `-seed`, replayed) is expected to surface both —
that's the intended difficulty gradient, not a gap in the demo.
