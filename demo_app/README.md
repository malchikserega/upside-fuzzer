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

### 1. Standalone (quick sanity check, no Docker)

```bash
cd demo_app
dotnet build
DOTNET_ROLL_FORWARD=Major dotnet run --project src/TeamFlow.Api
```

`src/TeamFlow.Api/Properties/launchSettings.json` pins the port to
**`http://localhost:5299`** and sets `launchBrowser: true` — `dotnet run` opens
straight to Swagger UI (`http://localhost:5299/swagger`) in your default browser, no
port-hunting required. The API is fully browsable there: every endpoint listed, "Try
it out" wired up, and the Bearer auth scheme ready to accept a token from the login
call below.

> `DOTNET_ROLL_FORWARD=Major` is only needed if your machine has newer .NET runtimes
> installed but not exactly 8.0 (the same situation `instrumentor.Tests/`'s own
> `.csproj` documents) — harmless either way.

In another terminal:

```bash
curl http://localhost:5299/health   # -> "ok"

curl -X POST http://localhost:5299/api/auth/login -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.test","password":"Passw0rd!23"}'
# -> {"token": "...", "userId": 1, "organizationId": 1, "role": "Admin"}
```

Paste that token into Swagger UI's "Authorize" button (`Bearer <token>`) to exercise
authenticated endpoints straight from the browser.

`demo_app/swagger.json` is a committed snapshot of the OpenAPI contract (22 paths,
26 operations) — open it directly for a static read of every endpoint/schema without
running anything. It's informational only: always regenerate a fresh one from the
actually-running (and, for fuzzing, actually-instrumented) container before compiling
a grammar, since it's the live spec that must match the live binary. Regenerate with:

```bash
curl http://localhost:5299/swagger/v1/swagger.json -o demo_app/swagger.json
```

### 2. The real pipeline (instrument → coverage → grammar → fuzz)

Exactly the commands a real target would use — no special-cased hacks:

```bash
cd /path/to/upside-fuzzer
python3 fuzz-prep-multi.py --src demo_app --out /tmp/teamflow-prep --main TeamFlow.Api
cd /tmp/teamflow-prep
docker compose build && docker compose up -d
curl http://localhost:7777/health        # wait for this to return "ok"

# Grammar (from the running instrumented container's own swagger):
curl http://localhost:7777/swagger/v1/swagger.json -o /tmp/teamflow-swagger.json
cd /path/to/upside-fuzzer
./compile-grammar.sh /tmp/teamflow-swagger.json --out grammars/teamflow \
  --src demo_app --main TeamFlow.Api   # --src+--main pulls in the Roslyn constraint
                                        # extraction (analyzer/) for #14's demo endpoint

# Fuzz:
export TARGET_HOST=http://localhost:7777
export SHM_HOST=http://localhost:7777
./void/go/void -grammar grammars/teamflow -direct-shm -profile security \
  -auth-file demo_app/auth.identities.json -time-budget 30
```

## Collecting identity tokens

This project doesn't (yet) auto-login for multi-identity fuzzing — `auth.identities.json`
needs real, pre-obtained JWTs pasted in (see `README.md`'s own `-auth-file` note in the
repo root for why). For this demo, every seed password is the same
(`Passw0rd!23`), so collecting all five is one loop:

```bash
BASE=http://localhost:7777   # or :5299 for the standalone run
python3 - <<'EOF'
import json, urllib.request

base = "http://localhost:7777"
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
token-populated file it writes is untracked (gitignore it if you keep one around —
tokens expire in 12h anyway).

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
  "url": ["http://localhost:7777/api/internal/aws-metadata-stub/latest/meta-data/iam/security-credentials/demo-role"]
}
```

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
RedeemAsync(...)` — see "Two real bugs this demo exposed in the fuzzer itself" below
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

## Two real bugs this demo exposed in the fuzzer itself

Building this demo against the actual pipeline (not just reading the code) surfaced
two genuine bugs in `fuzz-prep-multi.py`/`instrumentor/Program.cs` — both now fixed,
and both worth knowing about since they're not specific to TeamFlow:

1. **Non-main projects shipped uninstrumented.** `fuzz-prep-multi.py`'s "generate
   Dockerfile from scratch" path (used whenever a solution has no pre-existing
   Dockerfile — true for any brand-new multi-project app) builds the whole solution
   with `dotnet build`, which leaves every project with its own `bin/` folder and a
   *separate, pre-instrumentation* copy of every other referenced project's DLL
   (MSBuild's copy-local mechanism, executed before instrumentation runs). Each
   `RUN instrumentor ...` step instrumented the DLL sitting in *that DLL's own*
   project folder — but the final image only ever copied the *main* project's
   folder, which still held the stale, never-instrumented copy of every dependency.
   Confirmed empirically on this app: `TeamFlow.Infrastructure.dll` — which holds
   nearly all of the planted vulnerabilities — shipped with **zero** SharpFuzz/CmpLog
   instrumentation despite the build log claiming otherwise. Fixed by syncing each
   non-main project's freshly-instrumented DLL (and its `.upsidefuzz_constants.jsonl`
   / `.upsidefuzz_instrumented.jsonl` metadata) into the main project's own output
   folder before the final `COPY`. (The "adapt an existing Dockerfile" path was
   already unaffected — it instruments a single `dotnet publish` output folder that
   holds every DLL together.)
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

## Expected results (from an actual verification run)

The numbers below are from a real `-profile security -auth-file
demo_app/auth.identities.json -time-budget 3` run against this exact `docker compose`
stack — not a prediction. Coverage bootstrapped correctly across all three assemblies
(`Coverage health: ... app_assemblies=[... TeamFlow.Core TeamFlow.Infrastructure
TeamFlow.Api]`), then grew from a 0-edge baseline to **3038+ edges** entirely through
mutation (edges are not fixed ahead of time — this number reflects however much of the
app's actual branch space the 3-minute run reached). In 180 seconds: **149,155
requests**, **843 crashes**, deduplicating to **9 unique signatures across 7 distinct
root-cause clusters**, plus **137 access-control findings** (146 total triaged
findings). Confirmed present in `unique-crashes-*.jsonl`:

- `System.DivideByZeroException` at `ProjectsController.TaskStats` — the baseline crash.
- `Microsoft.Data.Sqlite.SqliteException: "unrecognized token"` at
  `GET /api/projects/{id}/tasks?search=` — bug #10, firing exactly as the honest
  caveat above predicts: tagged `server_error`/`backend_exception`/
  `confirmed_unhandled_exception`, **not** `sqli_error_reflected` (empirically
  confirms the marker-mismatch caveat, not just the theory behind it).
- `System.InvalidOperationException: "Empty legacy import payload."` at
  `LegacyImportService.ImportAsync` — bug #22's endpoint is reachable and crashing,
  though this particular run's fuzzer hit the null-payload guard clause first rather
  than a `$type`-gadget-shaped crash; both are real crashes proving the same unsafe
  `TypeNameHandling.Objects` configuration is live.
- `schema_undeclared_sensitive_field:passwordHash` on `GET /api/users/me` — bug #3,
  exactly as designed.
- `differential_auth_bypass:route-case` on `POST /Api/Organizations/1/Projects` — bug
  #8, exactly as designed.
- `bola_identical_cross_identity_response` (96 instances) and
  `bola_suspected_cross_identity_access` (22) across the BOLA endpoints (#4/#6/#7/#9/#12).
- Two **incidental, non-catalogued** findings the fuzzer found on its own:
  `System.IO.IOException: "...being used by another process"` in
  `FileStorageService.SaveAsync`/`ReadAsync` (concurrent fuzz workers racing the same
  upload filename — a real, unplanned concurrency bug distinct from #23), and
  `System.FormatException: "The header contains invalid values"` in
  `DocumentsController.Download` (an earlier fuzzed upload stored a malformed
  `Content-Type`, which later crashes `ControllerBase.File(...)` when reflected back
  into a response header) — a nice demonstration that this catalog isn't the ceiling
  of what the fuzzer finds here.

Bugs #20 (backdoor constant) and #21 (nested unlock gate) did **not** fire within this
particular 3-minute budget — both were independently, manually confirmed to crash
deterministically with the right input (see "Bugs only coverage-guided fuzzing finds"
above), and the mechanism that's supposed to find them is now confirmed live (the
extracted-constants dictionary shipped in the image contains `QA-INTERNAL-BYPASS-58f3`
and `EU-WEST`, and CmpLog reports live comparison sites in `TeamFlow.Infrastructure.dll`
— see the previous section). They're the two hardest bugs in the catalog by design;
converging on an exact 19-character string or an exact 4-value/6-character-length
combination out of a large candidate pool takes materially longer than 3 minutes of
mutation. A longer run (or a fixed `-seed`, replayed) is expected to surface both —
that's the intended difficulty gradient, not a gap in the demo.
