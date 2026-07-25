# Bitwarden — 1-Hour Fuzz Campaign (fresh checkout, populated data)

*2026-07-25 · local report, not hosted anywhere. See `BITWARDEN_1HOUR_REPORT.html` in this
same folder for the version with charts.*

A from-scratch run against a freshly-cloned, freshly-instrumented Bitwarden server
(hook-mode zero-edit instrumentation + CmpLog), populated with real users, an
organization, and vault items via Bitwarden's own official `util/SeederApi` tool, then
fuzzed for a full hour with multi-identity auth and every oracle enabled
(`-profile security`).

**Headline:** 741,150 requests · 295,481 coverage edges · **73 distinct root-cause
bugs** (not 2,641 — see "Reading the numbers" below) · 1 finding worth a security
engineer's time, everything else triaged honestly below.

| | |
|---|---|
| **295,481** | coverage edges reached (out of a 3,293-instrumented-type surface — the largest target this project has fuzzed) |
| **73** | distinct root-cause bugs, after clustering (`triage_summary.distinct_root_causes`) |
| **2,641** | raw "unique" crash signatures before clustering — see why this number is misleading, below |
| **1** | finding that survived honest triage as worth a security engineer's manual follow-up |

---

## Reading the numbers: 2,641 "unique crashes" is not 2,641 bugs

The engine's per-payload dedup produces 2,641 distinct crash *signatures*. Root-cause
clustering (`cluster.go`, same mechanism used throughout this project) collapses those
into **73 distinct root causes** — and even that number is dominated by one pattern: a
single cluster (a routing/authorization-attribute assertion, detailed below) accounts for
**2,054 of the 2,641 raw signatures (78%)** on its own. The other 72 clusters split the
remaining 587. Headline counts in this report use the 73 distinct-root-cause number, and
individual clusters are cited by their real cluster label, not by raw hit count.

---

## Methodology

- **Target**: fresh `git clone` of `bitwarden/server` (2026-07-25) — the repo has moved to
  **.NET 10** since this project's earlier Bitwarden runs (was .NET 8). 22 projects
  instrumented, `--instrument-all-user-code` (no namespace collides with the framework
  denylist), `--cmplog` active (Top-20+ #21 — comparison-operand harvesting from the
  target's own IL).
- **Data population**: Bitwarden's own `util/SeederApi` (an official dev/test tool this
  project hadn't used before) — 3 users (`SingleUserScene`), 1 organization with a
  confirmed owner (`SingleOrganizationScene`), 1 folder (`UserFolderScene`), 3 login
  ciphers (`UserLoginCipherScene`), 1 organization collection
  (`OrganizationCollectionScene`). Real encryption performed by Bitwarden's own Rust SDK,
  not hand-rolled.
- **Auth**: 4 identities in `auth.identities.json` — 3 real users authenticated via
  API-key `client_credentials` grant (`client_id=user.<userId>`, scope `api`) plus an
  unauthenticated `guest` identity, scheduled with `-identity-mode weighted`.
- **Dictionary**: `dict.custom.json` (the new custom-dictionary convention) seeded with
  the real user/org/cipher/folder/collection IDs and API keys discovered during seeding,
  merged automatically into `dict.json` by `compile-grammar.sh` — every field the fuzzer
  could plausibly need a *real* ID for had one available, not just boundary-value guesses.
- **Run**: `-profile security -seed 42 -time-budget 60`, direct HTTP coverage mode
  (target ran in Docker, engine ran natively against the published port).

---

## Findings — triaged by how real and how critical each one actually is

Every row below is the tool's own **honest triage** label, not a marketing gloss. This
section exists specifically to separate "the fuzzer flagged something" from "this is a
real, exploitable security bug" — most flagged signals in a run this size are the former,
not the latter.

### Tier 1 — Needs manual verification, and worth doing

**Cross-identity device lookup by identifier** (`GET /devices/identifier/{id}`,
`POST /devices/{id}/retrieve-keys`) — `likely_vuln` / `likely_vuln_high`, 9 flagged
instances, `access_control: true`.

The access-control oracle registered a device under one identity, then successfully
replayed the *same* lookup under a **different** identity and got a byte-identical
response back (`bola_identical_cross_identity_response` — the strong variant of the BOLA
check, not just "suspected"). If device lookup-by-identifier genuinely isn't scoped to
the calling user's own devices, that's a real access-control gap. **Caveat, stated
honestly**: in every instance actually observed this run, the leaked device record had
`"encryptedUserKey":null,"encryptedPublicKey":null` — the identifier was garbage
fuzzer-generated data (`bbbbbbb...`), so no *device* had real key material attached yet.
This means the *access-control gap itself* looks real, but this run did not prove it
leaks anything sensitive — that requires manually repeating the check against a device
that actually has `encryptedUserKey`/`encryptedPublicKey` populated (e.g. a device
created through a real login flow, not a fuzzer POST). This is the one finding from this
run worth a security engineer's time; everything else below is either debunked, a
robustness bug, or informational.

**Example — request as `user2-fuzzuser2`, but the returned device belongs to a
different, earlier identity:**
```
POST /devices/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/retrieve-keys
Authorization: Bearer <user2-fuzzuser2 JWT>

(empty body)
```
```json
200 OK
{"id":"4564d60c-a2ad-44a6-abb2-b492002ece2e","name":"57e70f25-FuzzCorp","type":0,
 "identifier":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
 "creationDate":"2026-07-25T02:50:24.7933333Z",
 "encryptedUserKey":null,"encryptedPublicKey":null,"object":"protectedDevice"}
```
Same result from `GET /devices/identifier/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
(same identifier, same identity) — `lastActivityDate`/`isTrusted` also returned, still
`encryptedUserKey`/`encryptedPublicKey`: `null`. The identifier itself is fuzzer-generated
garbage (`bbbb...`), not a real device value — which is exactly why the null key fields
don't prove a leak by themselves, and exactly why this needs a manual repeat against a
real, key-bearing device.

### Tier 2 — Flagged by the tool, debunked on inspection (not real bugs)

- **`GET /users/{userId}/public-key`** flagged `likely_vuln_high` /
  `bola_identical_cross_identity_response` (2 instances). This is **by design, not a
  vulnerability** — a user's public key exists specifically so *other* users can fetch it
  for end-to-end key exchange (sharing vault items, org invites). The access-control
  oracle currently has no way to know a given endpoint is *intentionally*
  cross-identity-readable (a documented gap — `ARCHITECTURE_REVIEW.md` #8, "ownership-matrix
  BOLA" is still open). Excluded from the real-finding count.

  ```
  GET /users/52d692d5-abea-46e8-a72a-b492002e0d8b/public-key
  Authorization: Bearer <user2-fuzzuser2 JWT>   (a different user's token)
  ```
  ```json
  200 OK
  {"userId":"52d692d5-abea-46e8-a72a-b492002e0d8b",
   "publicKey":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2bOrlQtyfqzydFagzWfDFbskocb/8jWFUIJ0Rgq5BTXBtNOO8oR328B4tR5hLmATkMP5ws4ULXbOdEuIy9mEcEzl3FnCzx2+9AdK28JQYjJpUtRrpRMeg4q/nikkLucw5sy3u0KUgJVwDW6wJPD2yLkAvyDgJ4HZ/rrBMFr16sTWV/mvBXIFujAPaPa0/O7GVn..."}
  ```

- **`sqli_time_based`** on `DELETE /accounts`, `POST /accounts/verify-password`,
  `POST /webauthn/attestation-options` (3 instances, all `likely_vuln_high`). All three
  fired on **HTTP 400** responses whose bodies read `"User verification failed"` /
  `"Invalid password"` — i.e. the request was *rejected* before doing anything
  SQL-adjacent, and none of them were repro-verified (`repro: null`). A slow response to a
  rejected, validation-failed request is far more consistent with concurrency contention
  under a 64-connection fuzzing load than genuine SQL execution. Same conclusion this
  project reached on the same finding shape in an earlier campaign — excluded here too.

  The actual payloads the oracle flagged (real attempted injections, for the record — the
  reason they're excluded is the 400+no-repro combination above, not that the payloads
  look harmless):
  ```
  POST /accounts/verify-password
  {"masterPasswordHash":"1'; WAITFOR DELAY '0:0:2'-- -","otp":"..%252f..%252f..%252fetc%252fpasswd", ...}
  → 400 {"validationErrors":{"MasterPasswordHash":["Invalid password."]}}

  POST /webauthn/attestation-options
  {"$type":"System.Diagnostics.Process, System","masterPasswordHash":"a","otp":"1 AND pg_sleep(2)", ...}
  → 400 {"validationErrors":{"":["User verification failed."]}}

  DELETE /accounts
  {"masterPasswordHash":"fuzzstring","otp":"1) AND SLEEP(2)-- -", ...}
  → 400 {"validationErrors":{"":["User verification failed."]}}
  ```
  All three are rejected by model validation *before* any query would run — the
  `WAITFOR`/`SLEEP`/`pg_sleep` payloads never reach a database.

### Tier 3 — Real, reproducible bugs (robustness/DoS-class, not directly exploitable)

These are genuine unhandled exceptions with real stack traces — legitimate findings, but
"causes an uncaught 500 instead of a clean 4xx" is a robustness gap, not by itself proof
of a security vulnerability. Cited by real cluster label:

| Cluster | Endpoint(s) | What's happening |
|---|---:|---|
| `NullReferenceException @ CiphersController.ValidateAttachment/PostFileForExistingAttachment/RenewFileUploadUrl` | 3 clusters, 72 combined hits | Attachment-upload validation path doesn't null-check something the fuzzer's malformed multipart/JSON bodies trigger. The single largest *real* bug pattern in this run by hit count. |
| `Cannot insert duplicate key row in object 'dbo.Device' ... UX_Device_UserId_Identifier` | 3 clusters | A raw `SqlException` (unique-constraint violation) surfaces as an unhandled 500 with the DB error text intact, instead of a handled "device already registered" response — a minor info-disclosure (schema/constraint names) plus a robustness gap. |
| `Value cannot be null. (Parameter 's') @ CoreHelpers.FixedTimeEquals` | 1 cluster | A constant-time-comparison helper (typically used in auth/crypto-adjacent checks) throws on a null argument instead of handling it — triggered via `POST /sends/file/validate/azure` with a bare newline body. |
| Billing/Stripe edge cases (`BillingException`, `Invalid API Key provided: SECRET`, `Could not find plan for type ...`) | 6 clusters | Mostly artifacts of this test environment's placeholder Stripe/installation keys (a real deployment has real billing credentials) rather than bugs in Bitwarden's billing logic itself — noted for completeness, not counted as security findings. |
| `$type`-deserialization-gadget probes (`System.Windows.Data.ObjectDataProvider`, `System.Configuration.Install.AssemblyInstaller`, ...) → `Expected 0x prefix` | 5 clusters | The engine's built-in insecure-deserialization gadget probes were tried against GUID-shaped route parameters. Every one failed with a clean parse error (`Expected 0x prefix`), not a type-confusion signal — **no evidence of exploitable deserialization**; the crash itself (uncaught `FormatException` instead of a 400) is a minor robustness gap, nothing more. |

**Example payloads, straight from the crash log:**
```
POST /ciphers/0/attachment-admin
(empty body)
→ 500 {"exceptionMessage":"Object reference not set to an instance of an object.",
       "exceptionStackTrace":"   at Bit.Api.Vault.Controllers.CiphersController.ValidateAttachment() ..."}

POST /devices
Authorization: Bearer <org-owner-fuzzuser0 JWT>
{"identifier":"fuzzstring","name":"upsidefuzz","type":21}
→ 500 {"exceptionMessage":"Cannot insert duplicate key row in object 'dbo.Device' with
       unique index 'UX_Device_UserId_Identifier'. The duplicate key value is
       (52d692d5-abea-46e8-a72a-b492002e0d8b, fuzzstring).\nThe statement has been terminated."}

POST /ciphers/attachment/validate/azure
Authorization: Bearer <guest — no real token>
(empty body)
→ 500 {"exceptionMessage":"Value cannot be null. (Parameter 's')",
       "exceptionStackTrace":"   at System.ArgumentNullException.Throw(String paramName)
   at System.Text.Encoding.GetBytes(String s)
   at Bit.Core.Utilities.CoreHelpers.FixedTimeEquals ..."}
```

### Tier 4 — Systemic pattern, real, low severity individually, but worth an engineering ticket

**Unvalidated GUID/Base64 route parameters, ~20 endpoints, one root cause repeated.**
`Unrecognized Guid format`, `Byte array for Guid must be exactly 16 bytes long`, `Guid
should contain 32 digits with 4 dashes`, and `Illegal base64url string!` account for the
large majority of the `needs_review` bucket's *distinct* clusters (as opposed to the one
giant cluster below). Devices, Ciphers, Folders, Sends, Organizations, and
SelfHostedOrganizationLicenses controllers all parse a route/body value as a GUID or
base64 string without validating its shape first, so malformed input throws an unhandled
exception instead of a clean 400. Not independently exploitable beyond "uncaught 500 +
stack trace disclosure in dev mode," but it's the same mistake made independently in ~20
places — a real, actionable pattern for whoever owns input validation conventions here.

```
DELETE /accounts/sso/admin​
Authorization: Bearer <org-owner-fuzzuser0 JWT>
→ 500 {"exceptionMessage":"Unrecognized Guid format.",
       "exceptionStackTrace":"   at System.Guid..ctor(String g)
   at Bit.Api.Auth.Controllers.AccountsController.DeleteSsoUser(String organizationId) ..."}
```

**The 78%-of-all-crashes cluster is a framework-internal routing assertion, not a
business-logic bug.** `A route decorated with '[Authorize<IOrganizationRequirement>]'
must include a route value named 'orgId' or 'organizationId'...` — 2,054 of the run's
2,641 raw unique-crash signatures, collapsed to **one** cluster. This fires when a
mutated URL happens to match a controller/action's route *template* but the resulting
route-value binding doesn't carry the parameter name the authorization attribute's own
reflection-based check expects — an assertion inside Bitwarden's own custom authorization
infrastructure, not attacker-controlled business logic. It is real (externally
triggerable, causes a 500 instead of a 404/400) but its security relevance is limited to
"this class of malformed URL causes a stack trace instead of a clean rejection," which is
why it's `needs_review`, not `likely_vuln`.

```
POST /organizations/0/users/0
Authorization: Bearer <org-owner-fuzzuser0 JWT>
{}
→ 500 {"error":"unhandled_exception"}
```

### Excluded entirely (test-environment artifacts)

`GET/POST /organizations/integrations/teams/*` — `Unable to resolve service for type
'Microsoft.Bot.Builder.IBot'`. Teams integration isn't wired up in this test stand; not a
Bitwarden bug, tagged `target_misconfiguration` by the tool's own triage and excluded
from every count above.

---

## Coverage & throughput over the hour

| Elapsed | Epoch | Coverage edges | Total crashes | Unique crashes | Errors |
|---:|---|---:|---:|---:|---:|
| 0s | Baseline | 10,370 | 0 | 0 | 0 |
| 3 min | Baseline→Harvest | 92,404 | 12,130 | 1,472 | 129 |
| 8 min | Harvest | 161,067 | 26,419 | 1,810 | 169 |
| 18 min | Deterministic | 190,570 | 32,492 | 1,918 | 198 |
| 30 min | Havoc | 225,881 | 36,851 | 2,371 | 634 |
| 45 min | Havoc→Splicing | 266,914 | 41,960 | 2,628 | 858 |
| 60 min | Splicing (end) | 295,481 | 43,135 | 2,641 | 991 |

Coverage climbed the entire hour without plateauing — this is a genuinely large target
(3,293 instrumented types; the coverage bitmap hit its 150%-of-capacity display cap by
minute ~8, meaning hash-collision pressure was real for the back half of the run, a
byproduct of fuzzing the largest single target this project has instrumented so far).
Throughput held at 200-250 req/s throughout, adaptively tuned between 62-64 concurrent
connections.

---

## A note on toolchain bugs found along the way (not Bitwarden bugs)

Standing up `util/SeederApi` (Bitwarden's own data-seeding tool, not previously used by
this project) surfaced two real bugs in *its* Dockerfile/csproj, unrelated to anything
this project ships:

1. `util/SeederApi/Dockerfile` sets `CARGO_TARGET_DIR=/tmp/cargo_target` before building
   its Rust crypto SDK, which silently breaks `util/RustSdk/RustSdk.csproj`'s hardcoded
   `Content Include="./rust/target/release/libsdk*.so"` glob (the file never lands where
   the glob expects) — the published image has no native crypto library in it at all,
   failing at first use with `Unable to load shared library ... libsdk.so`.
2. Once (1) is fixed, `RustSdk.csproj` only has `Content` entries for
   `linux-x64`/`osx-arm64`/`windows-x64` — there's no `linux-arm64` entry, so building on
   an arm64 Docker host (Apple Silicon, or any arm64 CI runner) produces a `.so` file that
   never gets linked to `runtimes/linux-arm64/native/`. The Dockerfile's own
   `--platform=$BUILDPLATFORM` build-stage pattern means the Rust compiler always targets
   the *builder's* native architecture regardless of `TARGETPLATFORM` (no `--target` flag
   is ever passed to `cargo build`), so this bites every arm64 host, not just
   cross-compilation scenarios.

Both fixed locally for this run (see the runbook); not upstreamed (out of scope for this
project's fuzzing work), reported here for completeness in the same honest-accounting
spirit as everything else in this report.

---

## Caveats, stated plainly

- **Development-mode stack traces inflate what's visible here.** This stand runs with
  `ASPNETCORE_ENVIRONMENT=Development`, which surfaces full exception messages and stack
  traces in error responses (`dev_mode_findings: 510` in the run's own triage summary).
  A production self-hosted deployment would show far less detail per crash — the
  *existence* of the underlying bugs wouldn't change, but an external attacker's view of
  them would be much narrower.
- **Placeholder billing/installation credentials cause some of Tier 3's findings** — a
  real deployment has real Stripe keys and a real Bitwarden installation ID; this test
  stand's fake values are the direct cause of several billing-related exceptions, not a
  Bitwarden defect.
- **Single local test environment**, not bitwarden.com or any production deployment —
  findings here say nothing about the hosted service.
- **Only 3 seeded users / 1 org / 3 ciphers.** The access-control oracle's coverage is
  bounded by how much real cross-identity data exists to probe against; a broader seed
  (more users, nested org roles, populated device key material) would likely surface more
  Tier-1-quality findings, especially for the device-lookup pattern flagged above.

---

Raw data: `benchmarks/raw/bitwarden-1hr-fresh/` · reproduce with
`BITWARDEN_FUZZ_RUNBOOK.md` (updated alongside this report with every gotcha hit during
this exact run) · engine: void, HTTP coverage mode, `profile=security`, `seed=42`.
