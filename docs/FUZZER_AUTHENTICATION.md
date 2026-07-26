# Fuzzer Authentication

This is the canonical way to pass authentication into Void. Use one auth identity file per target and pass it with `-auth-file` or `AUTH_FILE`.

**→ [Back to README](../README.md) · [Full Runbook](INSTRUCTIONS.md) · [Docs Index](INDEX.md)**

Copyable example: [`docs/auth.identities.example.json`](auth.identities.example.json).

```bash
./void \
  -auth-file ./auth.identities.json \
  -multi-identity=true \
  -identity-mode weighted \
  -identity-include-guest=true \
  -skip-on-crash
```

For noisy targets that return the same infrastructure 500 repeatedly, use `-skip-endpoint-on-500` instead of, or in addition to, `-skip-on-crash`. See the security profiles in [`INSTRUCTIONS.md`](INSTRUCTIONS.md#security-campaign-profiles) and the full flag table in [`void/README.md`](../void/README.md#fuzzer-flags-full-reference).

## Recommended Auth File

Create a JSON file with an `identities` array. Each identity is parsed once at startup; the hot request path only reuses prebuilt headers.

```json
{
  "version": "1",
  "identities": [
    {
      "name": "admin",
      "jwt": "eyJhbGciOi...",
      "weight": 2.0
    },
    {
      "name": "viewer",
      "headers": {
        "Authorization": "Bearer eyJhbGciOi...",
        "X-Tenant": "acme"
      },
      "weight": 1.0
    },
    {
      "name": "partner-api",
      "api_key_env": "PARTNER_API_KEY",
      "api_key_header": "X-Api-Key",
      "weight": 1.5
    },
    {
      "name": "cookie-user",
      "cookie": "session=abc; xsrf=def",
      "weight": 1.0
    },
    {
      "name": "guest",
      "weight": 0.3
    }
  ]
}
```

Supported fields:

| Field | Meaning |
|-------|---------|
| `name` | Identity label written into traces, crash records, and reports. Use meaningful names like `org-a-admin`, `org-b-viewer`, `guest`. |
| `jwt` | JWT or bearer token. Both `eyJ...` and `Bearer eyJ...` are accepted; Void sends `Authorization: Bearer <token>`. |
| `token` | Backward-compatible JWT field. Prefer `jwt` in new files. |
| `api_key` | Literal API key value. Prefer `api_key_env` when the file may be committed or shared. |
| `api_key_env` | Environment variable name containing the API key. If it is empty, that identity is skipped with a warning. |
| `api_key_header` | Header used for the API key. Defaults to `X-Api-Key`. |
| `cookie` | Cookie header value for session-based auth. |
| `headers` | Arbitrary header map. Values are sent as written. |
| `weight` | Scheduling weight for `-identity-mode weighted`. Defaults to `1.0`. |

The parser also accepts legacy top-level array and object-map forms, but the wrapper form above is the stable documented format.

## Runtime Precedence

Void applies auth consistently in live requests and generated PoCs:

1. Template/generated request headers are applied first.
2. The selected identity's headers override matching request headers case-insensitively.
3. The selected identity's `token`/`jwt` sets `Authorization: Bearer <token>`.
4. Legacy single-user auth (`AUTH_TOKEN`, `AUTH_HEADERS_JSON`, `AUTH_HEADER`, `AUTH_COOKIE`, login flow) is used only when no named identity is selected, or as the separate `default` identity if multi-identity scheduling is active.

This means a selected `guest` identity stays anonymous even if `AUTH_TOKEN` is also set. An API-key identity sends only the configured API-key/cookie/header material unless you explicitly add a bearer token to that identity too.

When `-auth-file` or `AUTH_IDENTITIES_JSON` is configured without an explicit login flow (`AUTH_URL` or `AUTH_BODY`), Void does not probe the legacy default `/api/authenticate` endpoint before the run. If you want an additional runtime-login `default` identity, set `AUTH_URL`/`AUTH_BODY` as usual.

## JWT Expiry Warnings (added 2026-07-26)

Void has no auto-login/session-refresh mechanism for `-auth-file` identities — a
long-standing, still-open gap (a token that expires mid-run just starts silently
producing 401s for that identity, with nothing to tell you why). What it *does* now
do is read the unsigned `exp` claim out of any JWT-shaped `jwt`/`token` value at
identity-load time (never verifying the signature — it's a client of whatever auth
scheme the target uses, not a verifier) and:

- **At startup**, print one `WARNING:` line per identity whose token is already
  expired, or will expire before the configured `-time-budget` finishes, e.g.:
  ```
  WARNING: identity "alice-expired": JWT already expired 1h0m8s ago (at 2026-07-26T15:44:44-04:00) -- requests will get 401s all run
  WARNING: identity "bob-expiring-soon": JWT expires in 1m22s (at 2026-07-26T16:46:14-04:00), before this 2-minute run finishes -- requests will start getting 401s partway through
  ```
- **During the run**, emit a one-time `JWT-EXPIRED` event into the event log the
  moment an identity's token — still valid at startup — actually crosses its
  expiry, so a sudden wave of 401s for one identity partway through a long run has
  an obvious, timestamped explanation instead of looking like a target regression.

Non-JWT tokens (API keys, cookies, opaque session tokens) have no `exp` claim to
read and are silently skipped — this is purely additive, best-effort awareness, not
a new requirement on identity shape. See `void/go/jwt_expiry.go` and its test file
for the exact logic.

## Single Identity Shortcuts

For quick one-user fuzzing, these environment variables still work:

```bash
export AUTH_TOKEN='eyJhbGciOi...'
export AUTH_HEADERS_JSON='{"Authorization":"Bearer eyJhbGciOi...","X-Api-Key":"secret"}'
export AUTH_HEADER='Authorization: Bearer eyJhbGciOi...'
export AUTH_COOKIE='session=abc'
```

`AUTH_TOKEN` may be a raw JWT or a pasted `Bearer ...` value. `AUTH_HEADERS_JSON` values are sent exactly as written. `AUTH_HEADER` is a legacy one-header shortcut; prefer `AUTH_HEADERS_JSON` or `-auth-file` for new runs.

## Access-Control Fuzzing Without Killing Speed

Use multiple identities when you want to find authorization bugs: IDOR, tenant isolation breaks, role bypass, admin-only route exposure, or endpoints that return different behavior depending on caller.

Good starting set:

| Identity | Why it helps |
|----------|--------------|
| `org-a-admin` | Reaches privileged setup and write paths. |
| `org-a-member` | Finds missing role checks inside the same tenant/org. |
| `org-b-member` | Finds cross-tenant access-control bugs. |
| `read-only` or `viewer` | Finds write operations that ignore role. |
| `guest` | Finds missing authentication and pre-auth crashes. |

Keep the set small: 2-5 identities is usually the sweet spot. Use `-identity-mode weighted` for normal bug hunting because it biases useful identities without multiplying every sequence by every user. Use `round-robin` only for deterministic sweeps, and `random` only when you intentionally want less scheduling bias.

Recommended weights:

```json
[
  {"name": "org-a-admin", "jwt": "...", "weight": 2.0},
  {"name": "org-a-member", "jwt": "...", "weight": 1.2},
  {"name": "org-b-member", "jwt": "...", "weight": 1.0},
  {"name": "viewer", "jwt": "...", "weight": 0.8},
  {"name": "guest", "weight": 0.2}
]
```

If the target has very little public surface, disable anonymous traffic:

```bash
./void -auth-file ./auth.identities.json -identity-include-guest=false
```

## Current Sequence Behavior

Void already builds producer-consumer request chains. By default, a follow-up sequence step preserves the identity that produced the runtime value. That avoids a combinatorial explosion and keeps coverage discovery fast.

Multi-identity scheduling is therefore speed-preserving endpoint and chain coverage, not exhaustive cross-identity branching. For access-control campaigns, give the fuzzer semantically different identities and let weighted scheduling explore the same routes with different callers over time.

## Security Flag Interactions

Some flags look duplicated because they operate at different scopes:

| Flags | Difference | Security use |
|-------|------------|--------------|
| `-skip-on-crash` / `-skip-endpoint-on-500` | `-skip-on-crash` removes only the crashing template. `-skip-endpoint-on-500` blocks the whole endpoint after the first 500. | Use both for noisy targets where breadth matters more than repeatedly exploring one broken route. |
| `-repro-runs` / `-crash-replay-count` | Repro verifies a finding for reporting. Crash replay keeps fuzzing near a crash to find variants. | Keep repro for final reports. Set `-crash-replay-count 0` for strict no-revisit scans. |
| `-crash-boost-*` / `-crash-replay-*` | Boost raises scheduler weight for a crashy endpoint. Replay queues concrete follow-up requests. | Keep them for exploitability/depth; disable both for broad scans on very crashy targets. |
| Sequence flags / `-race-mode` | Sequences build stateful chains. Race mode sends conflicting write bursts found during those chains. | Keep both for business-logic, authz, and state-corruption testing. |

---

**→ [Back to README](../README.md) · [Full Runbook](INSTRUCTIONS.md) · [Go Fuzzer Reference](../void/README.md)**
