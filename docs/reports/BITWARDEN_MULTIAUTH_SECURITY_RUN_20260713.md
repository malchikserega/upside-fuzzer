# Bitwarden Multi-Auth Security Fuzz Run - 2026-07-13

This report summarizes a 15-minute validation campaign against the local instrumented Bitwarden stand. The goal was to verify that Void's documented multi-auth identity file support works in a real run and that the security-focused flags behave as expected.

**→ [Back to README](../../README.md) · [Bitwarden Quickstart](../../QUICKSTART_BITWARDEN.md) · [Bitwarden Report](BITWARDEN_REPORT.md) · [Docs Index](../INDEX.md)**

> 📌 **Historical run report — 2026-07-13.** Point-in-time validation snapshot, not living
> documentation; not guaranteed reproducible against the current pipeline (see
> `ARCHITECTURE_REVIEW.md` Top-20 #9/#10 for what's changed since).

## Run Setup

Artifacts:

- `crashes/bitwarden-multiauth-security-20260713-1225/summary.json`
- `crashes/bitwarden-multiauth-security-20260713-1225/report.json`
- `crashes/bitwarden-multiauth-security-20260713-1225/unique-crashes.jsonl`
- `crashes/bitwarden-multiauth-security-20260713-1225/pocs/`
- `crashes/bitwarden-multiauth-security-20260713-1225/workflows/`

Auth identities:

| Identity | Auth type | Sanity check |
|----------|-----------|--------------|
| `bitwarden-admin` | Fresh JWT | `/sync` returned `200` |
| `bitwarden-alt-user` | Fresh JWT | `/sync` returned `200` |
| `guest` | Anonymous | `/sync` returned `401` |

The Bitwarden identity service was unable to issue fresh tokens initially because new-device login email attempted to connect to `localhost:25` inside the container. A temporary local dummy SMTP listener was started inside `bitwarden_prep-identity-1` for this local test stand only, allowing token generation without sending email.

Key flags:

```bash
-dict /grammar/dict.security.json
-auth-file /auth/auth.identities.json
-identity-mode weighted
-identity-include-guest=true
-direct-shm
-sequence-prob 0.45
-sequence-max-depth 5
-sequence-fanout 8
-race-mode=true
-race-prob 0.08
-race-burst 3
-skip-endpoint-on-500
-skip-on-crash
-crash-replay-count 0
-crash-boost-requests 0
-repro-runs 3
```

## Results

| Metric | Value |
|--------|-------|
| Duration | `900.0s` |
| Requests completed | `4,625,489` |
| Requests sent | `4,889,008` |
| Completed rate | `5,139 req/s` |
| Coverage edges | `149,248` |
| Baseline coverage ceiling | `42,694` |
| Mutation coverage above baseline | `+106,554` / `249.6%` |
| Average latency | `6.5ms` |
| Errors | `263,519` |
| Total crashes | `144` |
| Unique crashes | `139` |
| Generated PoCs | `139` |
| Generated workflow artifacts | `5,308` |

Identity distribution across unique crashes:

| Identity | Unique crashes |
|----------|----------------|
| `bitwarden-admin` | `90` |
| `bitwarden-alt-user` | `45` |
| `guest` | `4` |

Triage classification:

| Classification | Count |
|----------------|-------|
| `likely_vuln_high` | `2` |
| `likely_vuln` | `77` |
| `needs_review` | `58` |
| `noise` | `2` |

## Validation Notes

The multi-auth feature worked as intended:

- The fuzzer loaded `3` identities from `-auth-file`.
- Both authenticated users generated post-auth findings.
- Guest traffic was included and produced separate anonymous findings.
- The final `triage_summary` recorded `auth_file_configured=true`, `identity_count=3`, `identity_mode=weighted`, sequence settings, race settings, skip settings, and disabled crash replay/boost settings.
- Sequence evidence was generated: `unique-crashes.jsonl` includes sequence-labeled crashes, and `workflows/` contains deep workflow reproductions.
- The security dictionary was active: the run loaded `/grammar/dict.security.json`, and mutation labels include dictionary-driven payloads.

Security hygiene issue found and fixed:

- Initial PoC/report artifacts included real bearer tokens.
- The generator now redacts sensitive auth headers in PoCs and structured reports using placeholders such as `${AUTH_TOKEN:?set AUTH_TOKEN}`.
- Crash records and structured reports now include masked `auth_context` metadata: identity name, sensitive header name, auth scheme, JWT marker when applicable, token length, and short SHA-256 fingerprints.
- Existing artifacts from this run were sanitized.
- Follow-up redaction/auth-context smoke runs confirmed no real JWT values appeared in new PoCs or reports, while masked auth metadata remained available for triage.

## Interpretation

This is a successful validation run for the fuzzer feature itself. It shows that multi-user auth scheduling, direct SHM coverage, security dictionary mutations, stateful sequences, race settings, crash triage, repro, minimization, and skip-on-crash behavior can run together at high throughput on Bitwarden.

The findings are security-relevant, mostly stability/error-handling and post-auth exception issues. They should not be treated as automatically critical without manual exploitability review, but the run produced enough stable, post-auth crashes to justify deeper triage.

---

**→ [Back to README](../../README.md) · [Bitwarden Report](BITWARDEN_REPORT.md) · [Bitwarden Quickstart](../../QUICKSTART_BITWARDEN.md)**
