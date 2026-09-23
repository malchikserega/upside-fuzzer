# security_scenarios.yaml — the declarative security-scenario library

**→ [Back to README](../../README.md) · [Docs Index](../index.md) · [ARCHITECTURE_STATEFUL.md](../architecture/stateful-fuzzing.md) · [CAMPAIGN.md](campaigns.md)**

Every stateful security-scenario family the project's own design spec calls
for — BOLA/IDOR, tenant escape, mass assignment, workflow bypass, stale
object, optimistic locking, idempotency, races, auth confusion, async
workflows — described once, declaratively, in
[`security_scenarios.yaml`](../../tools/campaign/security_scenarios.yaml), each with the exact
`requires`/`valid`/`attack`/`confirm` shape the spec asks for, plus a
`request_budget` and `minimization_strategy`.

```bash
python3 security_scenarios.py                     # load + validate the shipped catalog
python3 security_scenarios.py path/to/other.yaml   # load + validate a different one
```

## Honest scope: catalog, not interpreter

**This is a validated catalog and drift check, not a runtime rule engine.**
`void`'s own oracles (`oracle.go`, `adversarial.go`, `idempotency.go`,
`race.go`, ...) already implement every one of these scenario families
natively in Go — hand-written, individually tested (200+ Go tests across
them, see [ARCHITECTURE_STATEFUL.md](../architecture/stateful-fuzzing.md) §2.5). This
file's job is to describe that same behavior in one declarative,
version-controlled place, and to make sure the description can't silently
drift from the code: every scenario's `implemented_by` field names the exact
Go symbol that does the work, and `security_scenarios.py`'s
`verify_catalog_matches_implementation` greps `src/void/internal/engine/*.go` to confirm that
symbol still exists — a scenario referencing a renamed or deleted function
fails loudly (`test_security_scenarios.py::test_real_catalog_loads_and_has_no_drift`
runs this against the shipped file on every test run).

A generic interpreter that reads this file and drives `void` purely from its
`valid`/`attack`/`confirm` blocks — instead of `void`'s own hand-written
Go oracles — is explicitly **not** built in this pass. That would mean
replacing already-working, already-tested logic with a generic rule engine,
a materially larger and riskier undertaking than documenting what already
exists. This file is the seed such an engine could eventually consume, not
the engine itself.

One scenario (`async_premature_consume`) is cataloged honestly as **not yet
implemented** — its own `description` field says so directly, and it's
listed under the `async_workflows` family (required by the design spec) even
though no dedicated Go finding exists for it today, only the scheduler's
poll-bias (`async.go`'s `asyncPollBonus`).

## Field reference

| Field | Required | Meaning |
|---|---|---|
| `family` | no | One of the ten scenario families this project's design spec names (`bola`, `tenant_escape`, `mass_assignment`, `workflow_bypass`, `stale_object`, `optimistic_locking`, `idempotency`, `races`, `auth_confusion`, `async_workflows`) |
| `description` | no | One-line, single-scalar description (block scalars aren't supported by `parse_simple_yaml` — see below) |
| `requires` | **yes** | List of dotted-path preconditions (e.g. `resource.owner_identity`) that must be known before this scenario can run — documentation of intent, not yet a machine-checked precondition list |
| `valid` | **yes** | The valid-chain step this scenario builds on (`identity`, `operation`) |
| `attack` | **yes** | The single controlled modification applied to the valid chain (`identity`, `operation`, and scenario-specific keys) |
| `confirm` | **yes** | A mapping of named confirmation predicates (e.g. `status_in: [200, 201, 204]`, `response_contains_resource_identity: true`) — a mapping, not a list of single-key mappings as the original design sketch shows, so it stays parseable by this project's bounded YAML-subset parser (see below) |
| `request_budget` | no | Default `10` — max requests this scenario should cost when eventually automated |
| `minimization_strategy` | no | Default `drop-unnecessary-steps` — hints at how a future whole-chain minimizer (Phase 5 #126) should shrink a finding from this scenario |
| `implemented_by` | no | `"file.go::Symbol"`, optionally with a trailing `(parenthetical)` for human context (e.g. an oracle-kind constant) — checked against `src/void/internal/engine/*.go` by the drift check |

## Why `confirm` is a mapping, not a list of single-key mappings

The original design sketch shows `confirm` as a YAML sequence of one-key
mappings:

```yaml
confirm:
  - status_in: [200, 201, 204]
  - response_contains_resource_identity: true
```

`parse_simple_yaml` (`campaign.py`, reused here) deliberately doesn't support
a sequence of mappings — see its own docstring. Rather than extend the
parser for a shape that adds no real expressiveness over a flat mapping,
`confirm` here is written as one:

```yaml
confirm:
  status_in: [200, 201, 204]
  response_contains_resource_identity: true
```

Semantically identical (a set of named confirmation predicates), and it
keeps this project's stdlib-only, deliberately bounded YAML parser bounded —
see [CAMPAIGN.md](campaigns.md)'s own "Why not PyYAML?" section for the
reasoning this follows.

`parse_simple_yaml` was extended for this file specifically to support one
new bounded flow-style form: `key: [a, b, c]` (an inline list of scalars
only — no nested lists/mappings), needed for `status_in: [200, 201, 204]`.
Flow *mappings* (`{a: b}`) remain unsupported.
