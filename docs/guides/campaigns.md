# campaign.yaml — the campaign contract

**→ [Back to README](../../README.md) · [Docs Index](../index.md) · [ARCHITECTURE_STATEFUL.md](../architecture/stateful-fuzzing.md)**

Instead of a hand-assembled, run-to-run-drifting bag of CLI flags, a campaign is
declared once as a single YAML file: what target to hit, how to bring it to a
known state, which identities to fuzz with, coarse safety policy, and which
security-scenario families to enable. `campaign.py` parses it and prints the
environment variables and `void` CLI flags it composes to — it does not invent
new engine behavior; every flag it emits already exists and is documented in
[CLI.md](../getting-started/cli.md)/`void/README.md`.

```bash
python3 campaign.py plan campaign.yaml   # print the resolved env/flags, change nothing
python3 campaign.py run campaign.yaml    # reset -> wait for readiness -> seed -> print the void invocation -> cleanup
```

Copy [`campaign.yaml.example`](../../tools/campaign/campaign.yaml.example) to get started.

## Why not PyYAML?

This project's Python side (`tools/grammar/grammarc/`, `tools/prep/fuzzprep/`) is deliberately
stdlib-only — "no `pip install` needed" is stated directly in those modules'
own test docstrings. `campaign.py` follows the same rule: `parse_simple_yaml`
is a small, bounded **subset** of YAML covering exactly what a campaign file
needs (block mappings, block sequences of scalars, quoted/unquoted scalars,
`#` comments) and explicitly **rejects** anything outside that (flow style
`[a, b]`/`{a: b}`, anchors/aliases, multi-document streams, block scalars,
tab indentation) with a clear `CampaignYAMLError` rather than silently
misparsing. If your campaign file needs full YAML (anchors, flow style, ...),
either restructure it into the supported subset or install PyYAML and adapt
`load_campaign`'s single call site — the rest of `campaign.py` only depends on
the parsed `dict`/`list`/scalar shape, not on which parser produced it.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `target.base_url` | **yes** | Maps to `TARGET_HOST`/`SHM_HOST` (void/README.md) |
| `target.swagger_url` | no | Documentation only today — not yet passed to the grammar compiler by `campaign.py` itself; compile the grammar the normal way (`tools/grammar/grammarc/`/`bin/compile-grammar.sh`) before running the campaign |
| `target.readiness` | no | List of paths (resolved against `base_url`) polled until each returns any status `< 500`, or `run` raises `TimeoutError` after 120s |
| `state.reset` | no | Shell command run first, via `run`, with `check=True` — a non-zero exit stops the campaign before it fuzzes against unknown state |
| `state.seed` | no | Shell command run after readiness, `check=True` |
| `state.cleanup` | no | Shell command run last, best-effort (`check=False` — runs even if something upstream failed) |
| `identities.file` | no | Maps to `-auth-file` + `-multi-identity=true` |
| `identities.required_roles` | no | Documentation only today — not yet validated against the identities file's actual contents |
| `policy.max_rps` | no | Documentation only today — `void` has no RPS-based throttle (only `-concurrency`/adaptive concurrency); parsed and available on the `Campaign` object for a future flag, not silently claimed as enforced |
| `policy.destructive_operations` | no | `allow` (default) / `deny` (maps to `-race-mode=false`) / `isolated` (documentation only today — `void` has no isolation mode to map it to) |
| `policy.workflow_depth` | no | Maps to `-sequence-max-depth` (default 6) |
| `scenarios` | no | List of scenario names, see below (default `[baseline]`) |

Fields marked "documentation only today" are parsed and validated, and show up
in `campaign.py`'s own printed plan, so they're never silently dropped — they
just don't have an engine mechanism to enforce yet. Treat them as recorded
operator intent until that mechanism exists.

## Scenario names

Each scenario turns on a coherent bundle of already-existing, already-tested
`void` flags (see [ARCHITECTURE_STATEFUL.md](../architecture/stateful-fuzzing.md) §2.5
for what each oracle family actually does). Scenarios are additive — listing
several just unions their flag sets, deduped.

| Scenario | Flags enabled |
|---|---|
| `baseline` | none (just ordinary coverage-guided fuzzing) |
| `bola` | `-access-probe -probe-bola=true -probe-auth-bypass=true` |
| `mass-assignment` | `-access-probe -probe-mass-assign=true` |
| `differential` | `-access-probe -probe-differential=true` |
| `lifecycle` | `-resource-graph=true -probe-stale-object=true -probe-stale-etag=true -probe-workflow-bypass=true` |
| `idempotency` | `-access-probe -probe-idempotency=true` |
| `concurrency` | `-race-mode=true -probe-race-outcome=true` |
| `injection` | `-injection-oracle=true` |
| `schema` | `-schema-conformance=true` |

An unrecognized scenario name doesn't fail the campaign — `campaign.py plan`
prints a `WARNING: unrecognized scenario name(s)` line so a typo is visible,
not silently ignored, while the rest of the campaign still runs.

This scenario→flag table is a fixed, small vocabulary, not the fully
declarative per-scenario precondition/confirm-rule engine the original design
task also calls for (`security_scenarios.yaml`, e.g. `cross_tenant_read` with
explicit `requires`/`valid`/`attack`/`confirm` blocks) — that's a separate,
larger contract layered on top of this one and tracked as its own piece of
work, not yet built.

## What `campaign.py run` actually does

1. Prints the resolved plan (same as `plan`).
2. Runs `state.reset` if set (propagates failure).
3. Polls every `target.readiness` path if set (raises on timeout).
4. Runs `state.seed` if set (propagates failure).
5. Prints the exact `TARGET_HOST=... SHM_HOST=... ./void <flags>` invocation
   to run — **it does not launch the `void` binary itself** in this pass
   (composing the command is the tested, reusable part; actually invoking a
   long-running fuzzing binary and streaming its output is a separate concern
   left to the operator or a future `upsidefuzz.py campaign run` wiring).
6. Runs `state.cleanup` if set, always (best-effort).
