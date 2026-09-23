# Typed Structural Mutation (Request Bodies)

Schema-aware mutation of nested/array/`oneOf`-discriminated request bodies — instead of
mutating an already-flattened JSON string blind, the fuzzer keeps a real typed tree from
grammar export through rendering, mutation, and minimization, only turning it into bytes
immediately before the request goes out. This closes the gap `docs/development/architecture-review.md`
used to track as its top P1 weakness ("no typed request-body model reaching mutation").

Added 2026-07-31. Fully additive: a grammar compiled with the current `tools/grammar/grammarc/`
gets it automatically; a grammar compiled *before* this existed (or any request whose body
schema this compiler doesn't recognize) renders through the exact same legacy flat-segment
path it always has, byte-for-byte. Nothing about existing grammars, the CLI, or old templates
changed.

---

## Why this exists

The old path: `template.go` renders a request body as one flat string; mutation
(`mutation_engine.go`) round-trips that string through `json.Unmarshal` → `map[string]any` →
`json.Marshal`, with no idea what the schema declared. A nested object, an array of objects,
a `oneOf`/discriminator-typed field — none of it is visible to the mutator; it can only flip
bytes or top-level keys.

The new path keeps the schema (`BodyNode`, parsed once per template from
`tools/grammar/grammarc/schema_ast.py`'s AST) and a disposable per-render value tree
(`BodyValue`) all the way through rendering and mutation. Ten operators (below) can now target
*exactly* "the second element of this array," "this `oneOf` variant's discriminator tag," or
"this nested object's only optional field," instead of guessing at flattened bytes.

---

## The flags

| Flag | Default | What it does |
|---|---|---|
| `-typed-body-mutation` | **true** | Master switch. `true`: templates with a `body_schema` (grammar compiled by the current `grammarc`) render through the typed tree. `false`: **every** template renders through the exact legacy flat-segment/`mutateJSONBody` path, unconditionally — the same bytes-in-bytes-out behavior as before this feature existed. |
| `-adversarial-body-rate` | `0.5` | Only matters when `-typed-body-mutation=true`, and only during `mutate`/`havoc` epochs (the `Baseline`/`Deterministic` epochs always render a schema-correct "valid" body). Probability that a given render applies exactly **one** deliberate structural violation instead of staying schema-correct. `0.0` = always valid (pure "reach business logic" mode); `1.0` = always exactly-one-violation (pure structural-attack mode). |

Both flags are visible per-run in the startup config dump, and both are captured in the run
manifest (`manifest.go`) for reproducibility.

### What each mode is actually *for*

- **`valid` mode** (the `1 - adversarial-body-rate` fraction, and always during `Baseline`/`Deterministic`) builds a fully-populated, schema-correct instance — every declared property present, arrays sized within `minItems`/`maxItems`, the right `oneOf` variant with a consistent discriminator tag, producer/consumer-bound id fields resolved through the tenant-aware binding chain (below). This is what actually clears server-side model-binding/validation and reaches real business logic — measurably: see the Bitwarden comparison below, where valid-mode-heavy typed runs reached **65% more code coverage** than the legacy mutator in the same wall-clock window.
- **`adversarial` mode** applies exactly one of the ten operators below, then stops — no stacking, so a resulting crash is attributable to one specific, nameable cause (a mutation label like `mcat_struct_required_omit`), not an opaque blob of corrupted bytes.

---

## The ten operators (`internal/engine/body_mutate.go`)

| Operator | Valid mode | Adversarial mode | Bug class it targets |
|---|---|---|---|
| `add_remove_field` | add an absent optional property / drop a present optional one | — | schema-correct completeness variation |
| `required_omit` | — | drop one `required` property | missing-required-field crashes, weak server-side validation |
| `array_resize` | resize within `[minItems, maxItems]` | resize outside that bound | array boundary bugs (empty-array NREs, off-by-one loops) |
| `variant_switch` | switch `oneOf`/`anyOf` to a different *valid* variant, discriminator kept consistent | switch shape but leave the discriminator tag pointing at the old variant | discriminator/polymorphism confusion, deserialization-gadget-adjacent bugs |
| `type_substitution` | — | replace a scalar with a wrong-type value (string where the schema says integer, etc.) | type-confusion exceptions, weak type coercion |
| `null_injection` | — | set a non-nullable node to `null` | null-reference exceptions on assumed-non-null fields |
| `undeclared_property` | — | insert a key the schema never declared (and `additionalProperties` doesn't cover) | **mass assignment** via a nested/undeclared field — the class the top-level-only legacy mutator structurally can't target precisely |
| `dup_key` | — | append a second object field with a repeated key | parser/deserializer disagreement on "last key wins" (a real representational trick: Go's own `encoding/json` can't even construct this, which is why this tree uses an ordered `[]BodyField` slice instead of a map) |
| `nesting_depth` | nest one level deeper (only on a genuinely recursive schema) | wrap a leaf in synthetic extra object layers regardless of schema (always available) | stack-depth/recursion-limit bugs in the target's own deserializer |
| `constraint_boundary` | set to the exact edge (`minLength`/`maxLength`/`minimum`/`maximum`/enum edge) | one step past the edge, or a value outside `enum_values` | off-by-one validation bugs, the same class `constraint-aware boundary mutation` already targets for path/query values, now for nested body fields too |

Selection is weighted MOpt-style (a sibling registry to the existing string-mutation
categories, so it can't collide with them) — operators that produce new coverage get picked
more often over the course of a run.

---

## Producer/consumer binding (nested, tenant-aware)

A body leaf shaped like an id (`customerId`, `organizationId`, …) is resolved through a
three-tier fallback, each tier already independently safe:

1. **Path-qualified `RuntimeStore` lookup** — keyed by `resourceType + "." + dotted schema path`, so two different nested `id` fields under different parents (`order.customer.id` vs. `order.shipping.id`) never collide in one bucket the way a flat key would.
2. **Tenant-scoped resource graph** — `findCompatibleResourcesInTenant`, the same tenant-aware lookup path-parameter substitution already used, now reachable from body fields too. A request rendered inside a chain scoped to tenant A will never bind tenant B's id into a nested body field.
3. **Flat dictionary pool** — the pre-existing, non-tenant-scoped fallback, unchanged, used when neither of the above has a better answer.

---

## Which command finds which kind of bug

These aren't hypothetical — they're the exact flags used for the measured comparison below.

```bash
# Reach as much business logic as possible, minimize deliberate corruption --
# best when you want COVERAGE and workflow depth, not raw crash count.
# (equivalent to -profile deep's default balance)
./void -grammar grammars/myapi -auth-file auth.json \
  -typed-body-mutation=true -adversarial-body-rate 0.2 \
  -time-budget 30

# Maximize structural-violation pressure -- best for hunting mass assignment,
# discriminator confusion, and off-by-one constraint bugs specifically.
# (this is what -profile security sets by default: 0.75)
./void -grammar grammars/myapi -auth-file auth.json \
  -typed-body-mutation=true -adversarial-body-rate 0.9 \
  -time-budget 30

# Legacy flat-JSON mutator, unconditionally -- for an apples-to-apples
# comparison, a CI smoke run prioritizing raw throughput (-profile fast's
# default), or reproducing pre-2026-07-31 behavior exactly.
./void -grammar grammars/myapi -auth-file auth.json \
  -typed-body-mutation=false \
  -time-budget 30
```

### Profile defaults

`-profile` (see `cmd/void/README.md`) sets both knobs for you, tuned to each profile's own
stated goal — pass either flag explicitly alongside a profile to override just that one:

| Profile | `-typed-body-mutation` | `-adversarial-body-rate` | Why |
|---|---|---|---|
| `fast` | `false` | — | Typed mode measurably costs throughput (schema-correct bodies reach real business logic instead of failing fast on malformed JSON — see latency numbers below); the wrong trade for a throughput-first CI smoke profile. |
| `deep` | `true` | `0.5` (the flag's own default, set explicitly for self-documentation) | Balanced: half the mutate/havoc-epoch renders stay schema-correct (maximize business-logic depth), half apply one structural violation. |
| `security` | `true` | `0.75` | Vulnerability-hunting wants more single-violation pressure than the flag's own default, mirroring the `-access-probe-prob 0.75` bump this profile already makes elsewhere. |

---

## Measured example: typed vs. flat on a real target

**Not a synthetic benchmark.** Both arms below ran the real fuzzer against a real,
freshly-seeded, coverage-instrumented Bitwarden `server` checkout (602 compiled templates,
294 with a `body_schema`) — same grammar, same two seeded identities, same 10-minute budget,
same `-seed 42`, fresh migrated-empty database per arm (full `docker compose down -v && up -d`
+ re-seed between runs, not just a container restart, since the data volume otherwise
persists across restarts):

```bash
# flat arm
TARGET_HOST=http://localhost:4100 ./void \
  -grammar grammars/bitwarden -auth-file auth.identities.json -identity-mode weighted \
  -time-budget 10 -seed 42 -typed-body-mutation=false \
  -event-log events.jsonl -summary-file summary.json -report-file report.json

# typed arm -- identical command, just the one flag flipped
TARGET_HOST=http://localhost:4100 ./void \
  -grammar grammars/bitwarden -auth-file auth.identities.json -identity-mode weighted \
  -time-budget 10 -seed 42 -typed-body-mutation=true \
  -event-log events.jsonl -summary-file summary.json -report-file report.json
```

| metric | flat (legacy) | typed | delta |
|---|--:|--:|--:|
| requests done | 157,607 | 101,712 | **−35%** |
| coverage edges reached | 136,181 | **224,816** | **+65%** |
| avg latency / request | 70ms | 314ms | +4.5× |
| crashes total / unique | 31,886 / 2,248 | 12,949 / 1,897 | lower |
| distinct root causes (real bug count) | 58 | 55 | ~wash |
| **confirmed-bug rate** (`confirmed_unhandled_exception` ÷ all crashes) | 3.28% | **9.27%** | **~2.8×** |
| workflows persisted (full multi-step chains completed) | 37 | 16 | lower (throughput-bound this run) |

### What this actually means — read the whole table, not just one row

**Typed mode is not simply "better" — it's a different, deliberate trade.** It sent 35%
fewer requests in the same 10 minutes, yet reached 65% more code and produced a crash stream
where confirmed real bugs were ~2.8× more common relative to noise. The latency jump (70ms →
314ms) is the actual mechanism, not a side effect: schema-correct bodies clear
model-binding/validation and reach real database writes and business logic far more often,
instead of failing fast on malformed JSON the way the legacy mutator's blind byte corruption
usually does. Fewer, slower, deeper requests — that's the trade, and it shows up
consistently across every coverage/quality metric.

**It is not a strict superset of the legacy mutator.** Of 14 confirmed distinct bugs found
across both arms, 9 were found by *both*; each found 5 the other didn't. The legacy mutator
caught two device-registration `SqlException`/uniqueness bugs typed missed this run; typed
caught (among others) a `NullReferenceException` on a nested array-of-objects report
endpoint (`POST /reports/password-health-report-applications`) that the legacy mutator never
hit. Direct operator attribution: 15.8% of all typed-run requests carried a structural
mutation label, and of the structural-labeled crashes specifically, 152 mapped to confirmed
real bugs against only 2 mapped to noise.

**This is target-dependent, and an earlier, smaller demo-app comparison showed a murkier
picture** — that target's easy bugs were mostly path/ID-driven, not body-validity-gated, so
schema-aware body mutation had little to bite into and the comparison there was dominated by
scheduler noise unrelated to this feature at all (zero crashes in either arm carried a
structural-mutation label). The lesson: this feature's value is real but conditional on the
target actually gating interesting behavior behind valid nested structure — which is exactly
the class of target it exists for.

---

## Backward compatibility

Every change is additive: a new optional `body_schema` field on `Template` (`omitempty`,
absent on any grammar compiled before this existed), a new `BodyTree` field on `WorkItem`
(nil unless both the grammar declares `body_schema` and `-typed-body-mutation` is on), and a
single added guard clause on the pre-existing `mutateJSONBody`/`minimizeJSONBody` calls so
they never run on a typed template. `arxiv/` is untouched. Recompile an old grammar with the
current `grammarc` to get `body_schema` for free — no CLI or template-format change required.

## Known v1 scope limits

- **No regex/pattern satisfaction.** `constraint_boundary`/type-substitution synthesize
  enum/length/numeric edge values but never attempt to actually satisfy a declared `pattern`
  — the same disclosed limit the pre-existing untyped `fieldConstraintStringCandidates` has.
- **No cross-seed splicing.** Each operator mutates one render's own tree; there's no
  JSON-subtree crossing between two different seeds' bodies (same limit the untyped splicing
  epoch already has).
- **`nesting_depth`'s valid-mode variant only fires on a genuinely recursive schema** (e.g. a
  comment-thread-shaped self-reference) — most real schemas aren't recursive, so in practice
  only its adversarial variant (which needs no recursion) will show up in most runs.
