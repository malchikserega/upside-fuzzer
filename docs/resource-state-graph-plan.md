# Resource State Graph & Generalized Extraction — Design Plan

Companion to [`resource-state-graph-report.md`](resource-state-graph-report.md) (written after
implementation, with measured results). This document describes the current implementation, its
concrete limitations, the proposed design, and — stated honestly up front — the scope actually
implemented in this pass versus what is deferred as future work. A project of this size, done properly
by a team, spans weeks; this document draws an honest line around what a single verified,
tested, integrated pass can responsibly deliver without inventing untested functionality.

---

## 1. Current architecture (as of this pass's starting point)

Three subsystems, as documented in `docs/ARCHITECTURE.md`/`docs/ARCHITECTURE_REVIEW.md`:

1. **`fuzzprep`/`grammarc`** (Python, compile-time) — parses the OpenAPI spec, infers producer/consumer
   relationships by **path and name convention only** (`grammarc/dependencies.py`), writes
   `templates.export.json`'s per-template `reads`/`writes` string lists.
2. **`void/go`** (Go, runtime) — the actual fuzzing engine. `sequence.go` is where stateful chaining
   lives today.

This plan concerns **runtime behavior only** (`void/go/`). The Python grammar compiler's
`dependencies.py` is deliberately left unchanged — see §9 ("What is explicitly out of scope").

## 2. Current sequence-context model (`sequence.go`, `types.go`)

- `SequenceState` (`types.go:354`): `{ID, Depth, Values map[string]string, Provenance map[string]string,
  History []SequenceStep, Energy float64}`. `Values`/`Provenance` are a **flat, untyped key→value map**
  scoped to one branch of one chain — no resource type, no lifecycle, no distinction between "this key
  refers to a User" vs "this key refers to an Order."
- A chain is extended by `enqueueSequenceFollowups` (`sequence.go:26`): on every successful step it
  extracts entity ids (`extractEntityIDs`), looks up statically-known consumers
  (`f.depConsumers`/`f.idConsumers`, populated once at startup from the grammar's `reads`/`writes`, plus
  a same-path-family runtime fallback in `findFollowups`), and fans out up to `-sequence-fanout` (default
  6) follow-up requests, +1 if the step reached a never-seen **shape signature**.

## 3. Current shape-signature behavior (`sequenceStateSignature`, `sequence.go:292`)

A chain's "state" is the ordered list of `(method, normalized-path, status-class)` triples across its
whole history — e.g. `"POST /orders:2 | GET /orders/{id}:2 | PUT /orders/{id}:4"`. This is coarse by
explicit prior design (`docs/ARCHITECTURE_REVIEW.md` calls it out directly): it cannot distinguish
*why* a `GET` after a `DELETE` returned 404 (resource genuinely gone vs. never existed vs. a filter
rejecting the request) from any other 4xx-ending chain with the same method/path/status-class shape. It
has no concept of resource identity, resource type, parent/child relationships, or lifecycle at all —
two completely unrelated resources going through unrelated CRUD chains can produce identical shape
signatures.

## 4. Current extraction rules (`extractEntityIDs`, `extractJSONRuntimeValues`, `sequence.go`)

This is the weakness #2 in scope. Concretely, today's extraction:

- `extractEntityIDs` (`sequence.go:744`): checks **only** `body["id"]`, `body["Id"]`, `body["data"][].id`,
  `body["data"][].Id`, and the last path segment of a `Location`/`location` header. Nothing else.
- `extractJSONRuntimeValues` (`sequence.go:685`, feeds the separate `RuntimeStore` value pool, not
  `SequenceState`): slightly broader — any key whose canonical form ends in `"id"`, or matches a fixed
  list `runtimeLearnKeys = {id, code, name, externalid, status, type, revision, key, slug}`. Still a
  **fixed name list**, not schema/structure-aware.
- `inferResourceIDKeyFromPath` (`sequence.go:655`): derives a dependency key by singularizing the last
  non-numeric, non-`{param}` path segment and appending `"Id"` — e.g. `/users/123` → `"userId"`. Works
  for conventional REST paths; produces nothing useful for `/users/{slug}` where the *canonical* path
  segment itself (not a numeric id) is the actual identifier, or for nested/composite paths.
- `isIDLikeKey` (`utils.go:663`): `canonicalKey(k) == "id" || strings.HasSuffix(canonicalKey(k), "id")`
  — the literal "larger list of field-name patterns" this task explicitly says not to just extend.

None of the following are extracted today: HAL `_links`, JSON:API `relationships`, `Link`/`ETag`/
`Content-Location` headers, URI path-template-aware segment typing (a URI is only ever treated as "take
the last path segment"), or any value recognized by *shape* (UUID, slug, opaque token) rather than by
field name.

## 5. Current producer-consumer inference (`grammarc/dependencies.py`, `f.depConsumers`/`f.idConsumers`)

Compile-time: a resource's "own id key" is derived from its path's last static segment
(singularized); a bare `"id"` path param/body field is renamed to that key; a compound `"fooId"` field
keeps its own name (free correlation *if* `foo` happens to also be a fuzzed resource family). This is a
**name/path-convention** system by the module's own explicit documentation — no schema-format awareness
(`format: uuid`), no response-schema relationship modeling. It is retained unchanged in this pass — see
§9.

Runtime: `f.depIndex`/`f.depConsumers`/`f.idConsumers` (`fuzzer.go:489`) are built once, at startup, purely
from the grammar's `reads`/`writes` plus the same `isIDLikeKey`/`inferDependencyKeys` name-based logic.
`findFollowups`'s same-path-family fallback (`sequence.go:394`) is the one already-existing
resource-type-agnostic signal — matching candidates by path-template prefix rather than by name — and is
kept and built upon, not replaced.

## 6. Current fanout algorithm (`findFollowups`, `followupPriority`, `sequence.go:361`)

Purely static: a hardcoded verb-affinity score table (`POST→GET` favored over `POST→DELETE`, etc.) plus
two small tie-break bonuses (same-normalized-path GET, longer path, path-param presence). **Zero
reference to coverage, historical yield, or novelty** anywhere in the scoring — the one coverage-adjacent
mechanism today is the flat `fanout+1` bonus for reaching a never-seen *shape* signature (§3), which
affects fanout *width* for the current step only, not which *specific* candidate consumers get
prioritized.

## 7. Identified design limitations (this pass's actual targets)

1. No resource type, canonical/alias identity, or lifecycle state — only a coarse per-chain shape string.
2. Extraction is a fixed field-name list; anything shaped differently (GUID under `"reference"`, HAL
   `_links.self.href`, JSON:API `relationships`) is invisible to the sequence engine.
3. Fanout ordering never looks at actual coverage yield or reachedness — a consumer that has produced 40
   new edges historically and one that has never once been reached score identically if their
   verb-affinity happens to match.
4. No concept of "deliberately explore an invalid transition" (GET-after-DELETE, UPDATE-after-DELETE) as
   a *distinct, prioritized* class from an ordinary next step — today it's just "another consumer,"
   indistinguishable in the fanout order from a valid one.

## 8. Proposed design

### 8.1 Typed resource identity & lifecycle model (new `void/go/resource_graph.go`)

```go
type LifecycleState int // Unknown, Discovered, Created, Readable, Modified, Deleted,
                         // Invalidated, FailedCreation, FailedModification, FailedDeletion, Stale

type ResourceIdentity struct {
    ResourceType    string  // "user", "order" — inferred, never bare "id"
    IdentityKind    string  // "scalar" | "uri" | "composite" | "opaque"
    NormalizedValue string  // namespaced: resourceType+kind+value, so identity is never
                            // compared across unrelated resource types by scalar value alone
    RawValue        string
    SourcePath      string  // JSON path / header name / link relation this came from
    Confidence      float64
}

type ResourceInstance struct {
    ResourceType   string
    Canonical      ResourceIdentity
    Aliases        []ResourceIdentity
    SourceOperation string
    CreatedInSeq   string
    LatestRepr     string           // bounded/truncated last-seen JSON representation
    Links          map[string]string // relation name -> URI
    ParentKey      string
    ChildKeys      []string
    Lifecycle      LifecycleState
    Confidence     float64
    ObservedCount  int
    LastSeenSeq    uint64            // logical execution order, not wall clock (deterministic under -seed)
}

type ResourceTransition struct {
    From, To                    LifecycleState
    ProducerOp, ConsumerOp      string
    SequenceID                  string
    StatusCode, CoverageDelta   int
    Result                      string // "valid" | "invalid" | "unknown"
    Order                        uint64
    Identities                  []ResourceIdentity
    Confidence                  float64
    FailureReason                string
}
```

`ResourceGraph` (bounded, mutex-protected — see §8.5) owns `map[string]*ResourceInstance` keyed by
`ResourceType + "|" + NormalizedValue`, a ring-bounded transition log, and per-type/alias/transition
count limits enforced on insert (oldest/lowest-confidence evicted first). **Explicitly namespaced by
resource type** — `id=1` for a `user` and `id=1` for an `order` are different graph keys by construction,
directly addressing the "do not merge identifiers across unrelated resource types" constraint.

Lifecycle is derived from a **combination** of signals, never HTTP method alone: the request method, the
response status class, whether this is the first observation of this identity or a repeat, the prior
recorded lifecycle state for this identity (if any), and (where declared) the endpoint's own OpenAPI
semantics already available via `f.responseSchemas`. E.g. a `GET` immediately following a recorded
`Deleted` state, returning 404, is classified as a `stale/deleted-reference` observation, not just
"another failed GET."

### 8.2 Generalized extraction pipeline (new `void/go/resource_extraction.go`)

A layered pipeline producing `ExtractedCandidate{RawValue, NormalizedValue, ValueType, ResourceType,
SourceOperation, JSONPath, HeaderName, LinkRelation, SchemaPath, Strategy, Confidence}` from each
response, replacing the fixed `extractEntityIDs`/`isIDLikeKey` name-list with:

1. **Structural extraction** — reuses the shape-detection regexes this codebase *already has* for a
   different purpose (`oracle.go`/`minimize.go`'s `reUUIDLike`/`reHexLong`/`reBizIDLike`/`reAllDigits`,
   `utils.go`): any scalar value matching a UUID, long-hex, digit, or dashed-business-id shape is a
   candidate **regardless of its field name** — this is the mechanism that makes `reference`,
   `resourceRef`, or a domain-specific field with zero `"id"` substring extractable at all.
2. **Header extraction** — `Location`, `Content-Location` (URI, parsed structurally, not
   `strings.Split` on `/`), `Link` (RFC 8288 `<uri>; rel="..."` parsing), `ETag` (as an alias/version
   signal, not an identity).
3. **HAL extraction** — `_links.<relation>.href` (both single-object and array-of-link forms).
4. **JSON:API extraction** — `data.type`+`data.id`, and `data.relationships.<rel>.data.{type,id}`.
5. **URI + route-template extraction** — any URI found by 2–4 above is matched against the engine's own
   already-known route templates (`f.activeIDs`/`f.meta[tid].Norm`) instead of naively taking the final
   path segment, so `/organizations/{orgId}/projects/{projectSlug}` correctly yields **two** typed
   candidates, not one.

Every candidate carries **provenance and a confidence score** (§8.4) — no silent "just believe it's an
id." Structural-only matches (shape but no header/link/schema corroboration) get the lowest confidence
tier; HAL/JSON:API/Location-header matches (structurally declared as a reference by the response format
itself) get the highest.

### 8.3 Producer-consumer compatibility scoring

Replaces `isIDLikeKey`+name-equality with a scored model: exact typed resource-type match > declared
link-relation match > route-template match > schema-format match (`uuid`, `slug`) > value-shape match >
name similarity (kept as the lowest-weight signal, not removed — some real APIs genuinely only have name
correlation to go on, and the existing `depConsumers`/`idConsumers`/same-family fallback already covers
this case reasonably well today, so it stays as a fallback tier, not the primary mechanism).

### 8.4 Coverage-directed consumer fanout

`findFollowups`'s final `sort.SliceStable(..., followupPriority)` is replaced by a scoring function
blending real, already-tracked signals — reusing `f.endpointStats[epKey].NewEdges` (this project already
tracks per-endpoint historical coverage yield; no new tracking needed) for "historical coverage yield,"
a new `f.reachedViaSequence map[int]bool` for "never reached," the resource graph's own novel-transition
detection for "novel binding," and the existing verb-affinity table as one input among several rather
than the sole signal. Deliberately-invalid-transition candidates (GET-after-Deleted, UPDATE-after-Deleted)
are *not* filtered out — they get their own scoring bucket so they're explored with real but bounded
priority, not treated identically to ordinary valid-workflow continuation.

Starvation prevention: a small epsilon-random component in the final selection (not just top-N by score)
so a lower-scored candidate still gets picked occasionally — this is a bounded, seeded-deterministic
random draw (respects `-seed`), not unbounded nondeterminism.

### 8.5 Concurrency ownership

Verified directly in the existing code (`worker.go`): `enqueueSequenceFollowups`, `learnFromResponse`,
and `learnFromRequestContext` are called **only** from `handleResult`, which is called **only** from
`mainLoop`'s own `select` — i.e., always on the single main-loop goroutine, never from a worker goroutine
(workers only call `f.sendOne`, writing results to a channel `handleResult` drains). This matches the
existing documented pattern for `f.seenStateSigs`/`f.persistedWorkflowSigs` (plain maps, no mutex, by the
same reasoning). The new `ResourceGraph` follows the identical ownership model — mutated only from that
goroutine — but still carries a `sync.Mutex` defensively (cheap, and removes any future risk if a call
site changes), verified with `-race` under both single-goroutine and a deliberately-adversarial
concurrent-caller test (§10).

## 9. What is explicitly out of scope for this pass, and why

- **`grammarc/dependencies.py` (the Python compile-time producer/consumer inference) is left
  unchanged.** It already documents its own name/path-convention limitation and is explicitly designed
  to degrade gracefully — the Go runtime side already independently re-derives its own producer/consumer
  signal and does not trust the Python side's `reads`/`writes` alone (see `docs/AI_CONTEXT.md`: "Void
  tracks dynamic identifiers two ways simultaneously"). Every capability this plan adds (HAL/JSON:API/
  header/structural extraction, lifecycle tracking, coverage-directed scoring) is a **runtime**
  behavior — the responses being parsed don't exist at grammar-compile time. Rewriting the Python
  compiler to also understand HAL/JSON:API would be a second, largely redundant project layered on
  top of a compile-time model that cannot see live response shapes anyway.
- **A full combinatorial state-graph search (DeepREST/EvoMaster-class)** is not attempted — this pass
  builds the typed resource/lifecycle *model* and *coverage-directed scoring*, which is the
  prerequisite infrastructure, not the full reinforcement-learned search algorithm.
- **Composite/multi-field identity keys** (e.g. `{tenant, user}` pairs) are modeled at the
  `ResourceIdentity.IdentityKind == "composite"` level (a normalized composite-key string), but a full
  general-purpose multi-field-correlation inference engine is not built — composite identities are
  recognized when they arrive pre-composed (e.g. a JSON:API compound id, or a nested object under a
  single field), not synthesized by correlating unrelated sibling fields.

## 10. Compatibility risks & mitigations

- **`SequenceState`'s persisted JSON shape** (`persistWorkflow`) gains new optional fields
  (`Resources`, `Transitions` — see §8.1) — additive, `omitempty`-tagged, so old workflow JSON files
  remain readable (Go's `json.Unmarshal` simply leaves new fields at their zero value when reading an
  old file; nothing in this codebase currently re-reads persisted workflow JSON programmatically, so
  this is a pure write-side addition with no read-compatibility surface to break).
- **`findFollowups`'s output ordering changes** (coverage-directed instead of purely static) — this is a
  deliberate, intended behavior change for the sequence engine's own exploration order. It does not
  change any on-the-wire request format, `templates.export.json`/`dict.json` schema, or CLI flag
  semantics; existing flags (`-sequence-fanout`, `-sequence-max-depth`, `-sequence-prob`) keep their
  exact current meaning. New behavior is entirely opt-out via `-resource-graph-enabled=false`, which
  falls back to the exact previous `followupPriority`-only ordering — verified by keeping that function
  intact and only bypassing it when the new path is enabled.
- **No existing CLI flag, report field, or `/shm/*` HTTP contract changes.**

## 11. Migration strategy

Purely additive at the code level: new files (`resource_graph.go`, `resource_extraction.go`, plus test
files), new `Fuzzer` struct field (`resourceGraph *ResourceGraph`), new optional `SequenceState` fields,
new CLI flags with defaults that enable the new behavior (since it strictly extends rather than replaces
what already works — the old name/path-based extraction and same-family fallback remain intact and run
first; the new pipeline adds candidates on top of them, and the new scoring blends in the old
verb-affinity table as one term rather than deleting it). No existing function signature changes in a
way that breaks a caller; `followupPriority` is retained unchanged and reused inside the new scoring
function.

## 12. Testing strategy

Per Phase 10 of the task: unit tests for identity normalization/typed isolation/alias merging/URI &
route-template matching/HAL/JSON:API/header extraction/confidence scoring; regression tests proving a
chain now completes for guid/slug/reference/Location-header/HAL-link/JSON:API-relationship/nested-
composite-key/domain-specific-no-"id"-substring identifiers that the *old* `extractEntityIDs`-only path
provably cannot extract (each regression test first asserts the *old* function returns nothing for that
input, then asserts the *new* pipeline does); lifecycle-transition classification tests
(create→read/update/delete/delete→read/delete→update/delete→delete/parent→child/alias reuse/same-scalar-
different-resource-type-isolation); scheduling tests (unreached-consumer priority, coverage-reward,
failure-penalty, non-starvation, seeded determinism, fanout-limit enforcement); an integration test using
an in-process `httptest` fixture server modeling a small multi-style API (conventional ids, GUIDs, HAL
links, a parent/child pair) proving the new pipeline builds chains the old one cannot; `-race` on the
new package's own tests plus a concurrent-caller adversarial test for `ResourceGraph`.

## 13. Benchmark strategy

Per Phase 11: a Go benchmark comparing extraction candidate *count and correctness* (not raw ns/op, which
is not the interesting number here) between the old `extractEntityIDs` and the new pipeline against a
fixed corpus of representative response bodies (plain `id`, GUID, slug, HAL, JSON:API, nested composite);
a scheduling-overhead benchmark (ns/op for the new `scoreConsumer`-based ranking vs. the old
`followupPriority`-based sort, to confirm the new path doesn't measurably regress the sequence engine's
own throughput); and, where feasible without a live external target, an in-process fixture-server-based
comparison of "number of distinct lifecycle transitions/valid chains discovered in N requests" old vs.
new. All numbers reported in `docs/resource-state-graph-report.md` are measured; anything not directly
measured is explicitly labeled as an architectural/expected benefit, not a claimed number.
