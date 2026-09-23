package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// resource_graph.go — a typed resource-lifecycle state graph, replacing the coarse
// per-chain shape signature (sequenceStateSignature, sequence.go) as the primary
// state model for stateful fuzzing. See docs/resource-state-graph-plan.md for the
// full design rationale.
//
// Ownership: mutated only from enqueueSequenceFollowups (sequence.go), which is
// itself called only from handleResult (worker.go), which is called only from
// mainLoop's own select -- i.e. always on the single main-loop goroutine, never
// concurrently with itself (verified directly against worker.go/sequence.go call
// graphs; matches the existing, established ownership model for f.seenStateSigs/
// f.persistedWorkflowExemplars, which are plain unsynchronized maps for the identical
// reason). ResourceGraph still carries a mutex defensively -- cheap, and removes
// any future risk if a call site changes -- verified safe under -race by
// resource_graph_test.go's adversarial concurrent-caller test.

// LifecycleState models where a resource instance is understood to be in its
// lifecycle, derived from a combination of signals (method, status class, prior
// recorded state, repeat-vs-first observation) -- never from HTTP method alone.
type LifecycleState int

const (
	LifecycleUnknown LifecycleState = iota
	LifecycleDiscovered
	LifecycleCreated
	LifecycleReadable
	LifecycleModified
	LifecycleDeleted
	LifecycleInvalidated
	LifecycleFailedCreation
	LifecycleFailedModification
	LifecycleFailedDeletion
	LifecycleStale
)

func (s LifecycleState) String() string {
	switch s {
	case LifecycleDiscovered:
		return "DISCOVERED"
	case LifecycleCreated:
		return "CREATED"
	case LifecycleReadable:
		return "READABLE"
	case LifecycleModified:
		return "MODIFIED"
	case LifecycleDeleted:
		return "DELETED"
	case LifecycleInvalidated:
		return "INVALIDATED"
	case LifecycleFailedCreation:
		return "FAILED_CREATION"
	case LifecycleFailedModification:
		return "FAILED_MODIFICATION"
	case LifecycleFailedDeletion:
		return "FAILED_DELETION"
	case LifecycleStale:
		return "STALE"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON renders the lifecycle state as its name, not its integer value, so
// persisted workflow JSON (persistWorkflow) is human-readable without a lookup table.
func (s LifecycleState) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// lifecycleStateFromString is MarshalJSON/String's inverse, used by
// UnmarshalJSON below (and directly testable on its own). Unknown/malformed
// names decode to LifecycleUnknown rather than erroring -- a checkpoint file
// from a newer engine version with a lifecycle name this build doesn't know
// about should degrade gracefully, not abort the whole resume.
func lifecycleStateFromString(s string) LifecycleState {
	switch s {
	case "DISCOVERED":
		return LifecycleDiscovered
	case "CREATED":
		return LifecycleCreated
	case "READABLE":
		return LifecycleReadable
	case "MODIFIED":
		return LifecycleModified
	case "DELETED":
		return LifecycleDeleted
	case "INVALIDATED":
		return LifecycleInvalidated
	case "FAILED_CREATION":
		return LifecycleFailedCreation
	case "FAILED_MODIFICATION":
		return LifecycleFailedModification
	case "FAILED_DELETION":
		return LifecycleFailedDeletion
	case "STALE":
		return LifecycleStale
	default:
		return LifecycleUnknown
	}
}

// UnmarshalJSON is MarshalJSON's counterpart -- without it, LifecycleState
// (an int-based type marshaled as its string name) fails to round-trip
// through JSON at all, which checkpoint.go's resume path depends on.
func (s *LifecycleState) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	*s = lifecycleStateFromString(name)
	return nil
}

// ResourceIdentity is a single reference to a resource, namespaced by resource
// type so a scalar value is never compared across unrelated resource types (a
// `user` with id "1" and an `order` with id "1" are different identities by
// construction -- NormalizedValue always embeds ResourceType).
type ResourceIdentity struct {
	ResourceType    string  `json:"resource_type"`
	IdentityKind    string  `json:"identity_kind"` // "scalar" | "uri" | "composite" | "opaque"
	NormalizedValue string  `json:"normalized_value"`
	RawValue        string  `json:"raw_value"`
	SourcePath      string  `json:"source_path"` // JSON path / header name / link relation
	Confidence      float64 `json:"confidence"`
}

// graphKey is the ResourceGraph's map key for this identity's owning instance.
func (id ResourceIdentity) graphKey() string {
	return id.ResourceType + "|" + id.NormalizedValue
}

// normalizeResourceValue produces an identity's NormalizedValue, always
// namespaced by resource type and identity kind so identical scalar values for
// different resource types can never collide in the graph.
func normalizeResourceValue(resourceType, identityKind, raw string) string {
	return resourceType + ":" + identityKind + ":" + strings.TrimSpace(raw)
}

// ResourceInstance is a concrete resource observed during fuzzing.
type ResourceInstance struct {
	ResourceType    string             `json:"resource_type"`
	Canonical       ResourceIdentity   `json:"canonical"`
	Aliases         []ResourceIdentity `json:"aliases,omitempty"`
	SourceOperation string             `json:"source_operation"`
	CreatedInSeq    string             `json:"created_in_sequence,omitempty"`
	LatestRepr      string             `json:"latest_representation,omitempty"`
	Links           map[string]string  `json:"links,omitempty"` // relation -> URI
	ParentKey       string             `json:"parent_key,omitempty"`
	ChildKeys       []string           `json:"child_keys,omitempty"`
	// TenantKey is the graph key of the root ancestor reached by walking
	// ParentKey to its end (resolveTenantKey), distinct from ParentKey itself
	// once a chain is more than one level deep -- e.g. for
	// project -> workspace -> organization, TenantKey is the organization, not
	// the immediate workspace parent. Empty until at least one parent link has
	// been recorded for this instance.
	TenantKey string `json:"tenant_key,omitempty"`
	// OwnerIdentity is the auth identity (WorkItem.Identity) that FIRST
	// created this instance. First-writer-wins: a later re-observation by a
	// different identity (e.g. cross-tenant probe traffic) never overwrites
	// it, so this stays a reliable "who actually owns this" signal for BOLA
	// and mass-assignment oracles rather than getting silently relabeled.
	OwnerIdentity string `json:"owner_identity,omitempty"`
	// Version is the most recently observed ETag/version-like header value,
	// refreshed on every re-observation -- the optimistic-locking signal the
	// stale-ETag oracle family needs (a write replayed with an out-of-date
	// Version should be rejected).
	Version string `json:"version,omitempty"`
	// Attributes is a small, bounded snapshot of the resource's own
	// top-level scalar response fields (e.g. {"status": "draft"}), refreshed
	// on every re-observation -- lets oracles (workflow-bypass, stale-object)
	// inspect the resource's own declared state, not just the lifecycle this
	// engine independently derives from method+status.
	Attributes    map[string]any `json:"attributes,omitempty"`
	Lifecycle     LifecycleState `json:"lifecycle"`
	Confidence    float64        `json:"confidence"`
	ObservedCount int            `json:"observed_count"`
	LastSeenOrder uint64         `json:"last_seen_order"`
}

// ResourceTransition records one lifecycle transition observed for one or more
// identities during a sequence step.
type ResourceTransition struct {
	From LifecycleState `json:"from"`
	To   LifecycleState `json:"to"`
	// Action names the specific business operation this step performed,
	// beyond the coarse From/To lifecycle state -- e.g. "approve" vs
	// "refund", both POST, both a MODIFIED transition, but different actions
	// (deriveTransitionAction, resource_scheduling.go). HTTP method alone is
	// a weak signal by design (POST /orders/{id}/approve and
	// POST /orders/{id}/refund are both POST but completely different
	// transitions) -- Action is what makes a transition typed
	// ("invoice:sent --pay--> invoice:paid") rather than just "POST -> POST".
	Action        string             `json:"action,omitempty"`
	ProducerOp    string             `json:"producer_op,omitempty"`
	ConsumerOp    string             `json:"consumer_op"`
	SequenceID    string             `json:"sequence_id"`
	StatusCode    int                `json:"status_code"`
	CoverageDelta int                `json:"coverage_delta"`
	Result        string             `json:"result"` // "valid" | "invalid" | "unknown"
	Order         uint64             `json:"order"`
	Identities    []ResourceIdentity `json:"identities,omitempty"`
	Confidence    float64            `json:"confidence"`
	FailureReason string             `json:"failure_reason,omitempty"`
}

// signature is a coarse (from,to,consumer-op-shape) key used for "has this exact
// transition ever been seen" novelty detection -- deliberately much finer-grained
// than sequenceStateSignature's whole-chain shape, but still bounded (not keyed by
// concrete identity, so it doesn't grow per-resource-instance). Keyed on ConsumerOp
// (which already embeds any action-suffix path segment), not Action, so novelty
// detection stays at its existing granularity -- Action is an additive, more
// readable label for reporting, not a replacement signal.
func (t ResourceTransition) signature() string {
	return fmt.Sprintf("%s->%s|%s", t.From, t.To, t.ConsumerOp)
}

// TransitionLabel renders a human-readable "type:from --action--> type:to"
// label matching the target design's typed-transition format (e.g.
// "invoice:sent --pay--> invoice:paid"), for reports and the E2E fixture
// matrix. Falls back to "?" for Action when unset (transitions recorded
// before this field existed, or via a code path that doesn't populate it).
func (t ResourceTransition) TransitionLabel(resourceType string) string {
	action := t.Action
	if action == "" {
		action = "?"
	}
	return fmt.Sprintf("%s:%s --%s--> %s:%s", resourceType, t.From, action, resourceType, t.To)
}

// ResourceGraphLimits bounds the graph's memory growth. Zero values fall back to
// the defaults in newResourceGraph.
type ResourceGraphLimits struct {
	MaxInstancesPerType   int
	MaxAliasesPerInstance int
	MaxTransitions        int
}

const (
	defaultMaxInstancesPerType   = 500
	defaultMaxAliasesPerInstance = 16
	defaultMaxTransitions        = 5000
)

// ResourceGraph is the bounded, typed resource-lifecycle model for one fuzzing run.
type ResourceGraph struct {
	mu sync.Mutex

	limits ResourceGraphLimits

	instances map[string]*ResourceInstance // key: ResourceIdentity.graphKey()
	byType    map[string][]string          // resourceType -> instance keys, insertion order

	transitions    []ResourceTransition // ring-bounded at limits.MaxTransitions
	seenTransition map[string]struct{}  // transition signature -> seen (novelty detection)

	// reachedConsumer counts how many times each template id has been selected as
	// a sequence follow-up consumer -- the "never reached" scheduling signal.
	reachedConsumer map[int]int
	// failedConsumer counts consecutive 4xx/5xx results for a template id when
	// used as a sequence consumer -- the "repeated failure" scheduling penalty.
	failedConsumer map[int]int

	order uint64 // monotonic logical clock, deterministic under -seed (not wall time)
}

func newResourceGraph(limits ResourceGraphLimits) *ResourceGraph {
	if limits.MaxInstancesPerType <= 0 {
		limits.MaxInstancesPerType = defaultMaxInstancesPerType
	}
	if limits.MaxAliasesPerInstance <= 0 {
		limits.MaxAliasesPerInstance = defaultMaxAliasesPerInstance
	}
	if limits.MaxTransitions <= 0 {
		limits.MaxTransitions = defaultMaxTransitions
	}
	return &ResourceGraph{
		limits:          limits,
		instances:       make(map[string]*ResourceInstance),
		byType:          make(map[string][]string),
		seenTransition:  make(map[string]struct{}),
		reachedConsumer: make(map[int]int),
		failedConsumer:  make(map[int]int),
	}
}

// nextOrder returns a monotonically increasing logical clock value, used instead
// of wall-clock time so ordering stays deterministic under a fixed -seed.
func (g *ResourceGraph) nextOrder() uint64 {
	g.order++
	return g.order
}

// RecordInstanceOpts carries recordInstance's optional provenance fields
// (owner identity, version, attributes). Kept as a variadic options struct
// rather than growing recordInstance's positional signature, so the many
// existing call sites (tests included) that don't care about these fields are
// unaffected.
type RecordInstanceOpts struct {
	OwnerIdentity string
	Version       string
	Attributes    map[string]any
}

// recordInstance upserts a resource instance by its canonical identity, bumping
// ObservedCount/LastSeenOrder and merging in a new lifecycle state (via
// transitionLifecycle's own from/to bookkeeping -- callers pass the *new* state
// here and record a transition separately via recordTransition). Enforces
// limits.MaxInstancesPerType by evicting the least-recently-seen, lowest-
// confidence instance of that type when over the cap.
func (g *ResourceGraph) recordInstance(id ResourceIdentity, sourceOp, seqID string, lifecycle LifecycleState, confidence float64, opts ...RecordInstanceOpts) *ResourceInstance {
	var o RecordInstanceOpts
	if len(opts) > 0 {
		o = opts[0]
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	key := id.graphKey()
	if inst, ok := g.instances[key]; ok {
		inst.ObservedCount++
		inst.LastSeenOrder = g.nextOrder()
		if confidence > inst.Confidence {
			inst.Confidence = confidence
		}
		if lifecycle != LifecycleUnknown {
			inst.Lifecycle = lifecycle
		}
		if inst.OwnerIdentity == "" && o.OwnerIdentity != "" {
			inst.OwnerIdentity = o.OwnerIdentity // first-writer-wins -- never relabel an established owner
		}
		if o.Version != "" {
			inst.Version = o.Version
		}
		if len(o.Attributes) > 0 {
			inst.Attributes = o.Attributes
		}
		return inst
	}

	g.evictIfOverCap(id.ResourceType)

	inst := &ResourceInstance{
		ResourceType:    id.ResourceType,
		Canonical:       id,
		SourceOperation: sourceOp,
		CreatedInSeq:    seqID,
		Lifecycle:       lifecycle,
		Confidence:      confidence,
		ObservedCount:   1,
		LastSeenOrder:   g.nextOrder(),
		OwnerIdentity:   o.OwnerIdentity,
		Version:         o.Version,
		Attributes:      o.Attributes,
	}
	g.instances[key] = inst
	g.byType[id.ResourceType] = append(g.byType[id.ResourceType], key)
	return inst
}

// maxTenantWalkDepth bounds resolveTenantKey's upward walk so any future
// accidental parent-link cycle can't hang the caller.
const maxTenantWalkDepth = 8

// resolveTenantKey walks inst's ParentKey chain up to its root ancestor (the
// instance with no further ParentKey of its own) and sets inst.TenantKey to
// that root's graph key. A no-op if inst has no ParentKey yet. Called by
// recordResourceGraphStep (sequence.go) every time a parent link is confirmed
// for inst, so TenantKey stays current as deeper ancestry is discovered.
func (g *ResourceGraph) resolveTenantKey(inst *ResourceInstance) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if inst.ParentKey == "" {
		return
	}
	rootKey := inst.ParentKey
	for i := 0; i < maxTenantWalkDepth; i++ {
		parent, ok := g.instances[rootKey]
		if !ok || parent.ParentKey == "" {
			break
		}
		rootKey = parent.ParentKey
	}
	inst.TenantKey = rootKey
}

// evictIfOverCap drops the oldest (lowest LastSeenOrder), then lowest-confidence,
// instance of resourceType when the per-type cap would otherwise be exceeded by
// the insert about to happen. Called with mu already held.
func (g *ResourceGraph) evictIfOverCap(resourceType string) {
	keys := g.byType[resourceType]
	if len(keys) < g.limits.MaxInstancesPerType {
		return
	}
	worstIdx := -1
	for i, k := range keys {
		inst := g.instances[k]
		if inst == nil {
			worstIdx = i
			break
		}
		if worstIdx == -1 {
			worstIdx = i
			continue
		}
		w := g.instances[keys[worstIdx]]
		if inst.LastSeenOrder < w.LastSeenOrder || (inst.LastSeenOrder == w.LastSeenOrder && inst.Confidence < w.Confidence) {
			worstIdx = i
		}
	}
	if worstIdx == -1 {
		return
	}
	delete(g.instances, keys[worstIdx])
	g.byType[resourceType] = append(keys[:worstIdx:worstIdx], keys[worstIdx+1:]...)
}

// recordAlias attaches an additional identity to an already-known instance
// (found by any of its existing identities), bounded at MaxAliasesPerInstance.
// A no-op if primary isn't already a known instance -- callers should
// recordInstance(primary, ...) first.
func (g *ResourceGraph) recordAlias(primary, alias ResourceIdentity) {
	g.mu.Lock()
	defer g.mu.Unlock()
	inst, ok := g.instances[primary.graphKey()]
	if !ok {
		return
	}
	for _, a := range inst.Aliases {
		if a.graphKey() == alias.graphKey() {
			return
		}
	}
	if len(inst.Aliases) >= g.limits.MaxAliasesPerInstance {
		return
	}
	inst.Aliases = append(inst.Aliases, alias)
}

// recordTransition appends a lifecycle transition (ring-bounded) and reports
// whether its (from,to,consumerOp) signature has never been seen before this
// call -- the "novel transition" scheduling signal.
func (g *ResourceGraph) recordTransition(t ResourceTransition) (novel bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t.Order = g.nextOrder()
	sig := t.signature()
	if _, seen := g.seenTransition[sig]; !seen {
		g.seenTransition[sig] = struct{}{}
		novel = true
	}
	g.transitions = append(g.transitions, t)
	if len(g.transitions) > g.limits.MaxTransitions {
		g.transitions = g.transitions[len(g.transitions)-g.limits.MaxTransitions:]
	}
	return novel
}

// findCompatibleResources returns instances of resourceType currently in one of
// the given lifecycle states (or any state if states is empty), most-recently-
// seen first. Used both to select a resource for a "valid" next step (e.g. an
// existing Readable/Created instance) and to deliberately select one for an
// "explore an invalid transition" step (e.g. a Deleted instance to GET again).
func (g *ResourceGraph) findCompatibleResources(resourceType string, states ...LifecycleState) []*ResourceInstance {
	g.mu.Lock()
	defer g.mu.Unlock()
	var allowed map[LifecycleState]struct{}
	if len(states) > 0 {
		allowed = make(map[LifecycleState]struct{}, len(states))
		for _, s := range states {
			allowed[s] = struct{}{}
		}
	}
	keys := g.byType[resourceType]
	out := make([]*ResourceInstance, 0, len(keys))
	for _, k := range keys {
		inst := g.instances[k]
		if inst == nil {
			continue
		}
		if allowed != nil {
			if _, ok := allowed[inst.Lifecycle]; !ok {
				continue
			}
		}
		out = append(out, inst)
	}
	// Most-recently-seen first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// findCompatibleResourcesInTenant is findCompatibleResources narrowed to one
// tenant scope: an instance is kept only if its own TenantKey equals
// tenantKey, or its own graph key IS tenantKey (the tenant root resource
// itself, e.g. the organization, whose TenantKey field is empty since it has
// no parent of its own). An empty tenantKey applies no restriction at all --
// the exact prior, unrestricted behavior -- which is deliberate: a sequence
// that hasn't yet touched a nested (child) resource has no established tenant
// scope to enforce (SequenceState.TenantKey stays "" for flat/non-nested
// APIs), and this must not regress substitution for those targets.
func (g *ResourceGraph) findCompatibleResourcesInTenant(resourceType, tenantKey string, states ...LifecycleState) []*ResourceInstance {
	all := g.findCompatibleResources(resourceType, states...)
	if tenantKey == "" {
		return all
	}
	out := make([]*ResourceInstance, 0, len(all))
	for _, inst := range all {
		if inst.TenantKey == tenantKey || inst.Canonical.graphKey() == tenantKey {
			out = append(out, inst)
		}
	}
	return out
}

// getInstance looks up a single instance by identity, or nil if unknown.
func (g *ResourceGraph) getInstance(id ResourceIdentity) *ResourceInstance {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.instances[id.graphKey()]
}

// markConsumerReached and markConsumerResult feed the coverage-directed
// scheduler's "never reached" and "repeated failure" signals (scoreConsumer,
// sequence.go).
func (g *ResourceGraph) markConsumerReached(templateID int) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reachedConsumer[templateID]++
	return g.reachedConsumer[templateID]
}

func (g *ResourceGraph) consumerReachedCount(templateID int) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reachedConsumer[templateID]
}

func (g *ResourceGraph) markConsumerResult(templateID int, failed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if failed {
		g.failedConsumer[templateID]++
	} else if g.failedConsumer[templateID] > 0 {
		g.failedConsumer[templateID]--
	}
}

func (g *ResourceGraph) consumerFailureCount(templateID int) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failedConsumer[templateID]
}

// snapshotForSequence returns the instances and transitions relevant to seqID,
// for inclusion in a persisted workflow (persistWorkflow, sequence.go). Bounded
// by construction -- it only ever returns what's already in the bounded graph.
func (g *ResourceGraph) snapshotForSequence(seqID string) ([]*ResourceInstance, []ResourceTransition) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var instances []*ResourceInstance
	for _, inst := range g.instances {
		if inst.CreatedInSeq == seqID {
			instances = append(instances, inst)
		}
	}
	var transitions []ResourceTransition
	for _, t := range g.transitions {
		if t.SequenceID == seqID {
			transitions = append(transitions, t)
		}
	}
	return instances, transitions
}

// instanceCount reports the total number of tracked instances, for diagnostics
// and tests asserting graph bounds are actually enforced.
func (g *ResourceGraph) instanceCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.instances)
}

// exportAll returns every currently-tracked instance and transition, for
// checkpoint.go's periodic save -- unlike snapshotForSequence, not filtered
// to one sequence. Returned instances are the graph's own live pointers (not
// deep-copied): checkpoint.go only ever reads them immediately before
// JSON-encoding, on the same single main-loop goroutine that owns the graph
// (see this file's top-level ownership comment), so no copy is needed.
func (g *ResourceGraph) exportAll() ([]*ResourceInstance, []ResourceTransition) {
	g.mu.Lock()
	defer g.mu.Unlock()
	instances := make([]*ResourceInstance, 0, len(g.instances))
	for _, inst := range g.instances {
		instances = append(instances, inst)
	}
	transitions := make([]ResourceTransition, len(g.transitions))
	copy(transitions, g.transitions)
	return instances, transitions
}

// importAll rebuilds the graph's instance/transition indices from a
// checkpoint (checkpoint.go's LoadCheckpoint), called once at startup before
// any concurrent access begins -- so, unlike every other exported method
// here, this does NOT need to preserve anything already in g (there is
// nothing yet). Instances are re-keyed by their own Canonical identity
// (recomputing graphKey() rather than trusting any stored key), and
// transitions repopulate seenTransition so novelty detection resumes exactly
// where the checkpointed run left off, not from a blank slate.
func (g *ResourceGraph) importAll(instances []*ResourceInstance, transitions []ResourceTransition) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var maxOrder uint64
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		key := inst.Canonical.graphKey()
		g.instances[key] = inst
		g.byType[inst.ResourceType] = append(g.byType[inst.ResourceType], key)
		if inst.LastSeenOrder > maxOrder {
			maxOrder = inst.LastSeenOrder
		}
	}
	g.transitions = append(g.transitions, transitions...)
	for _, t := range transitions {
		g.seenTransition[t.signature()] = struct{}{}
		if t.Order > maxOrder {
			maxOrder = t.Order
		}
	}
	if maxOrder > g.order {
		g.order = maxOrder
	}
}
