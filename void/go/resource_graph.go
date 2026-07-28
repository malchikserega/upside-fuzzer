package main

import (
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
// f.persistedWorkflowSigs, which are plain unsynchronized maps for the identical
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
	Lifecycle       LifecycleState     `json:"lifecycle"`
	Confidence      float64            `json:"confidence"`
	ObservedCount   int                `json:"observed_count"`
	LastSeenOrder   uint64             `json:"last_seen_order"`
}

// ResourceTransition records one lifecycle transition observed for one or more
// identities during a sequence step.
type ResourceTransition struct {
	From          LifecycleState     `json:"from"`
	To            LifecycleState     `json:"to"`
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
// concrete identity, so it doesn't grow per-resource-instance).
func (t ResourceTransition) signature() string {
	return fmt.Sprintf("%s->%s|%s", t.From, t.To, t.ConsumerOp)
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

// recordInstance upserts a resource instance by its canonical identity, bumping
// ObservedCount/LastSeenOrder and merging in a new lifecycle state (via
// transitionLifecycle's own from/to bookkeeping -- callers pass the *new* state
// here and record a transition separately via recordTransition). Enforces
// limits.MaxInstancesPerType by evicting the least-recently-seen, lowest-
// confidence instance of that type when over the cap.
func (g *ResourceGraph) recordInstance(id ResourceIdentity, sourceOp, seqID string, lifecycle LifecycleState, confidence float64) *ResourceInstance {
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
	}
	g.instances[key] = inst
	g.byType[id.ResourceType] = append(g.byType[id.ResourceType], key)
	return inst
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
