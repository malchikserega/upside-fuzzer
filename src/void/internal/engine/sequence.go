package engine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sequence.go — Stateful sequences: producer→consumer chain discovery,
// runtime value extraction from requests/responses, followup prioritization.

// stateNoveltyBonus is the Energy award for a sequence step reaching a
// never-seen workflow-state signature (Top-20 #12). Chosen to be comparable to
// a solid multi-edge CoverageDelta hit (edgeShare of a few units per request in
// practice), so state novelty competes with, rather than being drowned out by,
// ordinary coverage-driven energy.
const stateNoveltyBonus = 5.0

// transitionNoveltyBonus is the Energy award for recording a never-seen
// (from-lifecycle, to-lifecycle, consumer-op) resource transition --
// composite-reward term "state_transition_novelty"
// (docs/ARCHITECTURE_STATEFUL.md §2.6). Distinct from novelTransition's
// existing fanout+1 search-budget bonus (which widens exploration *breadth*
// for this step only): this instead raises the *seed's* long-term retention
// priority (worker.go sorts/prunes corpus entries by Energy), so a chain that
// reached a genuinely new transition is more likely to be kept and mutated
// further in later epochs, not just explored one branch deeper right now.
const transitionNoveltyBonus = 4.0

// maxChainDepthBonus is the Energy award for a sequence step reaching a chain
// depth this run has never reached before -- composite-reward term
// "valid_chain_depth" (docs/ARCHITECTURE_STATEFUL.md §2.6). A "personal best"
// pattern (mirrors stateNoveltyBonus/transitionNoveltyBonus): only the FIRST
// step to reach a new maximum depth earns it, not every step at every depth,
// so this doesn't just linearly favor long chains regardless of whether
// they're discovering anything new.
const maxChainDepthBonus = 6.0

// nextChainDepthAndEnergy computes a branching follow-up's Depth and Energy,
// applying maxChainDepthBonus exactly once per run the first time a new
// maximum chain depth is reached (f.maxChainDepthSeen) -- the "personal best"
// pattern mirroring newState/novelTransition's own bonuses above. Extracted
// as its own small, directly-testable method (mirrors patchTraceStatus,
// identity.go) since driving enqueueSequenceFollowups' full branching loop
// end to end requires real template-rendering machinery this test suite
// doesn't otherwise build.
func (f *Fuzzer) nextChainDepthAndEnergy(state *SequenceState) (depth int, energy float64) {
	depth = state.Depth + 1
	energy = state.Energy
	if depth > f.maxChainDepthSeen {
		f.maxChainDepthSeen = depth
		energy += maxChainDepthBonus
	}
	return depth, energy
}

// ProducerConsumerBinding is an explicit, typed record of one "this follow-up
// request's field was bound to this exact value, extracted from this exact
// prior response field" event. Previously this fact only existed implicitly,
// scattered across SequenceState.Values/Provenance (a flat field-name ->
// producer-op map with no record of *which* response field specifically, nor
// of which concrete consumer request the binding fed) -- nothing in the
// engine could answer "did this ID genuinely come from a producer response,
// and if so, from where" as a single, direct, queryable fact. Bounded
// (maxProducerConsumerBindings) and consulted by report/SARIF chain-trace
// output (Phase 5) and the E2E fixture matrix's producer-binding assertions.
type ProducerConsumerBinding struct {
	ProducerOp    string `json:"producer_op"`              // "METHOD /norm/path" that produced the value
	ProducerField string `json:"producer_field,omitempty"` // JSON path / header name / link relation the value came from
	ConsumerOp    string `json:"consumer_op"`              // "METHOD /norm/path" of the request the value was substituted into
	ConsumerField string `json:"consumer_field"`           // "path" | "body:<key>" | "query:<key>"
	ResourceType  string `json:"resource_type"`
	Value         string `json:"value"`
	SequenceID    string `json:"sequence_id"`
	Order         uint64 `json:"order"`
}

// maxProducerConsumerBindings bounds f.producerConsumerBindings' growth the
// same way ResourceGraph bounds its own transition log -- a debugging/
// reporting record, not something meant to grow unbounded over a long run.
const maxProducerConsumerBindings = 2000

// recordProducerConsumerBinding appends one binding event, ring-bounded.
// Same single-main-loop-goroutine ownership as f.resourceGraph -- see
// fuzzer.go's field comment.
func (f *Fuzzer) recordProducerConsumerBinding(b ProducerConsumerBinding) {
	f.bindingOrder++
	b.Order = f.bindingOrder
	f.producerConsumerBindings = append(f.producerConsumerBindings, b)
	if len(f.producerConsumerBindings) > maxProducerConsumerBindings {
		f.producerConsumerBindings = f.producerConsumerBindings[len(f.producerConsumerBindings)-maxProducerConsumerBindings:]
	}
}

// bindingsForSequence returns a defensive copy of every recorded
// ProducerConsumerBinding for the given sequence ID, in recording order --
// used by crash.go to attach a crash's own producer-binding provenance to its
// CrashFinding (Phase 5 #127/#128), closing the gap this file's own doc
// comment above already claimed was closed. nil for "" (a non-sequence
// crash) or a sequence with no recorded bindings, matching cloneChainTrace's
// (identity.go) same nil-for-absent convention.
func (f *Fuzzer) bindingsForSequence(seqID string) []ProducerConsumerBinding {
	if seqID == "" {
		return nil
	}
	var out []ProducerConsumerBinding
	for _, b := range f.producerConsumerBindings {
		if b.SequenceID == seqID {
			out = append(out, b)
		}
	}
	return out
}

// pickFollowupPathValue chooses the concrete value to substitute into a
// follow-up template's remaining path placeholder(s) (item #2, docs/
// resource-state-graph-report.md). It prefers a resource-graph-tracked,
// still-alive instance of the consumer's expected resource type over
// entityIDs[0] (the old id-name-centric extraction's first hit) -- previously
// this substitution ALWAYS used entityIDs[0] regardless of what the richer
// resource-graph pipeline had extracted for this exact step, so the graph
// only ever influenced *which* consumer template got scheduled
// (rankConsumersCoverageDirected), never *which concrete value* was plugged
// into it. tenantKey, when non-empty (SequenceState.TenantKey -- set once
// this chain has gone deep enough to establish a tenant scope), restricts the
// graph pick to instances belonging to that same tenant, so a "valid"
// workflow chain never substitutes in a same-typed resource that happens to
// belong to a DIFFERENT tenant/organization -- that substitution is exactly
// what the adversarial branch planner should do deliberately, not something
// the valid-chain builder should ever do by accident. Returns ok=false if
// neither source has anything to offer. inst is the ResourceInstance the
// value came from when fromGraph is true (nil otherwise) -- the caller uses
// it to record a ProducerConsumerBinding without re-querying the graph.
func (f *Fuzzer) pickFollowupPathValue(tid int, entityIDs []string, tenantKey string) (value string, fromGraph bool, ok bool, inst *ResourceInstance) {
	if f.cfg.ResourceGraphEnabled {
		if rt := resourceTypeFromEndpointPath(f.meta[tid].Norm); rt != "" {
			if compat := f.resourceGraph.findCompatibleResourcesInTenant(rt, tenantKey, LifecycleCreated, LifecycleReadable, LifecycleModified); len(compat) > 0 {
				return compat[0].Canonical.RawValue, true, true, compat[0]
			}
		}
	}
	if len(entityIDs) > 0 {
		return entityIDs[0], false, true, nil
	}
	return "", false, false, nil
}

func (f *Fuzzer) enqueueSequenceFollowups(res SendResult) int {
	source := res.Item
	if f.cfg.ResourceGraphEnabled {
		// Track this consumer's own result *before* any early return below, so
		// the "repeated failure" scheduling penalty (scoreConsumer) sees every
		// attempt, not just ones that went on to branch further.
		f.resourceGraph.markConsumerResult(source.TemplateID, res.Status >= 400)
	}
	if source.SeqDepth >= maxInt(1, f.cfg.SequenceMaxDepth) {
		f.seqStopMaxDepth++
		f.maybePersistSequence(res)
		return 0
	}

	state := source.SeqState
	if state == nil {
		// Start a new sequence state
		state = &SequenceState{
			ID:         fmt.Sprintf("seq-%d", rand.Int63()),
			Depth:      0,
			Values:     make(map[string]string),
			Provenance: make(map[string]string),
			History:    []SequenceStep{},
		}
	}

	// Record this step in the history
	// Clone headers to prevent mutation
	clonedHeaders := make(map[string]string)
	for k, v := range source.Headers {
		clonedHeaders[k] = v
	}

	step := SequenceStep{
		TemplateID:    source.TemplateID,
		Method:        source.Method,
		Path:          source.Path,
		Headers:       clonedHeaders,
		Body:          source.Body,
		Status:        res.Status,
		CoverageDelta: res.CoverageDelta,
		MutationLabel: source.MutationLabel,
	}
	state.History = append(state.History, step)

	if res.CoverageDelta > 0 {
		state.Energy += float64(res.CoverageDelta)
	}

	// Top-20 #12 -- state-reward sequence search: reward reaching a workflow
	// SHAPE (ordered method+normpath+status-class triples) never seen before in
	// this run, not just a new edge. This is deliberately coarse (no resource
	// lifecycle/typed state graph -- see docs/ARCHITECTURE_REVIEW.md §5) but it is
	// enough to make the sequence engine's own search prioritize genuinely novel
	// multi-step workflows over re-treading ones it has already explored, which
	// plain edge-coverage reward can't distinguish (a 3rd identical GET after a
	// POST looks the same to the coverage bitmap as the 1st).
	sig := sequenceStateSignature(state)
	newState := false
	if _, seen := f.seenStateSigs[sig]; !seen {
		f.seenStateSigs[sig] = struct{}{}
		newState = true
		state.Energy += stateNoveltyBonus
		f.newStatesFound++
		if f.newStatesFound <= 5 || f.newStatesFound%25 == 0 {
			f.addEvent(fmt.Sprintf("NEW STATE  seq(d%d) %s  (%d total)", state.Depth+1, truncate(sig, 80), f.newStatesFound))
		}
	}

	// Extract values and bind to this sequence context
	info := f.depIndex[source.TemplateID]
	producedDeps := mapKeys(info.Writes)
	producedIDKeys := mapKeys(info.IDWrites)
	entityIDs := extractEntityIDs(res.Body, res.Headers)

	provKey := fmt.Sprintf("%s %s", source.Method, source.Path)

	// Resource state graph (docs/resource-state-graph-plan.md): generalized
	// extraction (HAL/JSON:API/header/shape, not just id/Id/data[].id) +
	// typed lifecycle tracking, additive on top of the entityIDs extraction
	// above (which state.Values substitution below still uses unchanged).
	novelTransition := false
	if f.cfg.ResourceGraphEnabled {
		var touched []*ResourceInstance
		novelTransition, touched = f.recordResourceGraphStep(source, res, state.ID, provKey)
		// Adopt this chain's tenant scope the first time a touched resource has
		// one resolved -- i.e. once the chain has gone at least two levels deep
		// into a nested resource (e.g. org -> project). Sticky for the rest of
		// the chain (never overwritten once set): a later step touching an
		// unrelated/shallower resource must not silently widen or change an
		// already-established tenant scope.
		if state.TenantKey == "" {
			for _, inst := range touched {
				if inst.TenantKey != "" {
					state.TenantKey = inst.TenantKey
					break
				}
			}
		}
		if novelTransition {
			state.Energy += transitionNoveltyBonus
		}
	}

	if rid := inferResourceIDKeyFromPath(source.Path); rid != "" {
		for _, eid := range entityIDs {
			state.Values[rid] = eid
			state.Values["id"] = eid
			state.Provenance[rid] = provKey
			state.Provenance["id"] = provKey

			// Also add to global runtime store for baseline epoch (fallback)
			_ = f.runtime.addValue(rid, eid)
			_ = f.runtime.addValue("id", eid)
		}
	}

	if len(entityIDs) > 0 {
		for _, dep := range producedDeps {
			state.Values[dep] = entityIDs[0]
			state.Provenance[dep] = provKey
			f.runtime.addDepValue(dep, entityIDs[0])
		}
	}

	// If the step failed (4xx/5xx), we might still persist if we reached depth, but we don't branch further
	if res.Status >= 400 {
		f.seqStopFailedStep++
		f.maybePersistSequence(res)
		return 0
	}

	// Pagination/cursor-aware chaining (pagination.go, Phase 4 #121): a list
	// endpoint following up on ITSELF with an updated cursor is a shape
	// findFollowups structurally can't produce (its same-family fallback
	// explicitly excludes a template from following up on its own exact
	// method+path) -- handled here as its own direct mechanism instead.
	// Checked (and, on the early-return paths below, accounted for) BEFORE
	// the producedDeps/entityIDs gate, since a list response commonly has
	// neither -- a plain {"items":[...],"nextCursor":"..."} would otherwise
	// hit seqStopNoProducedValue before ever reaching this.
	paginationEnqueued := false
	if f.cfg.PaginationChaining {
		nextDepth, nextEnergy := f.nextChainDepthAndEnergy(state)
		paginationState := &SequenceState{
			ID: state.ID, Depth: nextDepth, Energy: nextEnergy, TenantKey: state.TenantKey,
			Values: cloneStringMap(state.Values), Provenance: cloneStringMap(state.Provenance),
			History: append([]SequenceStep{}, state.History...),
		}
		paginationEnqueued = f.maybeEnqueuePaginationFollowup(source, res, paginationState)
	}

	if len(producedDeps) == 0 && len(entityIDs) == 0 {
		meta := f.meta[source.TemplateID]
		if meta.Method != "POST" && meta.Method != "PUT" && meta.Method != "PATCH" {
			if !paginationEnqueued {
				f.seqStopNoProducedValue++
			}
			return boolToInt(paginationEnqueued)
		}
	}

	followups := f.findFollowups(source.TemplateID, source.Method, normalizePath(source.Path), producedDeps, producedIDKeys, state.TenantKey)
	if len(followups) == 0 {
		if !paginationEnqueued {
			f.seqStopNoFollowupCandidate++
		}
		f.maybePersistSequence(res)
		return boolToInt(paginationEnqueued)
	}

	fanout := minInt(maxInt(1, f.cfg.SequenceFanout), len(followups))
	if newState {
		// A sequence that just reached a never-seen workflow shape gets one extra
		// branch of search budget -- it's exactly the kind of exploration DeepREST/
		// EvoMaster's state-based search prioritizes over re-treading known states.
		fanout = minInt(fanout+1, len(followups))
	}
	if novelTransition {
		// A finer-grained signal than newState above: reaching a never-seen
		// (from-lifecycle, to-lifecycle, consumer-op) transition -- e.g. the
		// first time this run a DELETE-then-GET pattern was observed for ANY
		// resource of this type, not just this exact chain's shape -- also
		// earns one extra branch of search budget.
		fanout = minInt(fanout+1, len(followups))
	}
	enqueued := 0
	for _, tid := range followups[:fanout] {
		// Clone state for branching
		nextDepth, nextEnergy := f.nextChainDepthAndEnergy(state)
		nextState := &SequenceState{
			ID:         state.ID,
			Depth:      nextDepth,
			Values:     make(map[string]string, len(state.Values)),
			Provenance: make(map[string]string, len(state.Provenance)),
			History:    make([]SequenceStep, len(state.History)),
			Energy:     nextEnergy,
			TenantKey:  state.TenantKey,
		}
		for k, v := range state.Values {
			nextState.Values[k] = v
		}
		for k, v := range state.Provenance {
			nextState.Provenance[k] = v
		}
		copy(nextState.History, state.History)

		// We need a dummy item to pass the SeqState to renderTemplate so it prioritizes it
		dummy := &WorkItem{SeqState: nextState}
		mode := "none"
		if rand.Float64() >= 0.75 {
			mode = "mutate"
		}

		item, err := f.renderTemplateContext(tid, mode, 1, -1, dummy)
		if err != nil {
			continue
		}

		usedStaleExploration := false
		if f.cfg.ResourceGraphEnabled && strings.Contains(item.Path, "{") && rand.Float64() < f.cfg.ResourceGraphStaleExploreProb {
			// Phase 7 of docs/resource-state-graph-plan.md: deliberately bind this
			// follow-up to a resource already known to be DELETED/INVALIDATED,
			// instead of the freshly-produced entityIDs[0] below -- this is the
			// concrete mechanism that produces "create -> delete -> read",
			// "update after delete" and similar deliberately-invalid-transition
			// workflows, rather than only ever continuing a valid one.
			if rt := resourceTypeFromEndpointPath(f.meta[tid].Norm); rt != "" {
				stale := f.resourceGraph.findCompatibleResources(rt, LifecycleDeleted, LifecycleInvalidated)
				if len(stale) > 0 {
					item.Path = rePathParam.ReplaceAllString(item.Path, stale[0].Canonical.RawValue)
					usedStaleExploration = true
				}
			}
		}
		// Item #2 (docs/resource-state-graph-report.md): prefer a resource-graph-
		// tracked, still-alive instance of the consumer's expected resource type
		// over entityIDs[0] (the old id-name-centric extraction's first hit).
		// Previously this substitution ALWAYS used entityIDs[0] regardless of
		// what the richer resource-graph pipeline had extracted for this exact
		// step -- the graph only ever influenced *which* consumer template got
		// scheduled (rankConsumersCoverageDirected), never *which concrete value*
		// was plugged into it. That gap is why real-ID chains were rare even
		// when the graph had a perfectly good GUID on hand: the substitution
		// simply never looked at it.
		usedGraphValue := false
		if !usedStaleExploration && strings.Contains(item.Path, "{") {
			if value, fromGraph, ok, pickedInst := f.pickFollowupPathValue(tid, entityIDs, state.TenantKey); ok {
				item.Path = rePathParam.ReplaceAllString(item.Path, value)
				usedGraphValue = fromGraph
				if fromGraph && pickedInst != nil {
					f.recordProducerConsumerBinding(ProducerConsumerBinding{
						ProducerOp:    pickedInst.SourceOperation,
						ProducerField: pickedInst.Canonical.SourcePath,
						ConsumerOp:    fmt.Sprintf("%s %s", item.Method, normalizePath(item.Path)),
						ConsumerField: "path",
						ResourceType:  pickedInst.ResourceType,
						Value:         value,
						SequenceID:    nextState.ID,
					})
				}
			}
		}

		item.SeqDepth = nextState.Depth
		item.SeqState = nextState
		item.EpochName = "Sequence"
		item.EpochIdx = source.EpochIdx
		item.Identity = source.Identity
		seqLabel := fmt.Sprintf("seq(d%d:%s %s->%s)", item.SeqDepth, source.Method, normalizePath(source.Path), item.Method)
		if item.MutationLabel != "seed" {
			seqLabel += "+" + item.MutationLabel
		}
		if usedStaleExploration {
			seqLabel += "+explore_stale"
		}
		if usedGraphValue {
			seqLabel += "+graph_id"
		}
		item.MutationLabel = seqLabel
		item.MutationName = "sequence"
		item.Trace = f.extendTrace(source.Trace, item)

		if len(f.sequenceQueue) >= sequenceQueueMax {
			f.sequenceQueue = f.sequenceQueue[1:]
		}
		f.sequenceQueue = append(f.sequenceQueue, item)
		enqueued++
		if f.cfg.ResourceGraphEnabled {
			f.resourceGraph.markConsumerReached(tid)
		}
	}

	if enqueued == 0 && !paginationEnqueued {
		f.seqStopRenderFailed++
		f.maybePersistSequence(res)
	}

	return enqueued + boolToInt(paginationEnqueued)
}

// recordResourceGraphStep runs the generalized extraction pipeline
// (resource_extraction.go) over this step's response, records each candidate
// above f.cfg.ResourceGraphMinConfidence as a resource instance (or alias of an
// already-known one) in f.resourceGraph, derives and records a lifecycle
// transition per instance (deriveLifecycleTransition, resource_scheduling.go),
// and links multi-segment route-template matches (e.g.
// /organizations/{orgId}/projects/{projectSlug}) as parent->child. Returns
// whether any recorded transition's signature was never seen before this call
// (the fanout-widening signal in enqueueSequenceFollowups), plus every
// ResourceInstance touched this step (used to seed SequenceState.TenantKey
// once the chain reaches a resource with a resolved tenant scope).
func (f *Fuzzer) recordResourceGraphStep(source WorkItem, res SendResult, seqID, provKey string) (bool, []*ResourceInstance) {
	candidates := f.extractResourceCandidates(res.Body, res.Headers, provKey)
	// The request's OWN path is a candidate source too, not just the response:
	// a DELETE returning 204 (no body at all) or a GET/PUT whose response
	// doesn't echo the resource's own id back carry their target resource's
	// identity only in the request path itself. Without this, a real
	// create->delete->read-again chain against a fixture that returns an empty
	// body on DELETE would never record the DELETED transition at all -- the
	// resource simply wouldn't exist in the graph despite a real state change
	// having happened.
	candidates = append(candidates, f.matchRouteTemplateCandidates(source.Path, provKey, "request_path", confRouteTemplateOnly)...)
	// The request's own query string too -- an async operation poll request
	// (e.g. "GET /operations/status?jobId=abc-123") carries its operation id
	// as a query param, not a path segment.
	candidates = append(candidates, extractQueryParamCandidates(source.Path, provKey)...)
	if len(candidates) == 0 {
		return false, nil
	}

	// Computed once per step, not per candidate -- every instance recorded
	// from this response shares the same owner identity, version header, and
	// attribute snapshot.
	attrs := extractTopLevelAttributes(res.Body)
	if isAsyncSubmission(res.Status, res.Headers) {
		// Async-operation model (async.go, Phase 4 #120): tag this step's
		// resource as an in-flight async submission so scoreConsumer
		// (resource_scheduling.go) keeps preferring to re-poll it through to
		// a terminal state, rather than treating it like an ordinary
		// synchronously-completed resource.
		if attrs == nil {
			attrs = make(map[string]any, 1)
		}
		attrs["async_submitted"] = true
	}
	if isMultipartUpload(f.meta[source.TemplateID].ContentType) {
		// Multipart chain modeling (multipart_chain.go, Phase 4 #122): tag
		// this step's resource as having come from a file upload, so
		// scoreConsumer biases a later download/export-shaped candidate
		// toward actually completing the upload->[process]->download chain.
		if attrs == nil {
			attrs = make(map[string]any, 1)
		}
		attrs["source_multipart"] = true
	}
	instOpts := RecordInstanceOpts{
		OwnerIdentity: source.Identity,
		Version:       extractVersionHeader(res.Headers),
		Attributes:    attrs,
	}

	novelAny := false
	var touched []*ResourceInstance
	// Candidates sharing the same Strategy+JSONPath/HeaderName came from one
	// matchRouteTemplateCandidates call and are already in path-segment order
	// (see resource_extraction.go) -- consecutive ones from that same call are
	// linked parent->child below.
	var lastRouteGroupKey string
	var lastInstance *ResourceInstance
	// firstIdentityForValue tracks, within this single step, the first identity
	// seen for a given (resourceType, rawValue) pair -- when a *different*
	// extraction strategy later reports the same underlying value under a
	// different representation (e.g. a HAL self-link's last path segment and a
	// JSON:API "data.id" happen to be the same order id from the same
	// response), the later one is recorded as an alias of the first rather than
	// a second independent instance.
	firstIdentityForValue := map[string]ResourceIdentity{}

	for _, c := range candidates {
		if c.Confidence < f.cfg.ResourceGraphMinConfidence {
			continue
		}
		id := c.toIdentity()
		// Multiple candidates within this SAME step commonly resolve to the
		// same underlying (resourceType, rawValue) -- e.g. a structural "id"
		// field and a request-path route-template match both naming the same
		// resource. Only the FIRST such candidate should drive the
		// finding-emitting checks below: recordInstance mutates the shared
		// ResourceInstance's Attributes in place, so a second candidate's own
		// "prior" read would otherwise silently observe THIS step's own
		// already-applied update instead of the true prior state, both
		// misreporting the violation and double-firing it.
		valueKey := id.ResourceType + "|" + c.RawValue
		_, alreadyProcessedThisStep := firstIdentityForValue[valueKey]

		prior := LifecycleUnknown
		var priorStatus string
		var priorDisabled bool
		if existing := f.resourceGraph.getInstance(id); existing != nil {
			prior = existing.Lifecycle
			if existing.Attributes != nil {
				priorStatus, _ = existing.Attributes["status"].(string)
				priorDisabled = isSoftDisabledAttributes(existing.Attributes)
			}
		}
		to, result := deriveLifecycleTransition(source.Method, res.Status, prior)
		if !alreadyProcessedThisStep {
			// Adversarial branch planner, stale-object family (adversarial.go):
			// the lifecycle classification above has ALREADY determined this
			// exact request succeeded against a resource known to be deleted --
			// no separate probe/replay needed, this IS the finding.
			switch to {
			case LifecycleStale:
				f.recordStaleObjectFinding(source, res, id.ResourceType, "stale_read")
			case LifecycleInvalidated:
				f.recordStaleObjectFinding(source, res, id.ResourceType, "update_after_delete")
			default:
				if to == LifecycleDeleted && prior == LifecycleDeleted && result == "invalid" {
					f.recordStaleObjectFinding(source, res, id.ResourceType, "repeated_deletion")
				}
			}
			// Adversarial branch planner, workflow-bypass family (adversarial.go):
			// this step's own template declared an explicit x-state-transition
			// predecessor (Tier 1 of the transition-source priority chain) -- if
			// the resource's own last-known status disagrees with that declared
			// predecessor and the call still succeeded, the required predecessor
			// state was skipped.
			if xt := f.meta[source.TemplateID].XStateTransition; xt != nil && xt.From != "" &&
				res.Status >= 200 && res.Status < 300 && priorStatus != "" && priorStatus != xt.From {
				f.recordWorkflowBypassFinding(source, res, xt.From, priorStatus)
			}
			// Webhook/event callback lifecycle (webhook.go, Phase 4 #123): a
			// trigger-shaped action succeeding against a resource explicitly
			// marked disabled (active:false/enabled:false), without ever
			// having gone through DELETE -- a soft-disabled-but-still-active
			// violation the DELETE-only stale-object oracle can't see.
			if priorDisabled && res.Status >= 200 && res.Status < 300 {
				action := deriveTransitionActionForTemplate(f.meta[source.TemplateID], source.Method, source.Path)
				if _, isTrigger := webhookTriggerActionVerbs[action]; isTrigger {
					f.recordDisabledResourceStillActiveFinding(source, res, id.ResourceType)
				}
			}
		}
		inst := f.resourceGraph.recordInstance(id, provKey, seqID, to, c.Confidence, instOpts)
		touched = append(touched, inst)

		if primary, seen := firstIdentityForValue[valueKey]; seen {
			if primary.IdentityKind != id.IdentityKind {
				f.resourceGraph.recordAlias(primary, id)
			}
		} else {
			firstIdentityForValue[valueKey] = inst.Canonical
		}

		if c.Strategy == "route_template" {
			groupKey := c.Strategy + "|" + c.JSONPath
			if groupKey == lastRouteGroupKey && lastInstance != nil && lastInstance.Canonical.ResourceType != inst.ResourceType {
				if inst.ParentKey == "" {
					inst.ParentKey = lastInstance.Canonical.graphKey()
				}
				f.resourceGraph.resolveTenantKey(inst)
				hasChild := false
				for _, ck := range lastInstance.ChildKeys {
					if ck == inst.Canonical.graphKey() {
						hasChild = true
						break
					}
				}
				if !hasChild {
					lastInstance.ChildKeys = append(lastInstance.ChildKeys, inst.Canonical.graphKey())
				}
			}
			lastRouteGroupKey = groupKey
			lastInstance = inst
		} else {
			lastRouteGroupKey = ""
			lastInstance = nil
		}

		novel := f.resourceGraph.recordTransition(ResourceTransition{
			From: prior, To: to, Action: deriveTransitionActionForTemplate(f.meta[source.TemplateID], source.Method, source.Path),
			ConsumerOp: provKey, SequenceID: seqID,
			StatusCode: res.Status, CoverageDelta: res.CoverageDelta, Result: result,
			Identities: []ResourceIdentity{id}, Confidence: c.Confidence,
		})
		if novel {
			novelAny = true
		}
	}
	return novelAny, touched
}

func (f *Fuzzer) maybePersistSequence(res SendResult) {
	state := res.Item.SeqState
	if state == nil {
		return
	}

	// Item #3 (docs/resource-state-graph-report.md): a sequence that hasn't
	// reached the full configured depth is normally invisible to persistence
	// entirely -- the depth<2 gate below -- even when its own resource graph
	// shows a genuine real-ID producer->consumer chain, the single most
	// useful signal this feature can produce. Bypass the depth gate
	// specifically for that case (state.Depth>=1 means at least 2 steps,
	// the minimum a producer->consumer pair requires); every other kind of
	// shallow sequence is still gated by depth exactly as before, so this
	// doesn't flood disk with generic 2-step attempts that have nothing
	// resource-graph-interesting to show.
	hasRealIDChain := f.cfg.ResourceGraphEnabled && state.Depth >= 1 && f.sequenceHasRealIDChain(state)
	if state.Depth < 2 && !hasRealIDChain { // Depth is 0-indexed, so 2 means length 3
		return
	}

	// Must be mostly successful
	successCount := 0
	for _, step := range state.History {
		if step.Status >= 200 && step.Status < 400 {
			successCount++
		}
	}
	successRatio := float64(successCount) / float64(len(state.History))

	// Benchmark event stream (BENCHMARK_PLAN.md §12 sequence_event.jsonl, a
	// no-op unless -event-log was passed): every sequence that reached this
	// terminal point is logged here, regardless of whether it goes on to be
	// persisted to disk below -- "sequences attempted" needs the full
	// population, not just the successful subset.
	f.logSequenceEvent(state, successRatio >= 0.5)

	// Must have produced some coverage overall
	if state.Energy <= 0 {
		return
	}

	if successRatio < 0.5 {
		return
	}

	// Dedup by final workflow shape (Top-20 #12): many sequences reach the exact
	// same (method,normpath,status-class) shape via different concrete IDs/values
	// -- those are equivalent workflows for reporting purposes, so only one
	// exemplar is kept on disk per shape. Addresses docs/ARCHITECTURE_REVIEW.md §5
	// weakness #3 ("no dedup of equivalent workflows").
	//
	// Item #1 (docs/resource-state-graph-report.md): the kept exemplar is no
	// longer strictly "whichever arrived first" -- if a later occurrence of the
	// same shape carries genuine real-ID provenance and the currently-persisted
	// exemplar doesn't, the later one replaces it on disk. This directly
	// improves what a reader inspecting crashes/workflows/ actually sees,
	// without persisting more files overall (still exactly one exemplar per
	// shape) and without changing scheduling or any other behavior.
	sig := sequenceStateSignature(state)
	if existing, dup := f.persistedWorkflowExemplars[sig]; dup {
		f.dedupDuplicateRejected++
		if hasRealIDChain {
			f.dedupRealIDChainRejected++
			if !existing.hasRealIDChain {
				f.replacePersistedWorkflow(existing, state)
				f.persistedWorkflowExemplars[sig] = persistedExemplar{seqID: state.ID, depth: state.Depth, hasRealIDChain: true}
				f.dedupRealIDChainUpgrades++
			}
		}
		return
	}
	f.persistedWorkflowExemplars[sig] = persistedExemplar{seqID: state.ID, depth: state.Depth, hasRealIDChain: hasRealIDChain}

	// Save to disk
	f.persistWorkflow(state)
	f.workflowsPersisted++
}

// persistedExemplar tracks which sequence is currently the on-disk exemplar
// for a given workflow shape signature (sequenceStateSignature), so a later
// sequence reaching the same shape with genuine real-ID chain provenance can
// replace a weaker (e.g. placeholder-value) earlier exemplar instead of being
// silently discarded -- see maybePersistSequence's dedup-upgrade path (item #1).
type persistedExemplar struct {
	seqID          string
	depth          int
	hasRealIDChain bool
}

// replacePersistedWorkflow removes the on-disk exemplar for a shape (an
// earlier, weaker-provenance sequence) and persists the new, real-ID-backed
// one in its place.
func (f *Fuzzer) replacePersistedWorkflow(old persistedExemplar, newState *SequenceState) {
	oldJSON, oldSH := f.workflowFilePaths(old.depth, old.seqID)
	_ = os.Remove(oldJSON)
	_ = os.Remove(oldSH)
	f.persistWorkflow(newState)
}

// logSequenceEvent appends one row to sequence_event.jsonl (BENCHMARK_PLAN.md
// §12), a no-op unless -event-log was passed. new_coverage reports
// state.Energy as the closest available proxy -- it blends real coverage
// gain with the state-novelty bonus (Top-20 #12, stateNoveltyBonus), not a
// pure edge count; produced_bug_id is a comma-joined list of root-cause
// cluster keys crash.go's recordCrash recorded against this sequence ID
// (item #4, docs/resource-state-graph-report.md) -- empty if none, not a
// placeholder.
func (f *Fuzzer) logSequenceEvent(state *SequenceState, successFlag bool) {
	if f.sequenceEventWriter == nil {
		return
	}
	steps := make([]map[string]any, 0, len(state.History))
	for _, step := range state.History {
		steps = append(steps, map[string]any{
			"method": step.Method,
			"path":   step.Path,
			"status": step.Status,
		})
	}
	// Item #4 (docs/resource-state-graph-report.md): produced_bug_id now
	// reflects the root-cause cluster key(s) crash.go's recordCrash indexed
	// under this sequence ID, if any -- previously always "" (see the removed
	// comment above this function, which called that out as a genuine,
	// undisguised gap rather than a silently-faked field).
	producedBugID := strings.Join(f.crashesBySequence[state.ID], ",")
	row := map[string]any{
		"run_id":             f.cfg.RunID,
		"ts":                 time.Now().Unix(),
		"sequence_id":        state.ID,
		"shape_signature":    sequenceStateSignature(state),
		"depth":              state.Depth,
		"steps":              steps,
		"harvested_entities": state.Values,
		"success_flag":       successFlag,
		"new_coverage":       state.Energy,
		"produced_bug_id":    producedBugID,
	}
	_ = f.sequenceEventWriter.Write(row)
}

// sequenceStateSignature computes a coarse state signature for a sequence: the
// ordered SHAPE of (method, normalized-path, status-class) steps taken so far.
// Two sequences that reach the same shape via different concrete IDs/payloads
// are treated as the same "state" -- intentionally coarse (no resource
// lifecycle/typed state graph), but enough to reward reaching a new workflow
// shape instead of only a new coverage edge (Top-20 #12).
func sequenceStateSignature(state *SequenceState) string {
	parts := make([]string, 0, len(state.History))
	for _, step := range state.History {
		// normalizeEndpointPath (not normalizePath) so different concrete resource
		// ids collapse to the same route template -- otherwise every sequence would
		// look "new" purely because it touched a different numeric/UUID id.
		parts = append(parts, fmt.Sprintf("%s %s:%d", step.Method, normalizeEndpointPath(step.Path), statusClass(step.Status)))
	}
	return strings.Join(parts, "|")
}

// statusClass buckets an HTTP status into a coarse class for state-signature
// purposes (2xx/3xx/4xx/5xx), so e.g. 200 vs 201 don't count as different states
// but 200 vs 404 do.
func statusClass(status int) int {
	switch {
	case status >= 200 && status < 300:
		return 2
	case status >= 300 && status < 400:
		return 3
	case status >= 400 && status < 500:
		return 4
	case status >= 500:
		return 5
	default:
		return 0
	}
}

// sequenceHasRealIDChain reports whether this sequence's own resource-graph
// snapshot shows a genuine producer(response)->consumer(later request) reuse
// of a real, GUID-shaped identity value -- i.e. a value extracted from an
// earlier step's response literally reappearing in a later step's request
// path/body/headers. This is a diagnostic-only check (dedupRealIDChainRejected
// in maybePersistSequence): it measures the ceiling on how many dedup-rejected
// sequences would have upgraded the persisted exemplar for their shape if the
// dedup tie-breaker preferred real-ID provenance over first-arrival. It never
// affects scheduling, persistence, or any other behavior.
func (f *Fuzzer) sequenceHasRealIDChain(state *SequenceState) bool {
	resources, _ := f.resourceGraph.snapshotForSequence(state.ID)
	if len(resources) == 0 {
		return false
	}
	hist := state.History
	for _, r := range resources {
		rawVal := r.Canonical.RawValue
		if !reUUIDLike.MatchString(rawVal) {
			continue
		}
		producedAt := -1
		for i, h := range hist {
			if h.Method+" "+h.Path == r.SourceOperation {
				producedAt = i
				break
			}
		}
		if producedAt < 0 {
			continue
		}
		for j := producedAt + 1; j < len(hist); j++ {
			headersJSON, _ := json.Marshal(hist[j].Headers)
			haystack := hist[j].Path + " " + hist[j].Body + " " + string(headersJSON)
			if strings.Contains(haystack, rawVal) {
				return true
			}
		}
	}
	return false
}

// workflowFilePaths returns the on-disk paths persistWorkflow uses for a given
// sequence (depth, ID) pair. Shared with replacePersistedWorkflow (item #1)
// so an upgraded exemplar's old files can be located and removed.
func (f *Fuzzer) workflowFilePaths(depth int, seqID string) (jsonPath, shPath string) {
	outDir := filepath.Join(filepath.Dir(f.cfg.TimelineDir), "workflows")
	fnameBase := fmt.Sprintf("workflow_d%d_%s", depth+1, seqID)
	return filepath.Join(outDir, fnameBase+".json"), filepath.Join(outDir, fnameBase+".sh")
}

func (f *Fuzzer) persistWorkflow(state *SequenceState) {
	if f.cfg.TimelineDir == "" {
		return
	}
	outDir := filepath.Join(filepath.Dir(f.cfg.TimelineDir), "workflows")
	_ = os.MkdirAll(outDir, 0o755)

	if f.cfg.ResourceGraphEnabled {
		state.Resources, state.Transitions = f.resourceGraph.snapshotForSequence(state.ID)
	}

	fpathJSON, fpathSH := f.workflowFilePaths(state.Depth, state.ID)

	buf, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = os.WriteFile(fpathJSON, buf, 0o644)
	}

	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString(fmt.Sprintf("# Auto-generated Deep Workflow Reproduction Script (Depth: %d, Energy: %.0f)\n\n", state.Depth+1, state.Energy))
	sb.WriteString(fmt.Sprintf("TARGET=\"%s\"\n\n", f.target))

	for i, step := range state.History {
		sb.WriteString(fmt.Sprintf("# Step %d: %s %s (Expected Status: %d, Mut: %s)\n", i+1, step.Method, step.Path, step.Status, step.MutationLabel))
		sb.WriteString(fmt.Sprintf("curl -i -X %s \"$TARGET%s\" \\\n", step.Method, step.Path))

		for k, v := range step.Headers {
			sb.WriteString(fmt.Sprintf("  -H '%s: %s' \\\n", k, strings.ReplaceAll(v, "'", "'\\''")))
		}

		if step.Body != "" {
			sb.WriteString(fmt.Sprintf("  -d '%s'\n", strings.ReplaceAll(step.Body, "'", "'\\''")))
		} else {
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	_ = os.WriteFile(fpathSH, []byte(sb.String()), 0o755)
}

func (f *Fuzzer) findFollowups(sourceID int, sourceMethod, sourceNorm string, producedDeps, producedIDKeys []string, tenantKey string) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, 16)
	for _, dep := range producedDeps {
		for _, tid := range f.depConsumers[dep] {
			if tid == sourceID {
				continue
			}
			if f.isTemplateBlocked(tid) {
				continue
			}
			if _, ok := seen[tid]; ok {
				continue
			}
			seen[tid] = struct{}{}
			out = append(out, tid)
		}
	}
	for _, idk := range producedIDKeys {
		for _, tid := range f.idConsumers[canonicalKey(idk)] {
			if tid == sourceID {
				continue
			}
			if f.isTemplateBlocked(tid) {
				continue
			}
			if _, ok := seen[tid]; ok {
				continue
			}
			seen[tid] = struct{}{}
			out = append(out, tid)
		}
	}
	for _, tid := range f.activeIDs {
		if tid == sourceID {
			continue
		}
		if f.isTemplateBlocked(tid) {
			continue
		}
		if _, ok := seen[tid]; ok {
			continue
		}
		m := f.meta[tid]
		sameFamily := m.Norm == sourceNorm || strings.HasPrefix(m.Norm, sourceNorm+"/") || strings.HasPrefix(sourceNorm, m.Norm+"/")
		if !sameFamily {
			continue
		}
		if m.Method == sourceMethod && m.Norm == sourceNorm {
			continue
		}
		seen[tid] = struct{}{}
		out = append(out, tid)
	}

	if f.cfg.ResourceGraphEnabled {
		// Coverage-directed ranking (docs/resource-state-graph-plan.md §8.4):
		// blends historical coverage yield, never-reached bonus, and failure
		// penalty with the static verb-affinity table below as one input among
		// several, instead of static priority being the sole signal.
		return f.rankConsumersCoverageDirected(out, sourceMethod, sourceNorm, tenantKey)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a := f.meta[out[i]]
		b := f.meta[out[j]]
		return followupPriority(sourceMethod, sourceNorm, a.Method, a.Norm) < followupPriority(sourceMethod, sourceNorm, b.Method, b.Norm)
	})
	return out
}

func followupPriority(sourceMethod, sourceNorm, candMethod, candNorm string) int {
	s := strings.ToUpper(sourceMethod)
	c := strings.ToUpper(candMethod)
	score := 100
	if s == "POST" {
		switch c {
		case "GET":
			score -= 40
		case "PUT", "PATCH":
			score -= 25
		case "DELETE":
			score -= 12
		}
	} else if s == "PUT" || s == "PATCH" {
		switch c {
		case "GET":
			score -= 35
		case "DELETE":
			score -= 18
		}
	} else if s == "GET" {
		switch c {
		case "PUT", "PATCH":
			score -= 20
		case "DELETE":
			score -= 10
		}
	}
	if candNorm == sourceNorm && c == "GET" {
		score -= 8
	}
	if len(candNorm) > len(sourceNorm) {
		score -= 5
	}
	if strings.Contains(candNorm, "{") && strings.Contains(candNorm, "}") {
		score -= 3
	}
	return score
}

func (f *Fuzzer) learnFromRequestContext(path, body string) int {
	learned := 0
	vals := make([][2]string, 0, 32)
	rels := make([][4]string, 0, 64)

	pathVals := extractPathTokens(path)
	vals = append(vals, pathVals...)
	if rid := inferResourceIDKeyFromPath(path); rid != "" && len(pathVals) > 0 {
		vals = append(vals, [2]string{rid, pathVals[len(pathVals)-1][1]})
	}

	bodyVals := make([][2]string, 0, 32)
	bodyRels := make([][4]string, 0, 64)
	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			extractJSONRuntimeValues(js, &bodyVals, &bodyRels, f.runtime, "", 0)
		}
	} else if strings.Contains(body, "=") {
		if valsQ, err := url.ParseQuery(body); err == nil {
			for k, arr := range valsQ {
				if strings.TrimSpace(k) == "" || len(arr) == 0 {
					continue
				}
				v := normalizeValue(arr[0])
				if !isUsefulValue(v) {
					continue
				}
				bodyVals = append(bodyVals, [2]string{k, v})
			}
		}
	}
	vals = append(vals, bodyVals...)
	rels = append(rels, bodyRels...)

	pathIDs := filterIDLikePairs(pathVals)
	bodyIDs := filterIDLikePairs(bodyVals)
	for i := 0; i < minInt(8, len(pathIDs)); i++ {
		for j := 0; j < minInt(12, len(bodyIDs)); j++ {
			rels = append(rels, [4]string{pathIDs[i][0], pathIDs[i][1], bodyIDs[j][0], bodyIDs[j][1]})
		}
	}

	for _, kv := range vals {
		if f.runtime.addValue(kv[0], kv[1]) {
			learned++
		}
	}
	for _, rr := range rels {
		if f.runtime.addRelation(rr[0], rr[1], rr[2], rr[3]) {
			learned++
		}
	}
	return learned
}

func (f *Fuzzer) learnFromResponse(body string, headers map[string]string) int {
	learned := 0
	vals := make([][2]string, 0, 32)
	rels := make([][4]string, 0, 64)

	location := headers["Location"]
	if location == "" {
		location = headers["location"]
	}
	if location != "" {
		if u, err := url.Parse(location); err == nil {
			vals = append(vals, extractPathTokens(u.Path)...)
		} else {
			vals = append(vals, extractPathTokens(location)...)
		}
	}

	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			extractJSONRuntimeValues(js, &vals, &rels, f.runtime, "", 0)
		}
	}
	for _, kv := range vals {
		if f.runtime.addValue(kv[0], kv[1]) {
			learned++
		}
	}
	for _, rr := range rels {
		if f.runtime.addRelation(rr[0], rr[1], rr[2], rr[3]) {
			learned++
		}
	}
	return learned
}

var (
	depNameNoise = map[string]struct{}{
		"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}, "post": {}, "put": {}, "get": {}, "delete": {},
		"patch": {}, "query": {}, "header": {}, "body": {}, "path": {}, "data": {}, "audit": {}, "created": {},
		"updated": {}, "writer": {}, "reader": {}, "response": {}, "request": {}, "status": {}, "name": {},
		"primary": {}, "reverse": {}, "notes": {}, "revision": {}, "true": {}, "false": {},
	}
	pathTokenNoise = map[string]struct{}{
		"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}, "pairs": {}, "pair": {}, "rates": {}, "rate": {},
		"currencies": {}, "currency": {}, "users": {}, "user": {}, "accounts": {}, "account": {},
	}
	resourcePathNoise = map[string]struct{}{"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}}
	runtimeLearnKeys  = []string{"id", "code", "name", "externalid", "status", "type", "revision", "key", "slug"}
)

func inferDependencyKeys(depName string) []string {
	dep := strings.ToLower(depName)
	tokens := splitNonAlnum(dep)
	keys := []string{}
	hasAnyID := false
	for _, t := range tokens {
		if t == "id" || strings.HasSuffix(t, "id") {
			hasAnyID = true
			break
		}
	}
	for _, m := range reWordID.FindAllStringSubmatch(dep, -1) {
		if len(m) < 2 {
			continue
		}
		base := m[1]
		if _, bad := depNameNoise[base]; !bad && base != "" {
			keys = append(keys, base+"Id")
		}
	}
	for i, t := range tokens {
		if _, bad := depNameNoise[t]; bad || t == "" {
			continue
		}
		if strings.HasSuffix(t, "id") && len(t) > 2 {
			base := t[:len(t)-2]
			if _, bad := depNameNoise[base]; !bad && base != "" {
				keys = append(keys, base+"Id")
			}
		}
		if t == "id" {
			if i > 0 {
				prev := tokens[i-1]
				if _, bad := depNameNoise[prev]; !bad && prev != "" {
					keys = append(keys, singularize(prev)+"Id")
				}
			}
			keys = append(keys, "id")
		}
	}
	if hasAnyID {
		for _, t := range tokens {
			if _, bad := depNameNoise[t]; bad || t == "" {
				continue
			}
			keys = append(keys, singularize(t)+"Id")
		}
	}
	if !hasAnyID && len(keys) == 0 {
		return nil
	}
	keys = append(keys, "id")
	keys = dedupStrings(keys)
	if len(keys) > 10 {
		keys = keys[:10]
	}
	return keys
}

func extractPathTokens(path string) [][2]string {
	out := make([][2]string, 0, 16)
	if path == "" {
		return out
	}
	for _, token := range strings.Split(path, "/") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		if _, bad := pathTokenNoise[strings.ToLower(t)]; bad {
			continue
		}
		hasShape := strings.ContainsAny(t, "0123456789") || strings.Contains(t, "-") || strings.Contains(t, "_")
		if !hasShape {
			continue
		}
		if len(t) > 128 {
			continue
		}
		out = append(out, [2]string{"id", t})
	}
	return out
}

func inferResourceIDKeyFromPath(path string) string {
	if path == "" {
		return ""
	}
	tokens := []string{}
	for _, token := range strings.Split(path, "/") {
		t := strings.ToLower(strings.TrimSpace(token))
		if t == "" {
			continue
		}
		if _, bad := resourcePathNoise[t]; bad {
			continue
		}
		if strings.Contains(t, "{") || strings.Contains(t, "}") || t == "-" {
			continue
		}
		if _, err := strconv.Atoi(t); err == nil {
			continue
		}
		if strings.ContainsAny(t, "0123456789") {
			continue
		}
		tokens = append(tokens, t)
	}
	if len(tokens) == 0 {
		return ""
	}
	return singularize(tokens[len(tokens)-1]) + "Id"
}

// extractJSONRuntimeValues recurses into a decoded JSON response/request body,
// collecting flat (key, value) learnable pairs into outVals/outRels exactly as
// before. rt and pathPrefix are additive (typed structural mutation Stage 6):
// when rt is non-nil, every learnable leaf ALSO gets recorded into rt's
// path-qualified index (store.go's pathValues, keyed "resourceType.dotted.path")
// alongside the existing flat outVals write, so body_bind.go's Tier-1 lookup
// has real data to find. Passing rt=nil (as every existing test call site
// does) skips this entirely and reproduces the exact prior behavior.
func extractJSONRuntimeValues(node any, outVals *[][2]string, outRels *[][4]string, rt *RuntimeStore, pathPrefix string, depth int) {
	if depth > 6 {
		return
	}
	switch tv := node.(type) {
	case map[string]any:
		locals := make([][2]string, 0, len(tv))
		for k, v := range tv {
			fieldPath := k
			if pathPrefix != "" {
				fieldPath = pathPrefix + "." + k
			}
			kn := canonicalKey(k)
			isLearnable := strings.HasSuffix(kn, "id")
			if !isLearnable {
				for _, rk := range runtimeLearnKeys {
					if kn == rk || strings.HasSuffix(kn, rk) {
						isLearnable = true
						break
					}
				}
			}
			if isLearnable {
				if scalar, ok := toUsefulScalar(v); ok {
					*outVals = append(*outVals, [2]string{k, scalar})
					locals = append(locals, [2]string{k, scalar})
					recordScopedPathValue(rt, k, fieldPath, scalar)
				}
			}
			if m, ok := v.(map[string]any); ok {
				idField, nested, hasNested := "", any(nil), false
				if nv, ok := m["id"]; ok {
					idField, nested, hasNested = "id", nv, true
				} else if nv, ok := m["Id"]; ok {
					idField, nested, hasNested = "Id", nv, true
				}
				if hasNested {
					if scalar, ok := toUsefulScalar(nested); ok {
						nk := k + "Id"
						*outVals = append(*outVals, [2]string{nk, scalar})
						locals = append(locals, [2]string{nk, scalar})
						recordScopedPathValue(rt, nk, fieldPath+"."+idField, scalar)
					}
				}
			}
			extractJSONRuntimeValues(v, outVals, outRels, rt, fieldPath, depth+1)
		}
		if len(locals) > 1 {
			if len(locals) > 10 {
				locals = locals[:10]
			}
			for i := 0; i < len(locals); i++ {
				for j := i + 1; j < len(locals); j++ {
					*outRels = append(*outRels, [4]string{locals[i][0], locals[i][1], locals[j][0], locals[j][1]})
				}
			}
		}
	case []any:
		limit := minInt(100, len(tv))
		for i := 0; i < limit; i++ {
			extractJSONRuntimeValues(tv[i], outVals, outRels, rt, pathPrefix, depth+1)
		}
	}
}

// recordScopedPathValue is a no-op when rt is nil or the key isn't
// resource-type-shaped (resourceTypeFromKeyName returning "" for e.g. a bare
// "id" whose only type signal lives in its parent field's name, not its own).
func recordScopedPathValue(rt *RuntimeStore, key, path, value string) {
	if rt == nil {
		return
	}
	if resType := resourceTypeFromKeyName(key); resType != "" {
		rt.recordPathValue(resType+"."+path, value)
	}
}

func extractEntityIDs(body string, headers map[string]string) []string {
	out := []string{}
	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			if m, ok := js.(map[string]any); ok {
				if id, ok := m["id"]; ok {
					if s, ok := toUsefulScalar(id); ok {
						out = append(out, s)
					}
				} else if id, ok := m["Id"]; ok {
					if s, ok := toUsefulScalar(id); ok {
						out = append(out, s)
					}
				}
				if data, ok := m["data"].([]any); ok {
					for _, el := range data {
						if mm, ok := el.(map[string]any); ok {
							if id, ok := mm["id"]; ok {
								if s, ok := toUsefulScalar(id); ok {
									out = append(out, s)
								}
							} else if id, ok := mm["Id"]; ok {
								if s, ok := toUsefulScalar(id); ok {
									out = append(out, s)
								}
							}
						}
					}
				}
			}
		}
	}
	loc := headers["Location"]
	if loc == "" {
		loc = headers["location"]
	}
	if loc != "" {
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		if len(parts) > 0 {
			last := strings.TrimSpace(parts[len(parts)-1])
			if isUsefulValue(last) {
				out = append(out, last)
			}
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}

// enqueueCrashReplay queues n follow-up work items after a unique crash is found.
// It re-renders the crashing template with varying mutation modes to find bug variants.
func (f *Fuzzer) enqueueCrashReplay(item WorkItem, n int) {
	if n <= 0 || f.isTemplateBlocked(item.TemplateID) {
		return
	}
	epKey := endpointKey(item.Method, normalizePath(item.Path))
	if f.cfg.CrashReplayPerEndpoint > 0 {
		remaining := f.cfg.CrashReplayPerEndpoint - f.replayByEndpoint[epKey]
		if remaining <= 0 {
			return
		}
		n = minInt(n, remaining)
	}
	queueMax := maxInt(1, f.cfg.CrashReplayQueueMax)
	added := 0
	modes := []string{"mutate", "havoc", "mutate", "havoc", "havoc"}
	for i := 0; i < n; i++ {
		if len(f.replayQueue) >= queueMax {
			break
		}
		mode := modes[i%len(modes)]
		depth := 1 + (i / len(modes))
		rendered, err := f.renderTemplate(item.TemplateID, mode, depth, -1)
		if err != nil {
			// Fall back to replaying the exact crashing item.
			replay := item
			replay.MutationLabel = fmt.Sprintf("crash_replay_%d", i)
			replay.MutationName = "crash_replay"
			replay.EpochName = "Replay"
			f.replayQueue = append(f.replayQueue, replay)
			added++
			continue
		}
		rendered.MutationLabel = "crash_replay+" + rendered.MutationLabel
		rendered.MutationName = "crash_replay"
		rendered.EpochName = "Replay"
		f.replayQueue = append(f.replayQueue, rendered)
		added++
	}
	if added > 0 {
		f.replayByEndpoint[epKey] += added
	}
}
