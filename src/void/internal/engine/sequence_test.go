package engine

import (
	"os"
	"path/filepath"
	"testing"

	"void/internal/config"
)

// TestStatusClass verifies the coarse status bucketing used by state signatures
// (Top-20 #12): 200 vs 201 must collapse to the same class, but 2xx/4xx/5xx must
// differ.
func TestStatusClass(t *testing.T) {
	cases := map[int]int{
		200: 2, 201: 2, 204: 2, 299: 2,
		301: 3, 302: 3,
		400: 4, 404: 4, 499: 4,
		500: 5, 503: 5,
		100: 0,
	}
	for status, want := range cases {
		if got := statusClass(status); got != want {
			t.Errorf("statusClass(%d) = %d, want %d", status, got, want)
		}
	}
}

// TestSequenceStateSignature verifies the workflow-shape signature (Top-20 #12)
// is sensitive to step order and status class, but not to concrete IDs/bodies.
func TestSequenceStateSignature(t *testing.T) {
	mkState := func(steps ...SequenceStep) *SequenceState {
		return &SequenceState{History: steps}
	}

	postThenGet := mkState(
		SequenceStep{Method: "POST", Path: "/orders", Status: 201},
		SequenceStep{Method: "GET", Path: "/orders/123", Status: 200},
	)
	getThenPost := mkState(
		SequenceStep{Method: "GET", Path: "/orders/123", Status: 200},
		SequenceStep{Method: "POST", Path: "/orders", Status: 201},
	)
	if sequenceStateSignature(postThenGet) == sequenceStateSignature(getThenPost) {
		t.Errorf("step order must affect the signature")
	}

	// Different concrete resource id, same shape -> identical signature (both
	// normalizePath and statusClass collapse status 201 the same as 200 would).
	postThenGetOtherID := mkState(
		SequenceStep{Method: "POST", Path: "/orders", Status: 201},
		SequenceStep{Method: "GET", Path: "/orders/999", Status: 200},
	)
	if sequenceStateSignature(postThenGet) != sequenceStateSignature(postThenGetOtherID) {
		t.Errorf("different concrete IDs with the same shape must produce the same signature")
	}

	// A different status class on the same step must change the signature.
	postThenGetFailed := mkState(
		SequenceStep{Method: "POST", Path: "/orders", Status: 201},
		SequenceStep{Method: "GET", Path: "/orders/123", Status: 404},
	)
	if sequenceStateSignature(postThenGet) == sequenceStateSignature(postThenGetFailed) {
		t.Errorf("a different status class must change the signature")
	}
}

// TestEnqueueSequenceFollowupsRewardsNewStateOnce verifies that reaching a
// workflow shape for the first time awards the state-novelty energy bonus and
// increments newStatesFound, but reaching the identical shape again does not
// (Top-20 #12). Uses a 4xx status so the function takes its early-return path
// right after computing the signature, without needing template rendering.
func TestEnqueueSequenceFollowupsRewardsNewStateOnce(t *testing.T) {
	f := &Fuzzer{
		depIndex:                   map[int]DepInfo{},
		meta:                       map[int]TemplateMeta{},
		seenStateSigs:              map[string]struct{}{},
		persistedWorkflowExemplars: map[string]persistedExemplar{},
		cfg:                        config.Config{SequenceMaxDepth: 3},
	}

	mkRes := func() SendResult {
		return SendResult{
			Item:   WorkItem{TemplateID: 1, Method: "GET", Path: "/widgets/1"},
			Status: 404,
		}
	}

	if n := f.enqueueSequenceFollowups(mkRes()); n != 0 {
		t.Fatalf("expected 0 enqueued on a 404 (no branching), got %d", n)
	}
	if f.newStatesFound != 1 {
		t.Fatalf("expected newStatesFound=1 after the first 404 of this shape, got %d", f.newStatesFound)
	}

	if n := f.enqueueSequenceFollowups(mkRes()); n != 0 {
		t.Fatalf("expected 0 enqueued on a repeat 404, got %d", n)
	}
	if f.newStatesFound != 1 {
		t.Fatalf("expected newStatesFound to stay at 1 for a repeat of the same shape, got %d", f.newStatesFound)
	}
}

// TestEnqueueSequenceFollowupsAwardsTransitionNoveltyBonus verifies that the
// first-ever recorded resource transition (always novel on a fresh graph)
// awards transitionNoveltyBonus to the sequence's own Energy. Crafted to hit
// the seqStopNoFollowupCandidate early-return (no templates registered) --
// after the novelty bonus is applied, before template rendering would be
// needed -- mirroring TestSeqStopCounters_NoFollowupCandidate's setup
// (improvements_test.go).
func TestEnqueueSequenceFollowupsAwardsTransitionNoveltyBonus(t *testing.T) {
	f := &Fuzzer{
		depIndex:                   map[int]DepInfo{},
		meta:                       map[int]TemplateMeta{1: {Method: "POST", Norm: "/widgets"}},
		tmplEPKey:                  map[int]string{},
		endpointStats:              map[string]*EndpointStats{},
		seenStateSigs:              map[string]struct{}{},
		persistedWorkflowExemplars: map[string]persistedExemplar{},
		resourceGraph:              newResourceGraph(ResourceGraphLimits{}),
		runtime:                    newRuntimeStore(),
		cfg:                        config.Config{SequenceMaxDepth: 3, ResourceGraphEnabled: true},
	}

	state := &SequenceState{ID: "seq-1", Values: map[string]string{}, Provenance: map[string]string{}}
	n := f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "POST", Path: "/widgets", SeqState: state},
		Status: 201,
		Body:   `{"id":"1"}`,
	})
	if n != 0 {
		t.Fatalf("expected 0 enqueued (no templates registered to follow up with), got %d", n)
	}
	if f.seqStopNoFollowupCandidate != 1 {
		t.Fatalf("test setup bug: expected the no-followup-candidate stop reason, got seqStopNoFollowupCandidate=%d", f.seqStopNoFollowupCandidate)
	}
	if state.Energy < transitionNoveltyBonus {
		t.Fatalf("expected the first-ever transition to be novel and award transitionNoveltyBonus (%v), got Energy=%v", transitionNoveltyBonus, state.Energy)
	}
}

func TestEnqueueSequenceFollowupsNoBonusWhenResourceGraphDisabled(t *testing.T) {
	f := &Fuzzer{
		depIndex:                   map[int]DepInfo{1: {}},
		meta:                       map[int]TemplateMeta{1: {Method: "POST", Norm: "/widgets"}},
		tmplEPKey:                  map[int]string{},
		endpointStats:              map[string]*EndpointStats{},
		seenStateSigs:              map[string]struct{}{},
		persistedWorkflowExemplars: map[string]persistedExemplar{},
		runtime:                    newRuntimeStore(),
		cfg:                        config.Config{SequenceMaxDepth: 3, ResourceGraphEnabled: false},
	}
	state := &SequenceState{ID: "seq-1", Values: map[string]string{}, Provenance: map[string]string{}}
	f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "POST", Path: "/widgets", SeqState: state},
		Status: 201,
		Body:   `{"id":"1"}`,
	})
	// stateNoveltyBonus (workflow-shape novelty) is unrelated to
	// -resource-graph and always applies -- only transitionNoveltyBonus must
	// be skipped when the resource graph is disabled.
	if state.Energy != stateNoveltyBonus {
		t.Fatalf("expected only stateNoveltyBonus (%v) with -resource-graph=false, got Energy=%v (would include transitionNoveltyBonus if not properly gated)", stateNoveltyBonus, state.Energy)
	}
}

// TestNextChainDepthAndEnergy verifies the "personal best" pattern:
// maxChainDepthBonus is awarded exactly once, the first time a run reaches a
// new maximum chain depth -- not on every step at every depth.
func TestNextChainDepthAndEnergy_FirstTimeAtDepthAwardsBonus(t *testing.T) {
	f := &Fuzzer{}
	depth, energy := f.nextChainDepthAndEnergy(&SequenceState{Depth: 0, Energy: 10})
	if depth != 1 {
		t.Fatalf("expected depth=1, got %d", depth)
	}
	if energy != 10+maxChainDepthBonus {
		t.Fatalf("expected energy=10+maxChainDepthBonus=%v, got %v", 10+maxChainDepthBonus, energy)
	}
	if f.maxChainDepthSeen != 1 {
		t.Fatalf("expected maxChainDepthSeen updated to 1, got %d", f.maxChainDepthSeen)
	}
}

func TestNextChainDepthAndEnergy_RepeatAtSameDepthNoBonus(t *testing.T) {
	f := &Fuzzer{maxChainDepthSeen: 2}
	// A branch reaching depth=2 again (a sibling branch, not a new max) must
	// not re-earn the bonus.
	_, energy := f.nextChainDepthAndEnergy(&SequenceState{Depth: 1, Energy: 10})
	if energy != 10 {
		t.Fatalf("expected no bonus for a depth already reached this run, got energy=%v", energy)
	}
}

func TestNextChainDepthAndEnergy_DeeperChainStillAwardsBonus(t *testing.T) {
	f := &Fuzzer{maxChainDepthSeen: 2}
	_, energy := f.nextChainDepthAndEnergy(&SequenceState{Depth: 2, Energy: 10})
	if energy != 10+maxChainDepthBonus {
		t.Fatalf("expected a new max depth (3) to earn the bonus, got energy=%v", energy)
	}
	if f.maxChainDepthSeen != 3 {
		t.Fatalf("expected maxChainDepthSeen updated to 3, got %d", f.maxChainDepthSeen)
	}
}

// TestMaybePersistSequenceDedupsByFinalShape verifies that two workflows with
// the same final state signature (same step shapes, different concrete
// payloads) are only persisted once (Top-20 #12, closing the "no dedup of
// equivalent workflows" gap in docs/ARCHITECTURE_REVIEW.md §5).
func TestMaybePersistSequenceDedupsByFinalShape(t *testing.T) {
	f := &Fuzzer{persistedWorkflowExemplars: map[string]persistedExemplar{}}

	mkState := func(body string) *SequenceState {
		return &SequenceState{
			ID:     "seq-x",
			Depth:  2, // 0-indexed: length-3 history
			Energy: 3,
			History: []SequenceStep{
				{Method: "POST", Path: "/widgets", Status: 201, Body: body},
				{Method: "GET", Path: "/widgets/1", Status: 200},
				{Method: "DELETE", Path: "/widgets/1", Status: 204},
			},
		}
	}

	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: mkState(`{"name":"a"}`)}})
	if f.workflowsPersisted != 1 {
		t.Fatalf("expected workflowsPersisted=1 after the first equivalent workflow, got %d", f.workflowsPersisted)
	}

	// Same shape, different payload -> must be treated as equivalent, not persisted again.
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: mkState(`{"name":"b"}`)}})
	if f.workflowsPersisted != 1 {
		t.Fatalf("expected workflowsPersisted to stay at 1 for an equivalent workflow, got %d", f.workflowsPersisted)
	}
}

func TestFollowupPriority(t *testing.T) {
	// A GET after a POST should be preferred (lower score) over a DELETE after a POST.
	getScore := followupPriority("POST", "/widgets", "GET", "/widgets/{id}")
	deleteScore := followupPriority("POST", "/widgets", "DELETE", "/widgets/{id}")
	if getScore >= deleteScore {
		t.Errorf("expected GET-after-POST (%d) to score lower than DELETE-after-POST (%d)", getScore, deleteScore)
	}
	// An unrelated method-pair combination should still return the baseline.
	if got := followupPriority("DELETE", "/widgets", "POST", "/other"); got != 100 {
		t.Errorf("expected baseline score 100 for an uncategorized source method, got %d", got)
	}
}

func TestInferDependencyKeys(t *testing.T) {
	got := inferDependencyKeys("orderId")
	found := false
	for _, k := range got {
		if k == "id" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected inferDependencyKeys to always include the plain 'id' key, got %v", got)
	}

	if got := inferDependencyKeys("v1"); got != nil {
		t.Errorf("expected pure-noise dep names to produce no keys, got %v", got)
	}
}

func TestExtractPathTokens(t *testing.T) {
	got := extractPathTokens("/api/orders/12345/items/abc-def")
	if len(got) == 0 {
		t.Fatal("expected at least one shaped token extracted")
	}
	for _, kv := range got {
		if kv[0] != "id" {
			t.Errorf("expected key 'id' for every extracted path token, got %q", kv[0])
		}
	}
	// A plain word segment with no digit/hyphen/underscore "shape" is skipped.
	if got := extractPathTokens("/api/orders"); len(got) != 0 {
		t.Errorf("expected no tokens for a path with no id-shaped segments, got %v", got)
	}
	if got := extractPathTokens(""); len(got) != 0 {
		t.Errorf("expected no tokens for an empty path, got %v", got)
	}
}

func TestInferResourceIDKeyFromPath(t *testing.T) {
	if got := inferResourceIDKeyFromPath("/api/orders/12345"); got != "orderId" {
		t.Errorf("inferResourceIDKeyFromPath(/api/orders/12345) = %q, want orderId", got)
	}
	if got := inferResourceIDKeyFromPath(""); got != "" {
		t.Errorf("expected empty string for an empty path, got %q", got)
	}
	// Only numeric/noise segments -> no usable trailing name token.
	if got := inferResourceIDKeyFromPath("/api/v1/123"); got != "" {
		t.Errorf("expected empty string when no non-numeric non-noise segment remains, got %q", got)
	}
}

func TestExtractJSONRuntimeValues(t *testing.T) {
	var vals [][2]string
	var rels [][4]string
	doc := map[string]any{
		"id":     "order-1",
		"status": "open",
		"owner":  map[string]any{"id": "user-1"},
		"items":  []any{map[string]any{"id": "item-1"}},
	}
	extractJSONRuntimeValues(doc, &vals, &rels, nil, "", 0)
	if len(vals) == 0 {
		t.Fatal("expected at least one learnable value extracted")
	}
	foundNestedOwner := false
	for _, kv := range vals {
		if kv[0] == "ownerId" && kv[1] == "user-1" {
			foundNestedOwner = true
		}
	}
	if !foundNestedOwner {
		t.Errorf("expected a synthesized ownerId value from the nested {id: user-1} object, got %v", vals)
	}
	if len(rels) == 0 {
		t.Error("expected at least one relation recorded among the top-level learnable fields")
	}

	// Depth guard: beyond depth 6, extraction stops early (no panic, no values).
	var deepVals [][2]string
	var deepRels [][4]string
	extractJSONRuntimeValues(map[string]any{"id": "x"}, &deepVals, &deepRels, nil, "", 7)
	if len(deepVals) != 0 {
		t.Errorf("expected no extraction past the depth guard, got %v", deepVals)
	}
}

func TestExtractJSONRuntimeValues_RecordsPathQualifiedValuesWhenRuntimeStoreGiven(t *testing.T) {
	rt := newRuntimeStore()
	var vals [][2]string
	var rels [][4]string
	doc := map[string]any{
		"order": map[string]any{
			"customerId": "cust-1",
			"shipping":   map[string]any{"id": "addr-1"},
		},
	}
	extractJSONRuntimeValues(doc, &vals, &rels, rt, "", 0)

	if got := rt.getPathValues("customer.order.customerId"); len(got) != 1 || got[0] != "cust-1" {
		t.Errorf("expected customer.order.customerId=[cust-1], got %v", got)
	}
	if got := rt.getPathValues("shipping.order.shipping.id"); len(got) != 1 || got[0] != "addr-1" {
		t.Errorf("expected shipping.order.shipping.id=[addr-1], got %v", got)
	}
}

func TestExtractEntityIDs(t *testing.T) {
	got := extractEntityIDs(`{"id":"order-1","data":[{"id":"a"},{"Id":"b"}]}`, nil)
	want := map[string]bool{"order-1": true, "a": true, "b": true}
	if len(got) != 3 {
		t.Fatalf("expected 3 extracted entity ids, got %v", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected entity id %q in %v", id, got)
		}
	}

	// Location header fallback when the body has no id.
	got2 := extractEntityIDs(`not json`, map[string]string{"Location": "/api/orders/order-7"})
	if len(got2) != 1 || got2[0] != "order-7" {
		t.Errorf("expected Location-header fallback to yield [order-7], got %v", got2)
	}

	if got3 := extractEntityIDs(`{}`, nil); len(got3) != 0 {
		t.Errorf("expected no entity ids for an empty object with no Location header, got %v", got3)
	}
}

func TestLearnFromRequestContext(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore()}
	n := f.learnFromRequestContext("/api/orders/order-123", `{"userId":"user-1","note":"hi"}`)
	if n == 0 {
		t.Error("expected at least one learned value/relation from a path id plus a JSON body id field")
	}

	// Form-encoded body path.
	f2 := &Fuzzer{runtime: newRuntimeStore()}
	if n := f2.learnFromRequestContext("/api/orders", "userId=user-1&note=hi"); n == 0 {
		t.Error("expected at least one learned value from a form-encoded body")
	}
}

func TestLearnFromResponse(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore()}
	n := f.learnFromResponse(`{"id":"order-1","ownerId":"user-9"}`, map[string]string{"Location": "/api/orders/order-1"})
	if n == 0 {
		t.Error("expected at least one learned value from a JSON body plus Location header")
	}

	f2 := &Fuzzer{runtime: newRuntimeStore()}
	if n := f2.learnFromResponse("", nil); n != 0 {
		t.Errorf("expected 0 learned values from an empty body and no headers, got %d", n)
	}
}

func TestPickFollowupPathValue(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{ResourceGraphEnabled: false}}
	value, fromGraph, ok, inst := f.pickFollowupPathValue(1, []string{"first", "second"}, "")
	if !ok || value != "first" || fromGraph || inst != nil {
		t.Errorf("expected the first entityID to win when the resource graph is disabled, got (%q,%v,%v,%v)", value, fromGraph, ok, inst)
	}

	if _, _, ok, _ := f.pickFollowupPathValue(1, nil, ""); ok {
		t.Error("expected ok=false with no entityIDs and the resource graph disabled")
	}
}

func TestRecordProducerConsumerBindingAndBindingsForSequence(t *testing.T) {
	f := &Fuzzer{}
	if got := f.bindingsForSequence(""); got != nil {
		t.Errorf("expected nil for an empty sequence id, got %v", got)
	}
	if got := f.bindingsForSequence("seq-1"); got != nil {
		t.Errorf("expected nil for a sequence with no recorded bindings, got %v", got)
	}

	f.recordProducerConsumerBinding(ProducerConsumerBinding{SequenceID: "seq-1", Value: "a"})
	f.recordProducerConsumerBinding(ProducerConsumerBinding{SequenceID: "seq-2", Value: "b"})
	f.recordProducerConsumerBinding(ProducerConsumerBinding{SequenceID: "seq-1", Value: "c"})

	got := f.bindingsForSequence("seq-1")
	if len(got) != 2 || got[0].Value != "a" || got[1].Value != "c" {
		t.Errorf("expected [a,c] in recording order for seq-1, got %v", got)
	}
}

func TestRecordProducerConsumerBindingRingBounded(t *testing.T) {
	f := &Fuzzer{}
	for i := 0; i < maxProducerConsumerBindings+5; i++ {
		f.recordProducerConsumerBinding(ProducerConsumerBinding{SequenceID: "seq-1"})
	}
	if len(f.producerConsumerBindings) != maxProducerConsumerBindings {
		t.Errorf("expected bindings capped at %d, got %d", maxProducerConsumerBindings, len(f.producerConsumerBindings))
	}
}

func TestWorkflowFilePaths(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{TimelineDir: "/tmp/run1/timeline"}}
	jsonPath, shPath := f.workflowFilePaths(2, "seq-abc")
	if filepath.Base(jsonPath) != "workflow_d3_seq-abc.json" {
		t.Errorf("unexpected json path %q", jsonPath)
	}
	if filepath.Base(shPath) != "workflow_d3_seq-abc.sh" {
		t.Errorf("unexpected sh path %q", shPath)
	}
	if filepath.Dir(jsonPath) != filepath.Dir(shPath) {
		t.Errorf("expected json and sh paths to share a directory")
	}
}

func TestPersistWorkflow_NoTimelineDirIsNoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{}}
	// Must not panic and must not create anything when TimelineDir is unset.
	f.persistWorkflow(&SequenceState{ID: "seq-1", History: []SequenceStep{{Method: "GET", Path: "/x", Status: 200}}})
}

func TestPersistWorkflow_WritesJSONAndShellFiles(t *testing.T) {
	dir := t.TempDir()
	f := &Fuzzer{cfg: config.Config{TimelineDir: filepath.Join(dir, "run", "timeline")}, target: "http://example.test"}
	state := &SequenceState{
		ID:     "seq-write",
		Depth:  1,
		Energy: 3,
		History: []SequenceStep{
			{Method: "POST", Path: "/widgets", Status: 201, Body: `{"a":1}`, Headers: map[string]string{"X-Test": "v"}},
			{Method: "GET", Path: "/widgets/1", Status: 200},
		},
	}
	f.persistWorkflow(state)

	jsonPath, shPath := f.workflowFilePaths(state.Depth, state.ID)
	if _, err := os.Stat(jsonPath); err != nil {
		t.Errorf("expected the workflow JSON file to exist: %v", err)
	}
	shInfo, err := os.Stat(shPath)
	if err != nil {
		t.Fatalf("expected the workflow shell script to exist: %v", err)
	}
	if shInfo.Mode()&0o100 == 0 {
		t.Error("expected the workflow shell script to be executable")
	}
}

func TestSequenceHasRealIDChain(t *testing.T) {
	const uuid = "11111111-1111-4111-8111-111111111111"
	f := &Fuzzer{resourceGraph: newResourceGraph(ResourceGraphLimits{})}
	state := &SequenceState{
		ID: "seq-1",
		History: []SequenceStep{
			{Method: "POST", Path: "/widgets", Status: 201},
			{Method: "GET", Path: "/widgets/" + uuid, Status: 200},
		},
	}
	if f.sequenceHasRealIDChain(state) {
		t.Error("expected false when the resource graph has no recorded instances for this sequence")
	}

	id := ResourceIdentity{ResourceType: "widget", IdentityKind: "uuid", RawValue: uuid}
	f.resourceGraph.recordInstance(id, "POST /widgets", "seq-1", LifecycleCreated, 0.9, RecordInstanceOpts{})
	if !f.sequenceHasRealIDChain(state) {
		t.Error("expected true once a UUID-shaped instance produced by this sequence reappears in a later step")
	}
}

func TestFindFollowups_StaticPriorityOrdering(t *testing.T) {
	f := &Fuzzer{
		depConsumers: map[string][]int{},
		idConsumers:  map[string][]int{},
		activeIDs:    []int{1, 2, 3},
		meta: map[int]TemplateMeta{
			1: {Method: "POST", Norm: "/widgets"},
			2: {Method: "DELETE", Norm: "/widgets/{id}"},
			3: {Method: "GET", Norm: "/widgets/{id}"},
		},
		blockedEndpoints: map[string]struct{}{},
		tmplEPKey:        map[int]string{},
		cfg:              config.Config{ResourceGraphEnabled: false},
	}
	got := f.findFollowups(1, "POST", "/widgets", nil, nil, "")
	if len(got) != 2 {
		t.Fatalf("expected 2 same-family followups, got %v", got)
	}
	// GET should be prioritized ahead of DELETE after a POST (see followupPriority).
	if got[0] != 3 {
		t.Errorf("expected the GET follow-up (template 3) first, got order %v", got)
	}
}

func TestFindFollowups_ExcludesBlockedAndSelf(t *testing.T) {
	f := &Fuzzer{
		depConsumers:     map[string][]int{"orderId": {5, 1}},
		idConsumers:      map[string][]int{},
		activeIDs:        []int{1, 5},
		meta:             map[int]TemplateMeta{1: {Method: "POST", Norm: "/orders"}, 5: {Method: "GET", Norm: "/orders/{id}"}},
		blockedEndpoints: map[string]struct{}{},
		tmplEPKey:        map[int]string{},
		cfg:              config.Config{ResourceGraphEnabled: false},
	}
	got := f.findFollowups(1, "POST", "/orders", []string{"orderId"}, nil, "")
	if len(got) != 1 || got[0] != 5 {
		t.Fatalf("expected only template 5 (self excluded from its own producedDeps match), got %v", got)
	}
}

func TestEnqueueCrashReplay_BlockedTemplateIsNoOp(t *testing.T) {
	f := &Fuzzer{blockedEndpoints: map[string]struct{}{endpointKey("GET", normalizeEndpointPath("/x")): {}}, tmplEPKey: map[int]string{1: endpointKey("GET", normalizeEndpointPath("/x"))}}
	f.enqueueCrashReplay(WorkItem{TemplateID: 1, Method: "GET", Path: "/x"}, 3)
	if len(f.replayQueue) != 0 {
		t.Errorf("expected no replay items queued for a blocked template, got %d", len(f.replayQueue))
	}
}

func TestEnqueueCrashReplay_ZeroOrNegativeCountIsNoOp(t *testing.T) {
	f := &Fuzzer{blockedEndpoints: map[string]struct{}{}, tmplEPKey: map[int]string{}}
	f.enqueueCrashReplay(WorkItem{TemplateID: 1}, 0)
	if len(f.replayQueue) != 0 {
		t.Errorf("expected no replay items queued for n<=0, got %d", len(f.replayQueue))
	}
}

func TestEnqueueCrashReplay_RenderFailureFallsBackToReplayingOriginalItem(t *testing.T) {
	f := &Fuzzer{
		blockedEndpoints: map[string]struct{}{},
		tmplEPKey:        map[int]string{},
		replayByEndpoint: map[string]int{},
		tmplByID:         map[int]*Template{}, // no template registered -> renderTemplate must fail
		cfg:              config.Config{CrashReplayQueueMax: 10},
	}
	item := WorkItem{TemplateID: 99, Method: "GET", Path: "/missing"}
	f.enqueueCrashReplay(item, 2)
	if len(f.replayQueue) != 2 {
		t.Fatalf("expected 2 fallback-replayed items, got %d", len(f.replayQueue))
	}
	for _, q := range f.replayQueue {
		if q.MutationName != "crash_replay" {
			t.Errorf("expected MutationName=crash_replay on the fallback item, got %q", q.MutationName)
		}
	}
}
