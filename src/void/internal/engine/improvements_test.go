package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"void/internal/config"
)

// improvements_test.go covers the 5 fixes from docs/resource-state-graph-report.md's
// "what needs and can be improved" pass: (1) dedup prefers real-ID provenance,
// (2) value substitution biased toward resource-graph values, (3) lowered
// persistence bar for genuine real-ID chains, (4) crash-to-sequence linkage,
// (5) counters for why sequences stop extending.

// testGUID is a syntactically valid UUID (version nibble 4, variant nibble a)
// matching reUUIDLike, used throughout as a stand-in for a real extracted
// resource identity.
const testGUID = "550e8400-e29b-41d4-a716-446655440000"

// otherGUID is a second, distinct valid UUID used as a path value that is
// GUID-*shaped* but has no corresponding resource-graph instance recorded --
// i.e. it produces the same workflow shape signature as testGUID (both
// normalize to the "{uuid}" path-segment token) without being a genuine
// real-ID chain.
const otherGUID = "11111111-1111-4111-8111-111111111111"

func newImprovementsTestFuzzer(t *testing.T, timelineDir string) *Fuzzer {
	t.Helper()
	return &Fuzzer{
		depIndex:                   map[int]DepInfo{},
		meta:                       map[int]TemplateMeta{},
		tmplByID:                   map[int]*Template{},
		tmplEPKey:                  map[int]string{},
		depConsumers:               map[string][]int{},
		idConsumers:                map[string][]int{},
		blockedEndpoints:           map[string]struct{}{},
		endpointStats:              map[string]*EndpointStats{},
		seenStateSigs:              map[string]struct{}{},
		persistedWorkflowExemplars: map[string]persistedExemplar{},
		crashesBySequence:          map[string][]string{},
		resourceGraph:              newResourceGraph(ResourceGraphLimits{}),
		runtime:                    newRuntimeStore(),
		dict:                       &DictStore{},
		cfg: config.Config{
			SequenceMaxDepth:     3,
			ResourceGraphEnabled: true,
			TimelineDir:          timelineDir,
		},
	}
}

// mkChainState builds a SequenceState with a genuine real-ID chain recorded in
// f's resource graph under seqID: a GET response reveals testGUID (recorded
// as a "widget" instance), and a later PUT step's path reuses it verbatim --
// exactly the producer(response)->consumer(later request) pattern
// sequenceHasRealIDChain (sequence.go) detects.
func mkChainState(f *Fuzzer, seqID string, depth int) *SequenceState {
	f.resourceGraph.recordInstance(
		ResourceIdentity{
			ResourceType:    "widget",
			IdentityKind:    "scalar",
			NormalizedValue: normalizeResourceValue("widget", "scalar", testGUID),
			RawValue:        testGUID,
			SourcePath:      "$.id",
			Confidence:      0.9,
		},
		"GET /widgets", seqID, LifecycleReadable, 0.9,
	)
	hist := []SequenceStep{
		{Method: "GET", Path: "/widgets", Status: 200},
		{Method: "PUT", Path: "/widgets/" + testGUID, Status: 200},
	}
	if depth >= 2 {
		hist = append(hist, SequenceStep{Method: "GET", Path: "/widgets/" + testGUID, Status: 200})
	}
	return &SequenceState{ID: seqID, Depth: depth, Energy: 3, History: hist}
}

// ---------------------------------------------------------------------------
// Item #3: lowered persistence bar for genuine real-ID chains
// ---------------------------------------------------------------------------

func TestMaybePersistSequence_ShallowRealIDChainBypassesDepthGate(t *testing.T) {
	dir := t.TempDir()
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))
	state := mkChainState(f, "seq-shallow", 1) // depth=1: only 2 steps, fails the old depth>=2 gate

	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: state}})

	if f.workflowsPersisted != 1 {
		t.Fatalf("expected a shallow (depth=1) sequence with a genuine real-ID chain to be persisted, workflowsPersisted=%d", f.workflowsPersisted)
	}
	jsonPath, _ := f.workflowFilePaths(state.Depth, state.ID)
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected workflow file %s to exist: %v", jsonPath, err)
	}
}

func TestMaybePersistSequence_ShallowSequenceWithoutRealIDChainStaysGated(t *testing.T) {
	dir := t.TempDir()
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))
	state := &SequenceState{
		ID: "seq-shallow-plain", Depth: 1, Energy: 3,
		History: []SequenceStep{
			{Method: "GET", Path: "/widgets", Status: 200},
			{Method: "GET", Path: "/other", Status: 200},
		},
	}

	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: state}})

	if f.workflowsPersisted != 0 {
		t.Fatalf("expected a shallow sequence with no real-ID chain to remain gated by depth, workflowsPersisted=%d", f.workflowsPersisted)
	}
}

func TestMaybePersistSequence_DepthZeroNeverBypassesGate(t *testing.T) {
	// A single-step (depth=0) "sequence" structurally cannot contain a
	// producer->consumer chain -- sequenceHasRealIDChain must not even be
	// invoked (it would find nothing meaningful), and persistence must stay
	// gated exactly as before.
	dir := t.TempDir()
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))
	state := &SequenceState{
		ID: "seq-depth0", Depth: 0, Energy: 3,
		History: []SequenceStep{{Method: "GET", Path: "/widgets", Status: 200}},
	}

	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: state}})

	if f.workflowsPersisted != 0 {
		t.Fatalf("expected depth=0 to stay gated, workflowsPersisted=%d", f.workflowsPersisted)
	}
}

// ---------------------------------------------------------------------------
// Item #1: dedup prefers real-ID provenance
// ---------------------------------------------------------------------------

func TestMaybePersistSequence_DedupUpgradesToRealIDChainExemplar(t *testing.T) {
	dir := t.TempDir()
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))

	// First: a full-depth sequence reaching shape "GET 2xx|PUT 2xx|GET 2xx"
	// via otherGUID (GUID-*shaped* but with no resource-graph data recorded
	// for this seqID) -- a weaker, placeholder-quality exemplar.
	plain := &SequenceState{
		ID: "seq-plain", Depth: 2, Energy: 3,
		History: []SequenceStep{
			{Method: "GET", Path: "/widgets", Status: 200},
			{Method: "PUT", Path: "/widgets/" + otherGUID, Status: 200},
			{Method: "GET", Path: "/widgets/" + otherGUID, Status: 200},
		},
	}
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: plain}})
	if f.workflowsPersisted != 1 {
		t.Fatalf("expected the first (plain) exemplar to be persisted, workflowsPersisted=%d", f.workflowsPersisted)
	}
	plainJSON, _ := f.workflowFilePaths(plain.Depth, plain.ID)
	if _, err := os.Stat(plainJSON); err != nil {
		t.Fatalf("expected plain exemplar file to exist: %v", err)
	}

	// Second: a DIFFERENT sequence reaching the exact same shape, but backed
	// by a genuine real-ID chain (testGUID, recorded in the resource graph).
	chained := mkChainState(f, "seq-chained", 2)
	if sequenceStateSignature(plain) != sequenceStateSignature(chained) {
		t.Fatalf("test setup bug: plain and chained states must share a shape signature, got %q vs %q",
			sequenceStateSignature(plain), sequenceStateSignature(chained))
	}
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: chained}})

	if f.workflowsPersisted != 1 {
		t.Fatalf("expected workflowsPersisted to stay at 1 (still one exemplar per shape), got %d", f.workflowsPersisted)
	}
	if f.dedupDuplicateRejected != 1 {
		t.Fatalf("expected dedupDuplicateRejected=1, got %d", f.dedupDuplicateRejected)
	}
	if f.dedupRealIDChainRejected != 1 {
		t.Fatalf("expected dedupRealIDChainRejected=1, got %d", f.dedupRealIDChainRejected)
	}
	if f.dedupRealIDChainUpgrades != 1 {
		t.Fatalf("expected dedupRealIDChainUpgrades=1, got %d", f.dedupRealIDChainUpgrades)
	}
	if _, err := os.Stat(plainJSON); !os.IsNotExist(err) {
		t.Fatalf("expected the old plain exemplar file to have been removed, stat err=%v", err)
	}
	chainedJSON, _ := f.workflowFilePaths(chained.Depth, chained.ID)
	if _, err := os.Stat(chainedJSON); err != nil {
		t.Fatalf("expected the upgraded (real-ID chain) exemplar file to exist: %v", err)
	}
}

func TestMaybePersistSequence_DedupDoesNotDowngradeExistingRealIDExemplar(t *testing.T) {
	dir := t.TempDir()
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))

	first := mkChainState(f, "seq-chain-a", 2)
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: first}})
	if f.workflowsPersisted != 1 {
		t.Fatalf("expected first real-ID exemplar to persist, got %d", f.workflowsPersisted)
	}
	firstJSON, _ := f.workflowFilePaths(first.Depth, first.ID)

	// Second sequence: same shape, ALSO a genuine real-ID chain (different
	// sequence ID; testGUID re-recorded in the graph under the new seqID).
	second := mkChainState(f, "seq-chain-b", 2)
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: second}})

	if f.workflowsPersisted != 1 {
		t.Fatalf("expected workflowsPersisted to stay at 1, got %d", f.workflowsPersisted)
	}
	if f.dedupRealIDChainUpgrades != 0 {
		t.Fatalf("expected NO upgrade when the existing exemplar already has real-ID provenance, got %d", f.dedupRealIDChainUpgrades)
	}
	if _, err := os.Stat(firstJSON); err != nil {
		t.Fatalf("expected the original real-ID exemplar file to remain untouched: %v", err)
	}
}

func TestMaybePersistSequence_DedupWithoutRealIDChainNeitherSideIsRejectedTwice(t *testing.T) {
	// Two plain (non-chain) sequences reaching the same shape: ordinary dedup
	// behavior (only dedupDuplicateRejected increments) must be unaffected by
	// the new upgrade logic.
	dir := t.TempDir()
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))
	mk := func(id string) *SequenceState {
		return &SequenceState{
			ID: id, Depth: 2, Energy: 3,
			History: []SequenceStep{
				{Method: "GET", Path: "/orders", Status: 200},
				{Method: "PUT", Path: "/orders/1", Status: 200},
				{Method: "GET", Path: "/orders/1", Status: 200},
			},
		}
	}
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: mk("seq-a")}})
	f.maybePersistSequence(SendResult{Item: WorkItem{SeqState: mk("seq-b")}})

	if f.workflowsPersisted != 1 {
		t.Fatalf("expected workflowsPersisted=1, got %d", f.workflowsPersisted)
	}
	if f.dedupDuplicateRejected != 1 {
		t.Fatalf("expected dedupDuplicateRejected=1, got %d", f.dedupDuplicateRejected)
	}
	if f.dedupRealIDChainRejected != 0 || f.dedupRealIDChainUpgrades != 0 {
		t.Fatalf("expected no real-ID-chain counters to move for two plain sequences, got rejected=%d upgrades=%d",
			f.dedupRealIDChainRejected, f.dedupRealIDChainUpgrades)
	}
}

// ---------------------------------------------------------------------------
// Item #2a: prefer resource-graph values over entityIDs[0] for path substitution
// ---------------------------------------------------------------------------

func TestPickFollowupPathValue_PrefersGraphValueOverEntityIDs(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{
			ResourceType: "widget", IdentityKind: "scalar",
			NormalizedValue: normalizeResourceValue("widget", "scalar", testGUID),
			RawValue:        testGUID,
		},
		"GET /widgets", "seq-x", LifecycleReadable, 0.9,
	)

	value, fromGraph, ok, _ := f.pickFollowupPathValue(1, []string{"999"}, "")

	if !ok {
		t.Fatal("expected ok=true")
	}
	if !fromGraph {
		t.Fatal("expected fromGraph=true: a compatible resource-graph instance exists and must win over entityIDs[0]")
	}
	if value != testGUID {
		t.Fatalf("expected the graph-tracked value %q, got %q", testGUID, value)
	}
}

func TestPickFollowupPathValue_FallsBackToEntityIDsWhenGraphHasNothing(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	// No resource-graph instance of type "order" recorded at all.

	value, fromGraph, ok, _ := f.pickFollowupPathValue(1, []string{"999"}, "")

	if !ok || fromGraph || value != "999" {
		t.Fatalf("expected fallback to entityIDs[0]=%q, got value=%q fromGraph=%v ok=%v", "999", value, fromGraph, ok)
	}
}

func TestPickFollowupPathValue_ResourceGraphDisabledAlwaysUsesEntityIDs(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphEnabled = false
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", testGUID), RawValue: testGUID},
		"GET /widgets", "seq-x", LifecycleReadable, 0.9,
	)

	value, fromGraph, ok, _ := f.pickFollowupPathValue(1, []string{"999"}, "")

	if !ok || fromGraph || value != "999" {
		t.Fatalf("expected -resource-graph=false to reproduce the old entityIDs[0]-only behavior exactly, got value=%q fromGraph=%v ok=%v", value, fromGraph, ok)
	}
}

func TestPickFollowupPathValue_TenantScopeRestrictsGraphPick(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/projects/{param}"}
	orgA, prjA := projectInTenant(f.resourceGraph, "org-a", "prj-a")
	_, prjB := projectInTenant(f.resourceGraph, "org-b", "prj-b")

	// Scoped to org-a's tenant: must return org-a's project, never org-b's,
	// even though org-b's project is a perfectly valid "project" instance in
	// the graph -- this is the mechanism that keeps the VALID workflow
	// planner from ever crossing tenants by accident.
	value, fromGraph, ok, _ := f.pickFollowupPathValue(1, nil, orgA.Canonical.graphKey())
	if !ok || !fromGraph {
		t.Fatalf("expected a tenant-scoped graph hit, got ok=%v fromGraph=%v", ok, fromGraph)
	}
	if value != prjA.Canonical.RawValue {
		t.Fatalf("expected org-a's project (%s), got %q", prjA.Canonical.RawValue, value)
	}
	if value == prjB.Canonical.RawValue {
		t.Fatal("expected org-b's project to never be picked when scoped to org-a's tenant")
	}

	// No tenant scope established yet (empty string): either project is a
	// valid pick -- the pre-existing, unrestricted behavior for flat/shallow
	// chains.
	value2, _, ok2, _ := f.pickFollowupPathValue(1, nil, "")
	if !ok2 || (value2 != prjA.Canonical.RawValue && value2 != prjB.Canonical.RawValue) {
		t.Fatalf("expected an unscoped pick to return either project, got %q ok=%v", value2, ok2)
	}
}

func TestPickFollowupPathValue_NothingAvailable(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}

	_, _, ok, _ := f.pickFollowupPathValue(1, nil, "")

	if ok {
		t.Fatal("expected ok=false when neither the graph nor entityIDs has anything")
	}
}

// ---------------------------------------------------------------------------
// Producer->consumer binding records (ProducerConsumerBinding, sequence.go)
// ---------------------------------------------------------------------------

func TestPickFollowupPathValue_ReturnsInstanceOnlyWhenFromGraph(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{
			ResourceType: "widget", IdentityKind: "scalar",
			NormalizedValue: normalizeResourceValue("widget", "scalar", testGUID),
			RawValue:        testGUID, SourcePath: "$.id",
		},
		"GET /widgets", "seq-x", LifecycleReadable, 0.9,
	)

	value, fromGraph, ok, inst := f.pickFollowupPathValue(1, []string{"999"}, "")
	if !ok || !fromGraph {
		t.Fatalf("expected a graph hit, got ok=%v fromGraph=%v", ok, fromGraph)
	}
	if inst == nil {
		t.Fatal("expected a non-nil instance when fromGraph=true, so the caller can build a ProducerConsumerBinding")
	}
	if inst.Canonical.RawValue != value {
		t.Fatalf("expected the returned instance's own value to match the returned value, inst=%q value=%q", inst.Canonical.RawValue, value)
	}
	if inst.SourceOperation != "GET /widgets" {
		t.Fatalf("expected the instance's SourceOperation to be the producer op, got %q", inst.SourceOperation)
	}

	// Fallback path (entityIDs, not the graph): inst must be nil.
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	_, fromGraph2, ok2, inst2 := f.pickFollowupPathValue(2, []string{"999"}, "")
	if !ok2 || fromGraph2 {
		t.Fatalf("expected the entityIDs fallback, got ok=%v fromGraph=%v", ok2, fromGraph2)
	}
	if inst2 != nil {
		t.Fatalf("expected a nil instance for the entityIDs fallback path, got %+v", inst2)
	}
}

func TestRecordProducerConsumerBinding_MonotonicOrder(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.recordProducerConsumerBinding(ProducerConsumerBinding{ProducerOp: "POST /orders", ConsumerOp: "GET /orders/{id}", ConsumerField: "path", Value: "1"})
	f.recordProducerConsumerBinding(ProducerConsumerBinding{ProducerOp: "POST /orders", ConsumerOp: "PUT /orders/{id}", ConsumerField: "path", Value: "1"})
	if len(f.producerConsumerBindings) != 2 {
		t.Fatalf("expected 2 recorded bindings, got %d", len(f.producerConsumerBindings))
	}
	if f.producerConsumerBindings[0].Order >= f.producerConsumerBindings[1].Order {
		t.Fatalf("expected strictly increasing Order, got %d then %d", f.producerConsumerBindings[0].Order, f.producerConsumerBindings[1].Order)
	}
}

func TestRecordProducerConsumerBinding_BoundedRingBuffer(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	for i := 0; i < maxProducerConsumerBindings+50; i++ {
		f.recordProducerConsumerBinding(ProducerConsumerBinding{ProducerOp: "POST /x", ConsumerOp: "GET /x/{id}", ConsumerField: "path", Value: "v"})
	}
	if len(f.producerConsumerBindings) != maxProducerConsumerBindings {
		t.Fatalf("expected the binding log bounded at %d, got %d", maxProducerConsumerBindings, len(f.producerConsumerBindings))
	}
	// The oldest entries must have been dropped -- the last-recorded binding's
	// Order must be the highest, and the first-kept entry's Order must reflect
	// that the earliest 50 were evicted.
	last := f.producerConsumerBindings[len(f.producerConsumerBindings)-1]
	first := f.producerConsumerBindings[0]
	if last.Order != uint64(maxProducerConsumerBindings+50) {
		t.Fatalf("expected the last binding's Order to be %d, got %d", maxProducerConsumerBindings+50, last.Order)
	}
	if first.Order != 51 {
		t.Fatalf("expected the oldest 50 bindings to be evicted (first kept Order=51), got %d", first.Order)
	}
}

// ---------------------------------------------------------------------------
// Item #2b: bias body/query candidate pool toward resource-graph values
// ---------------------------------------------------------------------------

// countOccurrences returns how many times want appears in items. Used instead
// of comparing pool lengths against a separately-fetched "base" call, since
// customPayloadCandidates includes math/rand-driven business-ID mutation
// (mutateBusinessID) -- two separate invocations of it can legitimately
// return different-length results, making any base-vs-biased length
// comparison across two calls inherently flaky. Counting occurrences of a
// specific, fixed, never-otherwise-generated value (a hardcoded test UUID) is
// deterministic regardless of that unrelated randomness.
func countOccurrences(items []string, want string) int {
	n := 0
	for _, c := range items {
		if c == want {
			n++
		}
	}
	return n
}

func TestGraphBiasedPayloadCandidates_AddsWeightedGraphValues(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphValueBiasWeight = 3
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "cipher", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("cipher", "scalar", testGUID), RawValue: testGUID},
		"GET /ciphers", "seq-x", LifecycleReadable, 0.9,
	)

	biased := f.graphBiasedPayloadCandidates("cipherId")

	if count := countOccurrences(biased, testGUID); count != 3 {
		t.Fatalf("expected testGUID to appear exactly 3 times (bias weight) in the biased pool, got %d in %v", count, biased)
	}
}

func TestGraphBiasedPayloadCandidates_ZeroWeightDisablesBias(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphValueBiasWeight = 0
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "cipher", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("cipher", "scalar", testGUID), RawValue: testGUID},
		"GET /ciphers", "seq-x", LifecycleReadable, 0.9,
	)

	biased := f.graphBiasedPayloadCandidates("cipherId")

	if count := countOccurrences(biased, testGUID); count != 0 {
		t.Fatalf("expected weight=0 to add zero copies of the graph value, got %d in %v", count, biased)
	}
}

func TestGraphBiasedPayloadCandidates_BoundedToFiveInstances(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphValueBiasWeight = 1
	guids := []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		"44444444-4444-4444-8444-444444444444",
		"55555555-5555-4555-8555-555555555555",
		"66666666-6666-4666-8666-666666666666",
		"77777777-7777-4777-8777-777777777777",
	}
	for _, g := range guids {
		f.resourceGraph.recordInstance(
			ResourceIdentity{ResourceType: "cipher", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("cipher", "scalar", g), RawValue: g},
			"GET /ciphers", "seq-x", LifecycleReadable, 0.9,
		)
	}

	biased := f.graphBiasedPayloadCandidates("cipherId")

	present := 0
	for _, g := range guids {
		if countOccurrences(biased, g) == 1 {
			present++
		}
	}
	if present != 5 {
		t.Fatalf("expected exactly 5 of the 7 recorded instances to be considered (bounded), got %d present in %v", present, biased)
	}
}

func TestGraphBiasedPayloadCandidates_NonIDFieldUnaffected(t *testing.T) {
	// A field name that doesn't map to any resource type (resourceTypeFromKeyName
	// returns "") must be completely unaffected by the bias, even with graph data present.
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphValueBiasWeight = 3
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "cipher", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("cipher", "scalar", testGUID), RawValue: testGUID},
		"GET /ciphers", "seq-x", LifecycleReadable, 0.9,
	)

	biased := f.graphBiasedPayloadCandidates("description")

	if count := countOccurrences(biased, testGUID); count != 0 {
		t.Fatalf("expected a non-resource-typed field to be completely unaffected by the bias, got %d occurrences in %v", count, biased)
	}
}

// ---------------------------------------------------------------------------
// Item #5: counters for why sequences stop extending
// ---------------------------------------------------------------------------

func TestSeqStopCounters_MaxDepth(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphEnabled = false
	f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, SeqDepth: 3},
		Status: 200,
	})
	if f.seqStopMaxDepth != 1 {
		t.Fatalf("expected seqStopMaxDepth=1, got %d", f.seqStopMaxDepth)
	}
	if f.seqStopFailedStep != 0 || f.seqStopNoProducedValue != 0 || f.seqStopNoFollowupCandidate != 0 || f.seqStopRenderFailed != 0 {
		t.Fatalf("expected only seqStopMaxDepth to move, got %+v", []int{f.seqStopFailedStep, f.seqStopNoProducedValue, f.seqStopNoFollowupCandidate, f.seqStopRenderFailed})
	}
}

func TestSeqStopCounters_FailedStep(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphEnabled = false
	f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "GET", Path: "/widgets/1", SeqDepth: 0},
		Status: 500,
	})
	if f.seqStopFailedStep != 1 {
		t.Fatalf("expected seqStopFailedStep=1, got %d", f.seqStopFailedStep)
	}
	if f.seqStopMaxDepth != 0 || f.seqStopNoProducedValue != 0 || f.seqStopNoFollowupCandidate != 0 || f.seqStopRenderFailed != 0 {
		t.Fatalf("expected only seqStopFailedStep to move")
	}
}

func TestSeqStopCounters_NoProducedValue(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphEnabled = false
	// GET method (not POST/PUT/PATCH), empty body -> no entityIDs, no
	// producedDeps (depIndex has no entry for TemplateID=1) -> hits the
	// "non-mutating method with nothing chainable" branch directly.
	f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "GET", Path: "/widgets/1", SeqDepth: 0},
		Status: 200,
		Body:   "",
	})
	if f.seqStopNoProducedValue != 1 {
		t.Fatalf("expected seqStopNoProducedValue=1, got %d", f.seqStopNoProducedValue)
	}
	if f.seqStopMaxDepth != 0 || f.seqStopFailedStep != 0 || f.seqStopNoFollowupCandidate != 0 || f.seqStopRenderFailed != 0 {
		t.Fatalf("expected only seqStopNoProducedValue to move")
	}
}

func TestSeqStopCounters_NoFollowupCandidate(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphEnabled = false
	// The "no produced value" branch checks the TEMPLATE's own registered
	// method (f.meta[tid].Method), not the request's own WorkItem.Method --
	// register it as POST so that branch is bypassed regardless of
	// producedDeps/entityIDs; with depConsumers/idConsumers/activeIDs all
	// empty, findFollowups then has nothing to return.
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/widgets"}
	f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "POST", Path: "/widgets", SeqDepth: 0},
		Status: 200,
		Body:   "",
	})
	if f.seqStopNoFollowupCandidate != 1 {
		t.Fatalf("expected seqStopNoFollowupCandidate=1, got %d", f.seqStopNoFollowupCandidate)
	}
	if f.seqStopMaxDepth != 0 || f.seqStopFailedStep != 0 || f.seqStopNoProducedValue != 0 || f.seqStopRenderFailed != 0 {
		t.Fatalf("expected only seqStopNoFollowupCandidate to move")
	}
}

func TestSeqStopCounters_RenderFailed(t *testing.T) {
	f := newImprovementsTestFuzzer(t, "")
	f.cfg.ResourceGraphEnabled = false
	// tid=999 is "sameFamily" (same normalized path) as the source but a
	// different method, so findFollowups includes it -- yet f.tmplByID has no
	// entry for it, so renderTemplateContext fails for every candidate.
	// tid=1 itself must be registered as POST so the "no produced value"
	// branch is bypassed (see TestSeqStopCounters_NoFollowupCandidate).
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/widgets"}
	f.activeIDs = []int{999}
	f.meta[999] = TemplateMeta{Method: "GET", Norm: "/widgets"}
	f.enqueueSequenceFollowups(SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "POST", Path: "/widgets", SeqDepth: 0},
		Status: 200,
		Body:   "",
	})
	if f.seqStopRenderFailed != 1 {
		t.Fatalf("expected seqStopRenderFailed=1, got %d", f.seqStopRenderFailed)
	}
	if f.seqStopMaxDepth != 0 || f.seqStopFailedStep != 0 || f.seqStopNoProducedValue != 0 || f.seqStopNoFollowupCandidate != 0 {
		t.Fatalf("expected only seqStopRenderFailed to move")
	}
}

// ---------------------------------------------------------------------------
// Item #4: crash-to-sequence linkage (see also crash_test.go)
// ---------------------------------------------------------------------------

func TestLogSequenceEvent_PopulatesProducedBugIDFromLinkedCrash(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "sequence_event.jsonl")
	w, err := NewJSONLWriter(eventPath)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))
	f.sequenceEventWriter = w
	f.crashesBySequence = map[string][]string{
		"seq-with-bug": {"cluster-abc123"},
	}
	state := &SequenceState{
		ID: "seq-with-bug", Depth: 1,
		History: []SequenceStep{
			{Method: "GET", Path: "/widgets", Status: 200},
			{Method: "PUT", Path: "/widgets/1", Status: 500},
		},
	}

	f.logSequenceEvent(state, false)
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	buf, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(buf), `"produced_bug_id":"cluster-abc123"`) {
		t.Fatalf("expected produced_bug_id to be populated from crashesBySequence, got: %s", string(buf))
	}
}

func TestLogSequenceEvent_ProducedBugIDEmptyWhenNoCrashLinked(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "sequence_event.jsonl")
	w, err := NewJSONLWriter(eventPath)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	f := newImprovementsTestFuzzer(t, filepath.Join(dir, "timelines"))
	f.sequenceEventWriter = w
	state := &SequenceState{
		ID: "seq-clean", Depth: 1,
		History: []SequenceStep{
			{Method: "GET", Path: "/widgets", Status: 200},
			{Method: "GET", Path: "/widgets/1", Status: 200},
		},
	}

	f.logSequenceEvent(state, true)
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	buf, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(buf), `"produced_bug_id":""`) {
		t.Fatalf("expected produced_bug_id to be empty for a sequence with no linked crash, got: %s", string(buf))
	}
}
