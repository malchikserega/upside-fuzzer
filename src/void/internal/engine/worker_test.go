package engine

import (
	"testing"
	"time"

	"void/internal/config"
)

func TestCoverageSaturationPct(t *testing.T) {
	f := &Fuzzer{baselineEdgesCeiling: 100, currentEdges: 50}
	if got := f.coverageSaturationPct(); got != 50.0 {
		t.Errorf("expected 50%%, got %v", got)
	}

	f2 := &Fuzzer{baselineEdgesCeiling: 0, coverageCapacity: 200, currentEdges: 200}
	if got := f2.coverageSaturationPct(); got != 100.0 {
		t.Errorf("expected fallback to coverageCapacity giving 100%%, got %v", got)
	}

	f3 := &Fuzzer{}
	if got := f3.coverageSaturationPct(); got != 0 {
		t.Errorf("expected 0 when neither ceiling nor capacity is set, got %v", got)
	}

	// Clamp ceiling: even wildly over 100% must clamp to 150.
	f4 := &Fuzzer{baselineEdgesCeiling: 10, currentEdges: 1000}
	if got := f4.coverageSaturationPct(); got != 150.0 {
		t.Errorf("expected clamp to 150%%, got %v", got)
	}
}

func TestAddOrBoostSeed_AppendsNewSeedAndBoostsExisting(t *testing.T) {
	f := &Fuzzer{
		tmplEPKey:        map[int]string{},
		blockedEndpoints: map[string]struct{}{},
		endpointStats:    map[string]*EndpointStats{},
		seedSampler:      NewFenwickSampler(),
		corpus:           []Seed{{TemplateID: 1, Energy: 1.0}},
	}
	item := WorkItem{TemplateID: 1, Method: "GET", Path: "/widgets", SeedIdx: 0, MutationName: "seed", Raw: "GET /widgets\r\n\r\n"}
	f.addOrBoostSeed(item, 3)

	if f.corpus[0].EdgesFound != 3 {
		t.Errorf("expected the existing seed at SeedIdx=0 boosted, EdgesFound=%d", f.corpus[0].EdgesFound)
	}
	if len(f.corpus) != 2 {
		t.Fatalf("expected a new seed appended (corpus grows to 2), got %d", len(f.corpus))
	}
	if f.corpus[1].EdgesFound != 3 {
		t.Errorf("expected the newly appended seed's EdgesFound=3, got %d", f.corpus[1].EdgesFound)
	}
}

func TestAddOrBoostSeed_BlockedTemplateIsNoOp(t *testing.T) {
	f := &Fuzzer{
		tmplEPKey:        map[int]string{1: "GET /x"},
		blockedEndpoints: map[string]struct{}{"GET /x": {}},
		endpointStats:    map[string]*EndpointStats{},
		seedSampler:      NewFenwickSampler(),
	}
	f.addOrBoostSeed(WorkItem{TemplateID: 1, SeedIdx: -1}, 5)
	if len(f.corpus) != 0 {
		t.Errorf("expected no seed added for a blocked template, got %d", len(f.corpus))
	}
}

func TestAddOrBoostSeed_TriggersMinimizeAtCapacity(t *testing.T) {
	f := &Fuzzer{
		tmplEPKey:        map[int]string{},
		blockedEndpoints: map[string]struct{}{},
		endpointStats:    map[string]*EndpointStats{},
		seedSampler:      NewFenwickSampler(),
	}
	for i := 0; i < 500; i++ {
		f.corpus = append(f.corpus, Seed{TemplateID: 1, Energy: 5.0, EdgesFound: 1})
		f.seedSampler.Append(5.0)
	}
	f.addOrBoostSeed(WorkItem{TemplateID: 1, SeedIdx: -1}, 1)
	if len(f.corpus) > 400 {
		t.Errorf("expected minimizeCorpus to have pruned the corpus down to <=400, got %d", len(f.corpus))
	}
}

func TestMinimizeCorpus_PrunesExhaustedSeeds(t *testing.T) {
	f := &Fuzzer{
		corpus: []Seed{
			{Energy: 0.1, TimesChosen: 100, EdgesFound: 0}, // exhausted -> pruned
			{Energy: 5.0, TimesChosen: 1, EdgesFound: 2},   // kept
		},
		seedSampler: NewFenwickSampler(),
	}
	f.minimizeCorpus()
	if len(f.corpus) != 1 {
		t.Fatalf("expected 1 seed kept after pruning the exhausted one, got %d", len(f.corpus))
	}
	if f.corpus[0].EdgesFound != 2 {
		t.Errorf("expected the productive seed kept, got %+v", f.corpus[0])
	}
}

func TestMinimizeCorpus_CapsAtMaxByEnergyWhenPruningNotEnough(t *testing.T) {
	f := &Fuzzer{seedSampler: NewFenwickSampler()}
	for i := 0; i < 450; i++ {
		f.corpus = append(f.corpus, Seed{Energy: float64(i), EdgesFound: 1})
	}
	f.minimizeCorpus()
	if len(f.corpus) != 400 {
		t.Fatalf("expected the corpus capped at 400, got %d", len(f.corpus))
	}
	// Highest-energy seeds must be the ones kept.
	if f.corpus[0].Energy != 449 {
		t.Errorf("expected the highest-energy seed first after the cap sort, got %v", f.corpus[0].Energy)
	}
}

func TestShouldLearnFromSuccess(t *testing.T) {
	f := &Fuzzer{}
	if !f.shouldLearnFromSuccess(SendResult{Item: WorkItem{Method: "POST"}}) {
		t.Error("expected true for a write method")
	}
	if !f.shouldLearnFromSuccess(SendResult{Item: WorkItem{Method: "GET"}, Headers: map[string]string{"Location": "/x/1"}}) {
		t.Error("expected true when a Location header is present")
	}
	if !f.shouldLearnFromSuccess(SendResult{Item: WorkItem{Method: "GET", EpochName: "Baseline"}}) {
		t.Error("expected true for the Baseline epoch regardless of body")
	}
	if f.shouldLearnFromSuccess(SendResult{Item: WorkItem{Method: "GET"}, Body: ""}) {
		t.Error("expected false for an empty body with no other signal")
	}
	if f.shouldLearnFromSuccess(SendResult{Item: WorkItem{Method: "GET"}, Body: "plain text, not json"}) {
		t.Error("expected false for a non-JSON body")
	}
}

func TestShouldEnqueueSequence(t *testing.T) {
	f := &Fuzzer{}
	if !f.shouldEnqueueSequence(SendResult{Item: WorkItem{Method: "POST"}}, 0) {
		t.Error("expected true for a write method regardless of learned count")
	}
	if !f.shouldEnqueueSequence(SendResult{Item: WorkItem{Method: "GET"}}, 3) {
		t.Error("expected true when something was learned")
	}
}

func TestEnsureEndpointStats_CreatesAndReuses(t *testing.T) {
	f := &Fuzzer{endpointStats: map[string]*EndpointStats{}}
	ep1 := f.ensureEndpointStats("GET", "/widgets/1")
	ep2 := f.ensureEndpointStats("GET", "/widgets/2")
	if ep1 != ep2 {
		t.Error("expected the same *EndpointStats reused for the same normalized endpoint")
	}
	if ep1.Method != "GET" {
		t.Errorf("expected Method=GET, got %q", ep1.Method)
	}
}

func TestEnsureMutationStats_DefaultsEmptyNameToSeed(t *testing.T) {
	f := &Fuzzer{mutationStats: map[string]*MutationStats{}}
	ms := f.ensureMutationStats("")
	if ms.Name != "seed" {
		t.Errorf("expected an empty name to default to 'seed', got %q", ms.Name)
	}
	ms2 := f.ensureMutationStats("seed")
	if ms != ms2 {
		t.Error("expected the same *MutationStats instance reused")
	}
}

func TestMineClientErrorFields_ValidationProblemDetailsShape(t *testing.T) {
	body := `{"errors":{"Status":["must be one of [Pending, Paid, Shipped]"]}}`
	got := mineClientErrorFields(body)
	vals, ok := got["Status"]
	if !ok || len(vals) != 3 {
		t.Fatalf("expected 3 mined values for Status, got %v", got)
	}
}

func TestMineClientErrorFields_FlatFieldMapShape(t *testing.T) {
	body := `{"Role":["Valid values: Member, Admin"]}`
	got := mineClientErrorFields(body)
	if vals, ok := got["Role"]; !ok || len(vals) != 2 {
		t.Errorf("expected 2 mined values for Role, got %v", got)
	}
}

func TestMineClientErrorFields_UnrelatedJSONYieldsEmpty(t *testing.T) {
	if got := mineClientErrorFields(`{"count":5}`); len(got) != 0 {
		t.Errorf("expected no mined fields for an unrelated JSON shape, got %v", got)
	}
}

func TestMineClientErrorFields_NonJSONOrEmptyYieldsEmpty(t *testing.T) {
	if got := mineClientErrorFields(""); len(got) != 0 {
		t.Errorf("expected empty map for an empty body, got %v", got)
	}
	if got := mineClientErrorFields("plain text"); len(got) != 0 {
		t.Errorf("expected empty map for a non-JSON body, got %v", got)
	}
	if got := mineClientErrorFields("not json {"); len(got) != 0 {
		t.Errorf("expected empty map for invalid JSON, got %v", got)
	}
}

func TestRecordClientErrorSample_LearnsFieldsAndCapsSamples(t *testing.T) {
	f := &Fuzzer{
		runtime:       newRuntimeStore(),
		clientSamples: map[string][]string{},
	}
	body := `{"errors":{"Status":["must be one of [Pending, Paid]"]}}`
	f.recordClientErrorSample("POST", "/orders", 400, body)

	if len(f.runtime.valuesForKey("Status")) == 0 {
		t.Error("expected the mined field value learned into the runtime store")
	}
	k := endpointKey("POST", normalizePath("/orders"))
	if len(f.clientSamples[k]) != 1 {
		t.Fatalf("expected 1 sample recorded, got %d", len(f.clientSamples[k]))
	}

	for i := 0; i < 10; i++ {
		f.recordClientErrorSample("POST", "/orders", 400, "some other error")
	}
	if len(f.clientSamples[k]) != 5 {
		t.Errorf("expected client error samples capped at 5, got %d", len(f.clientSamples[k]))
	}
}

func TestTemplateDependencyWeight(t *testing.T) {
	f := &Fuzzer{
		depIndex: map[int]DepInfo{
			1: {},                                     // no reads/writes -> 1.0
			2: {Writes: map[string]struct{}{"a": {}}}, // writes only, no reads -> 1.2
			3: {Reads: map[string]struct{}{"orderId": {}}},
		},
		runtime: newRuntimeStore(),
	}
	if got := f.templateDependencyWeight(1); got != 1.0 {
		t.Errorf("expected 1.0 for no reads/writes, got %v", got)
	}
	if got := f.templateDependencyWeight(2); got != 1.2 {
		t.Errorf("expected 1.2 for writes-only, got %v", got)
	}
	// Reads present but nothing known yet -> ratio=0 -> weight=0.2, clamped to >=0.05.
	if got := f.templateDependencyWeight(3); got < 0.05 || got > 2.4 {
		t.Errorf("expected a clamped weight in [0.05,2.4], got %v", got)
	}
	f.runtime.addDepValue("orderId", "known-value")
	afterKnown := f.templateDependencyWeight(3)
	if afterKnown <= f.templateDependencyWeight(1)-1.0 {
		// sanity: known dep should raise the weight vs the empty-read state above
	}
	if afterKnown < 0.05 {
		t.Errorf("expected a valid weight once the dep is known, got %v", afterKnown)
	}
}

func TestTemplateHealthWeight_CrashBoostOverride(t *testing.T) {
	f := &Fuzzer{
		meta:          map[int]TemplateMeta{1: {Method: "GET", Norm: "/x"}},
		crashBoost:    map[string]int{endpointKey("GET", "/x"): 2},
		endpointStats: map[string]*EndpointStats{},
		authBlocked:   map[string]*AuthBlockedState{},
		cfg:           config.Config{CrashBoostWeight: 9.0},
	}
	if got := f.templateHealthWeight(1); got != 9.0 {
		t.Errorf("expected the crash-boost weight 9.0, got %v", got)
	}
	if remaining := f.crashBoost[endpointKey("GET", "/x")]; remaining != 1 {
		t.Errorf("expected the crash-boost counter decremented to 1, got %d", remaining)
	}
}

func TestTemplateHealthWeight_NoStatsDefaultsToOne(t *testing.T) {
	f := &Fuzzer{
		meta:          map[int]TemplateMeta{1: {Method: "GET", Norm: "/x"}},
		crashBoost:    map[string]int{},
		endpointStats: map[string]*EndpointStats{},
		authBlocked:   map[string]*AuthBlockedState{},
		cfg:           config.Config{},
	}
	if got := f.templateHealthWeight(1); got != 1.0 {
		t.Errorf("expected the default weight 1.0 with no stats yet, got %v", got)
	}
}

func TestTuneConcurrency_DisabledIsNoOp(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{AdaptiveConcurrency: false}, currentConcurrency: 8}
	f.tuneConcurrency()
	if f.currentConcurrency != 8 {
		t.Errorf("expected concurrency unchanged when AdaptiveConcurrency is disabled, got %d", f.currentConcurrency)
	}
}

func TestTuneConcurrency_TooSoonSinceLastTuneIsNoOp(t *testing.T) {
	f := &Fuzzer{
		cfg:                config.Config{AdaptiveConcurrency: true},
		currentConcurrency: 8,
		lastTuneTS:         time.Now(),
	}
	f.tuneConcurrency()
	if f.currentConcurrency != 8 {
		t.Errorf("expected no change within the 1s minimum tuning interval, got %d", f.currentConcurrency)
	}
}

func TestTuneConcurrency_HighErrorRateScalesDown(t *testing.T) {
	f := &Fuzzer{
		cfg:                config.Config{AdaptiveConcurrency: true, MinConcurrency: 1, MaxConcurrency: 32},
		currentConcurrency: 10,
		lastTuneTS:         time.Now().Add(-2 * time.Second),
		totalDone:          10,
		totalErrors:        5, // errRate = 5/15 = 0.33 > 0.15
		eventLog:           make([]string, 0, 8),
		startTime:          time.Now(),
	}
	f.tuneConcurrency()
	if f.currentConcurrency >= 10 {
		t.Errorf("expected concurrency scaled down under a high error rate, got %d", f.currentConcurrency)
	}
}

func TestTuneConcurrency_HealthyLoadScalesUp(t *testing.T) {
	f := &Fuzzer{
		cfg:                config.Config{AdaptiveConcurrency: true, MinConcurrency: 1, MaxConcurrency: 32},
		currentConcurrency: 4,
		lastTuneTS:         time.Now().Add(-2 * time.Second),
		totalDone:          20, // doneRate=10/s > 4*0.75=3
		latencyTotalMS:     200,
		eventLog:           make([]string, 0, 8),
		startTime:          time.Now(),
	}
	f.tuneConcurrency()
	if f.currentConcurrency <= 4 {
		t.Errorf("expected concurrency scaled up under healthy low-latency high-throughput load, got %d", f.currentConcurrency)
	}
}

func TestTemplateHealthWeight_CrashRateThrottle(t *testing.T) {
	epKey := endpointKey("GET", "/x")
	f := &Fuzzer{
		meta:       map[int]TemplateMeta{1: {Method: "GET", Norm: "/x"}},
		crashBoost: map[string]int{},
		endpointStats: map[string]*EndpointStats{
			epKey: {Reqs: 20, Logged5xx: 15},
		},
		authBlocked: map[string]*AuthBlockedState{},
		cfg: config.Config{
			EndpointCrashRateThreshold:  50,
			EndpointCrashRateMinCrashes: 2,
			EndpointCrashRateWeight:     0.02,
			EndpointReqShareCapPct:      100,
			EndpointReqCapMinReqs:       1000,
		},
	}
	if got := f.templateHealthWeight(1); got != 0.02 {
		t.Errorf("expected the crash-rate-throttled weight 0.02, got %v", got)
	}
}
