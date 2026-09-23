package engine

import (
	"math/rand"
	"strings"
	"testing"
	"void/internal/config"
)

// --- Lifecycle transition classification tests (Phase 10's "Lifecycle tests").

func TestLifecycle_CreateThenRead(t *testing.T) {
	created, result := deriveLifecycleTransition("POST", 201, LifecycleUnknown)
	if created != LifecycleCreated || result != "valid" {
		t.Fatalf("POST 201 from UNKNOWN: got (%s,%s), want (CREATED,valid)", created, result)
	}
	read, result := deriveLifecycleTransition("GET", 200, created)
	if read != LifecycleReadable || result != "valid" {
		t.Fatalf("GET 200 from CREATED: got (%s,%s), want (READABLE,valid)", read, result)
	}
}

func TestLifecycle_CreateThenUpdate(t *testing.T) {
	modified, result := deriveLifecycleTransition("PUT", 200, LifecycleCreated)
	if modified != LifecycleModified || result != "valid" {
		t.Fatalf("PUT 200 from CREATED: got (%s,%s), want (MODIFIED,valid)", modified, result)
	}
}

func TestLifecycle_CreateThenDelete(t *testing.T) {
	deleted, result := deriveLifecycleTransition("DELETE", 204, LifecycleCreated)
	if deleted != LifecycleDeleted || result != "valid" {
		t.Fatalf("DELETE 204 from CREATED: got (%s,%s), want (DELETED,valid)", deleted, result)
	}
}

func TestLifecycle_DeleteThenRead_IsStaleInvalid(t *testing.T) {
	stale, result := deriveLifecycleTransition("GET", 200, LifecycleDeleted)
	if stale != LifecycleStale || result != "invalid" {
		t.Fatalf("GET 200 from DELETED: got (%s,%s), want (STALE,invalid) -- a successful read of a resource this run deleted is exactly the interesting case", stale, result)
	}
	confirmedGone, result := deriveLifecycleTransition("GET", 404, LifecycleDeleted)
	if confirmedGone != LifecycleDeleted || result != "valid" {
		t.Fatalf("GET 404 from DELETED: got (%s,%s), want (DELETED,valid) -- correctly confirms deletion", confirmedGone, result)
	}
}

func TestLifecycle_DeleteThenUpdate_IsInvalid(t *testing.T) {
	invalidated, result := deriveLifecycleTransition("PUT", 200, LifecycleDeleted)
	if invalidated != LifecycleInvalidated || result != "invalid" {
		t.Fatalf("PUT 200 from DELETED: got (%s,%s), want (INVALIDATED,invalid) -- an update that 'succeeded' on a deleted resource is a bug-shaped signal", invalidated, result)
	}
	rejected, result := deriveLifecycleTransition("PUT", 409, LifecycleDeleted)
	if rejected != LifecycleDeleted || result != "valid" {
		t.Fatalf("PUT 409 from DELETED: got (%s,%s), want (DELETED,valid) -- correctly rejected", rejected, result)
	}
}

func TestLifecycle_DeleteThenDelete_IsRepeatedInvalid(t *testing.T) {
	to, result := deriveLifecycleTransition("DELETE", 200, LifecycleDeleted)
	if to != LifecycleDeleted || result != "invalid" {
		t.Fatalf("DELETE 200 from DELETED: got (%s,%s), want (DELETED,invalid) -- repeated-deletion transition", to, result)
	}
	to, result = deriveLifecycleTransition("DELETE", 404, LifecycleDeleted)
	if to != LifecycleDeleted || result != "valid" {
		t.Fatalf("DELETE 404 from DELETED: got (%s,%s), want (DELETED,valid) -- correctly rejected double-delete", to, result)
	}
}

func TestLifecycle_FailedCreation(t *testing.T) {
	to, result := deriveLifecycleTransition("POST", 400, LifecycleUnknown)
	if to != LifecycleFailedCreation || result != "invalid" {
		t.Fatalf("POST 400: got (%s,%s), want (FAILED_CREATION,invalid)", to, result)
	}
}

func TestLifecycle_FailedModification(t *testing.T) {
	to, result := deriveLifecycleTransition("PATCH", 422, LifecycleCreated)
	if to != LifecycleFailedModification || result != "invalid" {
		t.Fatalf("PATCH 422 from CREATED: got (%s,%s), want (FAILED_MODIFICATION,invalid)", to, result)
	}
}

func TestLifecycle_FailedDeletion(t *testing.T) {
	to, result := deriveLifecycleTransition("DELETE", 403, LifecycleCreated)
	if to != LifecycleFailedDeletion || result != "invalid" {
		t.Fatalf("DELETE 403 from CREATED: got (%s,%s), want (FAILED_DELETION,invalid)", to, result)
	}
}

func TestLifecycle_MethodAloneIsNotSufficient(t *testing.T) {
	// Same method+status pair, different prior state, must produce a
	// different classification -- proving the derivation genuinely consults
	// prior state, not just (method,status).
	fromUnknown, _ := deriveLifecycleTransition("GET", 200, LifecycleUnknown)
	fromDeleted, _ := deriveLifecycleTransition("GET", 200, LifecycleDeleted)
	if fromUnknown == fromDeleted {
		t.Fatalf("expected GET 200 to classify differently depending on prior state (UNKNOWN vs DELETED), got the same result %s for both", fromUnknown)
	}
}

func TestDeriveTransitionAction_DistinguishesSameMethodDifferentAction(t *testing.T) {
	approve := deriveTransitionAction("POST", "/orders/42/approve")
	refund := deriveTransitionAction("POST", "/orders/42/refund")
	if approve != "approve" || refund != "refund" {
		t.Fatalf("expected distinct actions for approve/refund, got %q and %q", approve, refund)
	}
	if approve == refund {
		t.Fatal("expected POST /approve and POST /refund to produce DIFFERENT actions -- HTTP method alone is not sufficient (the design constraint this exists for)")
	}
}

func TestDeriveTransitionAction_KnownVerbSuffixMatchesRegardlessOfIDShape(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/invoices/inv-123/pay", "pay"},
		{"/invoices/550e8400-e29b-41d4-a716-446655440000/refund", "refund"},
		{"/organizations/7/coupons/redeem", "redeem"},
		{"/organizations/7/credits/withdraw", "withdraw"},
	}
	for _, c := range cases {
		if got := deriveTransitionAction("POST", c.path); got != c.want {
			t.Errorf("deriveTransitionAction(POST, %q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestDeriveTransitionAction_FallsBackToMethodForConventionalCRUD(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"POST", "/orders", "create"},
		{"GET", "/orders/42", "read"},
		{"PUT", "/orders/42", "update"},
		{"PATCH", "/orders/42", "update"},
		{"DELETE", "/orders/42", "delete"},
	}
	for _, c := range cases {
		if got := deriveTransitionAction(c.method, c.path); got != c.want {
			t.Errorf("deriveTransitionAction(%s, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestDeriveTransitionAction_TrailingResourceIDNotMistakenForAction(t *testing.T) {
	// The trailing segment here normalizes to a {param}/{uuid} placeholder,
	// not a literal verb -- must fall back to the generic method-derived
	// action, not try to treat the id itself as an action name.
	if got := deriveTransitionAction("GET", "/orders/42"); got != "read" {
		t.Fatalf("expected fallback to 'read' for a trailing numeric id, got %q", got)
	}
	if got := deriveTransitionAction("GET", "/orders/550e8400-e29b-41d4-a716-446655440000"); got != "read" {
		t.Fatalf("expected fallback to 'read' for a trailing GUID, got %q", got)
	}
}

func TestDeriveTransitionActionForTemplate_XStateTransitionExtensionWins(t *testing.T) {
	meta := TemplateMeta{XStateTransition: &XStateTransitionHint{From: "sent", Action: "pay", To: "paid"}, RoslynAction: "SubmitPayment"}
	// The path/method heuristic alone would say "update" (PUT) -- Tier 1 must win.
	if got := deriveTransitionActionForTemplate(meta, "PUT", "/invoices/42"); got != "pay" {
		t.Fatalf("expected the explicit x-state-transition action (pay) to win over Roslyn/heuristic, got %q", got)
	}
}

func TestDeriveTransitionActionForTemplate_NonGenericRoslynActionWinsOverHeuristic(t *testing.T) {
	meta := TemplateMeta{RoslynAction: "ApproveOrder"}
	if got := deriveTransitionActionForTemplate(meta, "POST", "/orders/42"); got != "ApproveOrder" {
		t.Fatalf("expected the non-generic Roslyn action name to win over the method-derived fallback (create), got %q", got)
	}
}

func TestDeriveTransitionActionForTemplate_GenericRoslynActionFallsThrough(t *testing.T) {
	meta := TemplateMeta{RoslynAction: "Post"}
	if got := deriveTransitionActionForTemplate(meta, "POST", "/orders"); got != "create" {
		t.Fatalf("expected a generic Roslyn action name (Post) to fall through to the heuristic (create), got %q", got)
	}
}

func TestDeriveTransitionActionForTemplate_ZeroValueMetaFallsThroughToHeuristic(t *testing.T) {
	if got := deriveTransitionActionForTemplate(TemplateMeta{}, "POST", "/orders/42/approve"); got != "approve" {
		t.Fatalf("expected zero-value TemplateMeta to degrade gracefully to the path-heuristic result, got %q", got)
	}
}

func TestIsGenericRoslynActionName(t *testing.T) {
	generic := []string{"Get", "GetAll", "Post", "PUT", "index", "Create", "Handle"}
	for _, name := range generic {
		if !isGenericRoslynActionName(name) {
			t.Errorf("expected %q to be classified as a generic action name", name)
		}
	}
	specific := []string{"ApproveOrder", "RefundPayment", "RestoreTask", "RedeemCoupon"}
	for _, name := range specific {
		if isGenericRoslynActionName(name) {
			t.Errorf("expected %q to NOT be classified as generic", name)
		}
	}
}

func TestTransitionLabel_RendersTypedFormat(t *testing.T) {
	tr := ResourceTransition{From: LifecycleReadable, To: LifecycleModified, Action: "pay"}
	label := tr.TransitionLabel("invoice")
	want := "invoice:READABLE --pay--> invoice:MODIFIED"
	if label != want {
		t.Fatalf("TransitionLabel() = %q, want %q", label, want)
	}
}

func TestTransitionLabel_FallsBackToPlaceholderForUnsetAction(t *testing.T) {
	tr := ResourceTransition{From: LifecycleCreated, To: LifecycleReadable}
	if label := tr.TransitionLabel("order"); !strings.Contains(label, "--?-->") {
		t.Fatalf("expected a '?' placeholder for an unset Action, got %q", label)
	}
}

// --- Coverage-directed scheduling tests (Phase 10's "Scheduling tests").

func newTestFuzzerForScheduling() *Fuzzer {
	f := &Fuzzer{
		meta:          map[int]TemplateMeta{},
		tmplEPKey:     map[int]string{},
		endpointStats: map[string]*EndpointStats{},
		resourceGraph: newResourceGraph(ResourceGraphLimits{}),
		cfg: config.Config{
			ResourceGraphEnabled:            true,
			ResourceGraphUnreachedWeight:    40,
			ResourceGraphYieldWeight:        2,
			ResourceGraphFailurePenalty:     5,
			ResourceGraphSuccessProbWeight:  15,
			ResourceGraphAvailabilityWeight: 20,
			ResourceGraphExploreRate:        0, // deterministic by default; overridden per-test
		},
	}
	return f
}

func TestScoreConsumer_UnreachedConsumerScoresHigherThanReached(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	f.resourceGraph.markConsumerReached(2) // tid=2 has been reached before; tid=1 has not

	s1 := f.scoreConsumer(1, "POST", "/orders", "")
	s2 := f.scoreConsumer(2, "POST", "/orders", "")
	if s1 <= s2 {
		t.Fatalf("expected the never-reached consumer (tid=1, score=%v) to score higher than the already-reached one (tid=2, score=%v)", s1, s2)
	}
}

func TestScoreConsumer_HistoricalCoverageYieldIncreasesScore(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/b/{param}"}
	f.tmplEPKey[1] = "GET /a/{param}"
	f.tmplEPKey[2] = "GET /b/{param}"
	f.endpointStats["GET /a/{param}"] = &EndpointStats{NewEdges: 50}
	f.endpointStats["GET /b/{param}"] = &EndpointStats{NewEdges: 0}
	// Mark both reached so the "unreached" bonus doesn't dominate the comparison.
	f.resourceGraph.markConsumerReached(1)
	f.resourceGraph.markConsumerReached(2)

	s1 := f.scoreConsumer(1, "POST", "/a", "")
	s2 := f.scoreConsumer(2, "POST", "/b", "")
	if s1 <= s2 {
		t.Fatalf("expected the consumer with historical coverage yield (tid=1, score=%v) to outscore one with none (tid=2, score=%v)", s1, s2)
	}
}

func TestScoreConsumer_RepeatedFailureReducesScore(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	f.resourceGraph.markConsumerReached(1)
	before := f.scoreConsumer(1, "POST", "/orders", "")

	f.resourceGraph.markConsumerResult(1, true)
	f.resourceGraph.markConsumerResult(1, true)
	f.resourceGraph.markConsumerResult(1, true)
	after := f.scoreConsumer(1, "POST", "/orders", "")

	if after >= before {
		t.Fatalf("expected 3 recorded failures to reduce the score (before=%v, after=%v)", before, after)
	}
}

func TestScoreConsumer_HistoricalSuccessProbabilityIncreasesScore(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/b/{param}"}
	f.tmplEPKey[1] = "GET /a/{param}"
	f.tmplEPKey[2] = "GET /b/{param}"
	f.endpointStats["GET /a/{param}"] = &EndpointStats{Reqs: 10, S2xx: 9} // 90% success
	f.endpointStats["GET /b/{param}"] = &EndpointStats{Reqs: 10, S2xx: 1} // 10% success
	f.resourceGraph.markConsumerReached(1)
	f.resourceGraph.markConsumerReached(2)

	s1 := f.scoreConsumer(1, "POST", "/a", "")
	s2 := f.scoreConsumer(2, "POST", "/b", "")
	if s1 <= s2 {
		t.Fatalf("expected the consumer with a higher historical 2xx rate (tid=1, score=%v) to outscore one with a low rate (tid=2, score=%v)", s1, s2)
	}
}

func TestScoreConsumer_SuccessProbabilityWeightZeroDisablesTerm(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.cfg.ResourceGraphSuccessProbWeight = 0
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	f.tmplEPKey[1] = "GET /a/{param}"
	f.endpointStats["GET /a/{param}"] = &EndpointStats{Reqs: 10, S2xx: 10}
	f.resourceGraph.markConsumerReached(1)

	withStats := f.scoreConsumer(1, "POST", "/a", "")

	f.endpointStats["GET /a/{param}"] = &EndpointStats{Reqs: 10, S2xx: 0}
	withoutSuccess := f.scoreConsumer(1, "POST", "/a", "")

	if withStats != withoutSuccess {
		t.Fatalf("expected weight=0 to make the success-probability term a no-op, got %v vs %v", withStats, withoutSuccess)
	}
}

func TestScoreConsumer_ResourceAvailabilityIncreasesScore(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"} // has a live "widget" instance
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/gadgets/{param}"} // no live "gadget" instance
	f.resourceGraph.markConsumerReached(1)
	f.resourceGraph.markConsumerReached(2)
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"POST /widgets", "seq-1", LifecycleCreated, 0.9,
	)

	s1 := f.scoreConsumer(1, "POST", "/widgets", "")
	s2 := f.scoreConsumer(2, "POST", "/gadgets", "")
	if s1 <= s2 {
		t.Fatalf("expected the consumer with an actually-available resource instance (tid=1, score=%v) to outscore one with none (tid=2, score=%v)", s1, s2)
	}
}

func TestScoreConsumer_ResourceAvailabilityRespectsTenantScope(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/projects/{param}"}
	f.resourceGraph.markConsumerReached(1)
	orgA, _ := projectInTenant(f.resourceGraph, "org-a", "prj-a")
	_, _ = projectInTenant(f.resourceGraph, "org-b", "prj-b")

	inScope := f.scoreConsumer(1, "POST", "/projects", orgA.Canonical.graphKey())
	wrongScope := f.scoreConsumer(1, "POST", "/projects", "organization|organization:scalar:org-does-not-exist")
	if inScope <= wrongScope {
		t.Fatalf("expected an in-tenant-scope availability check (score=%v) to outscore one with no matching tenant (score=%v)", inScope, wrongScope)
	}
}

func TestRankConsumersCoverageDirected_OrdersByScore(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/b/{param}"}
	f.meta[3] = TemplateMeta{Method: "GET", Norm: "/c/{param}"}
	// tid=2 reached and yields nothing; tid=1 and tid=3 unreached.
	f.resourceGraph.markConsumerReached(2)

	ranked := f.rankConsumersCoverageDirected([]int{2, 1, 3}, "POST", "/x", "")
	if len(ranked) != 3 {
		t.Fatalf("expected 3 candidates back, got %d", len(ranked))
	}
	if ranked[0] == 2 {
		t.Fatalf("expected an already-reached consumer to rank behind unreached ones, got order %v", ranked)
	}
}

func TestRankConsumersCoverageDirected_DeterministicWithFixedSeed(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.cfg.ResourceGraphExploreRate = 0.5 // exercise the exploration branch too
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/b/{param}"}
	f.meta[3] = TemplateMeta{Method: "GET", Norm: "/c/{param}"}
	f.meta[4] = TemplateMeta{Method: "GET", Norm: "/d/{param}"}

	rand.Seed(12345)
	first := f.rankConsumersCoverageDirected([]int{1, 2, 3, 4}, "POST", "/x", "")
	rand.Seed(12345)
	second := f.rankConsumersCoverageDirected([]int{1, 2, 3, 4}, "POST", "/x", "")

	if len(first) != len(second) {
		t.Fatalf("length mismatch between two seeded runs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("expected identical ranking with the same math/rand seed, got %v vs %v", first, second)
		}
	}
}

func TestRankConsumersCoverageDirected_NoStarvation(t *testing.T) {
	// A consumer that always scores lowest must still occasionally be
	// promoted to the front by the epsilon-exploration term, across many
	// trials -- i.e. it must not be *permanently* starved.
	f := newTestFuzzerForScheduling()
	f.cfg.ResourceGraphExploreRate = 1.0 // always explore, for a fast/deterministic-enough test
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/b/{param}"}
	// tid=1 is reached many times over (low score); tid=2 is never reached
	// (always scores highest without exploration).
	for i := 0; i < 100; i++ {
		f.resourceGraph.markConsumerReached(1)
	}

	promotedAtLeastOnce := false
	for trial := 0; trial < 50; trial++ {
		ranked := f.rankConsumersCoverageDirected([]int{2, 1}, "POST", "/x", "")
		if ranked[0] == 1 {
			promotedAtLeastOnce = true
			break
		}
	}
	if !promotedAtLeastOnce {
		t.Fatal("expected the low-scoring consumer to be promoted to the front at least once across 50 trials with explore-rate=1.0 -- starvation prevention is not working")
	}
}

func TestRankConsumersCoverageDirected_SingleCandidateIsNoOp(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/a/{param}"}
	ranked := f.rankConsumersCoverageDirected([]int{1}, "POST", "/x", "")
	if len(ranked) != 1 || ranked[0] != 1 {
		t.Fatalf("expected a single-candidate list to pass through unchanged, got %v", ranked)
	}
}

func TestRankConsumersCoverageDirected_EmptyIsNoOp(t *testing.T) {
	f := newTestFuzzerForScheduling()
	ranked := f.rankConsumersCoverageDirected(nil, "POST", "/x", "")
	if len(ranked) != 0 {
		t.Fatalf("expected an empty candidate list to stay empty, got %v", ranked)
	}
}

// TestFindFollowups_ResourceGraphDisabledMatchesOldOrdering verifies the
// disable-and-fall-back compatibility guarantee: with -resource-graph=false,
// findFollowups must produce exactly the same order the pre-existing
// followupPriority-only sort would.
func TestFindFollowups_ResourceGraphDisabledUsesStaticPriorityOnly(t *testing.T) {
	f := &Fuzzer{
		meta:          map[int]TemplateMeta{},
		tmplByID:      map[int]*Template{},
		activeIDs:     []int{1, 2},
		depConsumers:  map[string][]int{},
		idConsumers:   map[string][]int{},
		resourceGraph: newResourceGraph(ResourceGraphLimits{}),
		cfg:           config.Config{ResourceGraphEnabled: false},
	}
	f.meta[1] = TemplateMeta{Method: "DELETE", Norm: "/orders/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	f.activeIDs = []int{1, 2}

	out := f.findFollowups(99, "POST", "/orders", nil, nil, "")
	// followupPriority favors GET over DELETE after a POST -- GET (tid=2) must
	// come first when the resource graph is disabled and this is the only
	// signal in play.
	if len(out) != 2 || out[0] != 2 {
		t.Fatalf("expected static verb-affinity ordering (GET before DELETE) when resource graph is disabled, got %v", out)
	}
}
