package engine

import (
	"testing"
	"void/internal/config"
)

func newRaceTestFuzzer() *Fuzzer {
	return &Fuzzer{
		cfg: config.Config{
			RaceMode:         true,
			RaceProb:         1.0,
			RaceBurst:        4,
			ProbeRaceOutcome: true,
		},
		meta:               map[int]TemplateMeta{},
		raceQueue:          make([]WorkItem, 0, 16),
		raceBurstSuccess:   map[string]int{},
		raceBurstSeen:      map[string]int{},
		raceBurstEvaluated: map[string]struct{}{},
	}
}

// ---------------------------------------------------------------------------
// isRaceCandidatePath: broadened concurrency-action keyword set
// ---------------------------------------------------------------------------

func TestIsRaceCandidatePath_ConcurrencyActionKeywords(t *testing.T) {
	yes := []string{
		"/orders/1/approve", "/invoices/1/cancel", "/coupons/redeem",
		"/accounts/1/withdraw", "/transfer", "/payments/1/refund",
		"/invites/1/accept", "/invites/1/reject", "/orders/1/confirm",
		"/cart/checkout", "/orders/1", // original commerce keyword set still works
	}
	for _, p := range yes {
		if !isRaceCandidatePath(p) {
			t.Errorf("expected %q to be a race candidate path", p)
		}
	}
	no := []string{"/health", "/widgets/1", "/users/1/profile"}
	for _, p := range no {
		if isRaceCandidatePath(p) {
			t.Errorf("expected %q NOT to be a race candidate path", p)
		}
	}
}

// ---------------------------------------------------------------------------
// enqueueRaceBurst: BurstID/BurstSize/BurstAction tagging
// ---------------------------------------------------------------------------

func TestEnqueueRaceBurst_TagsEveryMemberWithSharedBurstID(t *testing.T) {
	f := newRaceTestFuzzer()
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/coupons/{param}/redeem"}
	source := WorkItem{TemplateID: 1, Method: "POST", Path: "/coupons/abc/redeem"}
	f.enqueueRaceBurst(source)

	if len(f.raceQueue) != 4 {
		t.Fatalf("expected 4 queued burst members (RaceBurst=4), got %d", len(f.raceQueue))
	}
	id := f.raceQueue[0].BurstID
	if id == "" {
		t.Fatal("expected a non-empty BurstID")
	}
	for i, it := range f.raceQueue {
		if it.BurstID != id {
			t.Errorf("member %d: expected shared BurstID %q, got %q", i, id, it.BurstID)
		}
		if it.BurstSize != 4 {
			t.Errorf("member %d: expected BurstSize=4, got %d", i, it.BurstSize)
		}
		if it.BurstAction != "redeem" {
			t.Errorf("member %d: expected BurstAction=redeem, got %q", i, it.BurstAction)
		}
	}
}

func TestEnqueueRaceBurst_NonCandidatePathNoOp(t *testing.T) {
	f := newRaceTestFuzzer()
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/widgets"}
	f.enqueueRaceBurst(WorkItem{TemplateID: 1, Method: "POST", Path: "/widgets"})
	if len(f.raceQueue) != 0 {
		t.Fatalf("expected no burst for a non-candidate path, got %d", len(f.raceQueue))
	}
}

// ---------------------------------------------------------------------------
// recordRaceBurstResult: outcome evaluation
// ---------------------------------------------------------------------------

func TestRecordRaceBurstResult_MultipleSuccessesRaiseFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t) // real uniqueWriter, needed by recordAdversarialFinding
	f.cfg.ProbeRaceOutcome = true
	id := "race-1"
	item := WorkItem{Method: "POST", Path: "/coupons/abc/redeem", BurstID: id, BurstSize: 3, BurstAction: "redeem"}

	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding before all %d members have reported, got %d", item.BurstSize, f.adversarialFindings)
	}
	f.recordRaceBurstResult(SendResult{Item: item, Status: 409}) // 3rd member correctly rejected

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding once 2 of 3 concurrent redeem requests succeeded, got %d", f.adversarialFindings)
	}
	tr := f.findings[0].Triage
	if tr["classification"] != "likely_vuln_high" || tr["severity_score"] != 9 {
		t.Fatalf("expected a sensitive action (redeem) double-success to be high severity, got %+v", tr)
	}
}

func TestRecordRaceBurstResult_OnlyOneSuccessNoFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.cfg.ProbeRaceOutcome = true
	id := "race-2"
	item := WorkItem{Method: "POST", Path: "/coupons/abc/redeem", BurstID: id, BurstSize: 3, BurstAction: "redeem"}

	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	f.recordRaceBurstResult(SendResult{Item: item, Status: 409})
	f.recordRaceBurstResult(SendResult{Item: item, Status: 409})

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding when exactly 1 of 3 concurrent requests succeeded (correct exclusivity), got %d", f.adversarialFindings)
	}
}

func TestRecordRaceBurstResult_EvaluatedExactlyOncePerBurst(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.cfg.ProbeRaceOutcome = true
	id := "race-3"
	item := WorkItem{Method: "POST", Path: "/coupons/abc/redeem", BurstID: id, BurstSize: 2, BurstAction: "redeem"}

	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding after the burst completes, got %d", f.adversarialFindings)
	}
	// A stray extra result for the same (already-evaluated) burst ID must not
	// re-trigger evaluation or duplicate the finding.
	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	if f.adversarialFindings != 1 {
		t.Fatalf("expected exactly 1 finding even with a stray extra result, got %d", f.adversarialFindings)
	}
}

func TestRecordRaceBurstResult_ErroredMemberStillCountsTowardSeen(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.cfg.ProbeRaceOutcome = true
	id := "race-4"
	item := WorkItem{Method: "POST", Path: "/coupons/abc/redeem", BurstID: id, BurstSize: 2, BurstAction: "redeem"}

	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	// Simulate a network-error member (handleResult, worker.go, calls this
	// BEFORE its own res.Err early return) -- Status is meaningless/zero here.
	f.recordRaceBurstResult(SendResult{Item: item, Err: errTestNetwork})

	if _, done := f.raceBurstEvaluated[id]; !done {
		t.Fatal("expected the burst to be evaluated once an errored member brings the seen-count to BurstSize")
	}
}

func TestRecordRaceBurstResult_DisabledByFlag(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.cfg.ProbeRaceOutcome = false
	id := "race-5"
	item := WorkItem{Method: "POST", Path: "/coupons/abc/redeem", BurstID: id, BurstSize: 2, BurstAction: "redeem"}

	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})
	f.recordRaceBurstResult(SendResult{Item: item, Status: 200})

	if f.adversarialFindings != 0 {
		t.Fatalf("expected -probe-race-outcome=false to suppress the finding entirely, got %d", f.adversarialFindings)
	}
}

func TestRecordRaceBurstResult_EmptyBurstIDIsNoOp(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.recordRaceBurstResult(SendResult{Item: WorkItem{Method: "GET", Path: "/x"}, Status: 200})
	if len(f.raceBurstSeen) != 0 || f.adversarialFindings != 0 {
		t.Fatal("expected a result with no BurstID to be a complete no-op")
	}
}

var errTestNetwork = &testNetError{}

type testNetError struct{}

func (e *testNetError) Error() string { return "simulated network error" }
