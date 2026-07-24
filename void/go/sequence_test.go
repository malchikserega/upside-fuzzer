package main

import "testing"

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
		depIndex:              map[int]DepInfo{},
		meta:                  map[int]TemplateMeta{},
		seenStateSigs:         map[string]struct{}{},
		persistedWorkflowSigs: map[string]struct{}{},
		cfg:                   Config{SequenceMaxDepth: 3},
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

// TestMaybePersistSequenceDedupsByFinalShape verifies that two workflows with
// the same final state signature (same step shapes, different concrete
// payloads) are only persisted once (Top-20 #12, closing the "no dedup of
// equivalent workflows" gap in ARCHITECTURE_REVIEW.md §5).
func TestMaybePersistSequenceDedupsByFinalShape(t *testing.T) {
	f := &Fuzzer{persistedWorkflowSigs: map[string]struct{}{}}

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
