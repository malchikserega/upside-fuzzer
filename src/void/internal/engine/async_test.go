package engine

import "testing"

func TestIsAsyncSubmission_202IsAlwaysAsync(t *testing.T) {
	if !isAsyncSubmission(202, nil) {
		t.Fatal("expected status 202 to always be recognized as an async submission")
	}
}

func TestIsAsyncSubmission_RetryAfterHeaderOnAnySuccessStatus(t *testing.T) {
	if !isAsyncSubmission(201, map[string]string{"Retry-After": "5"}) {
		t.Fatal("expected a 201 with Retry-After to be recognized as async")
	}
	if !isAsyncSubmission(200, map[string]string{"retry-after": "5"}) {
		t.Fatal("expected case-insensitive header matching")
	}
}

func TestIsAsyncSubmission_OrdinarySuccessIsNotAsync(t *testing.T) {
	if isAsyncSubmission(200, map[string]string{"Content-Type": "application/json"}) {
		t.Fatal("expected an ordinary 200 with no Retry-After to NOT be async")
	}
	if isAsyncSubmission(404, nil) {
		t.Fatal("expected a non-2xx status to never be async")
	}
}

func TestIsAsyncTerminalStatusValue(t *testing.T) {
	terminal := []string{"completed", "Succeeded", "FAILED", "cancelled", "error", "done"}
	for _, s := range terminal {
		if !isAsyncTerminalStatusValue(s) {
			t.Errorf("expected %q to be recognized as a terminal async status", s)
		}
	}
	pending := []string{"pending", "running", "in_progress", "queued", ""}
	for _, s := range pending {
		if isAsyncTerminalStatusValue(s) {
			t.Errorf("expected %q to NOT be recognized as terminal", s)
		}
	}
}

func TestIsAsyncOperationPending(t *testing.T) {
	if isAsyncOperationPending(nil) {
		t.Fatal("expected nil instance to be not-pending")
	}
	notSubmitted := &ResourceInstance{Attributes: map[string]any{"status": "pending"}}
	if isAsyncOperationPending(notSubmitted) {
		t.Fatal("expected an instance never marked async_submitted to be not-pending")
	}
	pending := &ResourceInstance{Attributes: map[string]any{"async_submitted": true, "status": "running"}}
	if !isAsyncOperationPending(pending) {
		t.Fatal("expected a submitted, non-terminal-status instance to be pending")
	}
	terminal := &ResourceInstance{Attributes: map[string]any{"async_submitted": true, "status": "completed"}}
	if isAsyncOperationPending(terminal) {
		t.Fatal("expected a submitted instance with a terminal status to NOT be pending anymore")
	}
	noStatusYet := &ResourceInstance{Attributes: map[string]any{"async_submitted": true}}
	if !isAsyncOperationPending(noStatusYet) {
		t.Fatal("expected a submitted instance with no status field yet to default to pending")
	}
}

// ---------------------------------------------------------------------------
// Integration: recordResourceGraphStep tags async_submitted on a real 202
// ---------------------------------------------------------------------------

func TestRecordResourceGraphStep_202TagsAsyncSubmitted(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/imports"}

	submit := WorkItem{Method: "POST", Path: "/imports"}
	f.recordResourceGraphStep(submit, SendResult{
		Item: submit, Status: 202, Headers: map[string]string{"Location": "/imports/job-1"},
		Body: `{"id":"job-1","status":"pending"}`,
	}, "seq-1", "POST /imports")

	inst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "import", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("import", "scalar", "job-1")})
	if inst == nil {
		t.Fatal("expected the job resource to be recorded")
	}
	if !isAsyncOperationPending(inst) {
		t.Fatalf("expected the 202-submitted job to be recognized as a pending async operation, got Attributes=%+v", inst.Attributes)
	}
}

func TestScoreConsumer_PollBonusForPendingAsyncOperation(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/imports/{param}"} // poll candidate
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"} // unrelated candidate
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "import", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("import", "scalar", "job-1"), RawValue: "job-1"},
		"POST /imports", "seq-1", LifecycleCreated, 0.9,
		RecordInstanceOpts{Attributes: map[string]any{"async_submitted": true, "status": "running"}},
	)
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"POST /widgets", "seq-1", LifecycleCreated, 0.9,
	)
	f.resourceGraph.markConsumerReached(1)
	f.resourceGraph.markConsumerReached(2)

	pollScore := f.scoreConsumer(1, "POST", "/imports", "")
	ordinaryScore := f.scoreConsumer(2, "POST", "/widgets", "")
	if pollScore <= ordinaryScore {
		t.Fatalf("expected the pending-async poll candidate (score=%v) to outscore an ordinary available resource (score=%v)", pollScore, ordinaryScore)
	}
}

func TestScoreConsumer_NoPollBonusOnceTerminal(t *testing.T) {
	f := newTestFuzzerForScheduling()
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/imports/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "import", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("import", "scalar", "job-1"), RawValue: "job-1"},
		"POST /imports", "seq-1", LifecycleCreated, 0.9,
		RecordInstanceOpts{Attributes: map[string]any{"async_submitted": true, "status": "completed"}},
	)
	f.resourceGraph.markConsumerReached(1)

	withTerminal := f.scoreConsumer(1, "POST", "/imports", "")

	// Same setup but pending -- must score strictly higher than the terminal case.
	f2 := newTestFuzzerForScheduling()
	f2.meta[1] = TemplateMeta{Method: "GET", Norm: "/imports/{param}"}
	f2.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "import", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("import", "scalar", "job-1"), RawValue: "job-1"},
		"POST /imports", "seq-1", LifecycleCreated, 0.9,
		RecordInstanceOpts{Attributes: map[string]any{"async_submitted": true, "status": "running"}},
	)
	f2.resourceGraph.markConsumerReached(1)
	withPending := f2.scoreConsumer(1, "POST", "/imports", "")

	if withPending <= withTerminal {
		t.Fatalf("expected a pending operation (score=%v) to score higher than an already-terminal one (score=%v) -- the poll bonus should stop once resolved", withPending, withTerminal)
	}
}
