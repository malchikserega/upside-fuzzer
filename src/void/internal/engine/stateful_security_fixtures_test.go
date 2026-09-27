package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"void/internal/config"
)

// stateful_security_fixtures_test.go — Phase 5 #128: an in-process, real-HTTP
// fixture matrix proving each of the stateful-security properties named in
// the original architecture spec's fixture-suite requirement (nested tenant
// resource, cross-tenant read, deleted-resource-still-mutable, approval
// bypass, ignored ETag, double payment, async import job, privileged
// mass-assignment) actually fires through the REAL engine machinery --
// f.sendOne doing genuine HTTP round trips against an httptest server, the
// real oracle enqueue/handle functions, the real resource graph, and (for the
// last test) the real recordCrash pipeline -- not fabricated SendResult
// structs standing in for a network round trip the way most of this file's
// sibling *_test.go files reasonably do for narrower unit coverage.
//
// Distinct from resource_integration_test.go (Phase 1 #107), which proves
// real HTTP responses drive resource-graph EXTRACTION correctly. This file
// proves the ADVERSARIAL/security-finding side of the same pipeline: that a
// deliberately vulnerable fixture endpoint's real response actually causes a
// real finding, and that a correctly-behaving contrast case does not.
//
// CI wiring: run explicitly (not just swept up in the blanket `go test ./...`
// step) by .github/workflows/e2e.yml's "Stateful-security E2E fixture matrix"
// step, so a regression here fails as its own named gate.

// newStatefulSecurityFixtureServer models a small multi-tenant app with one
// deliberately vulnerable endpoint per named property above. Vulnerabilities
// are real server-side behavior (e.g. PUT ignoring If-Match entirely), not
// pre-canned responses shaped to make an assertion pass.
func newStatefulSecurityFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// --- Nested tenant resource: POST creates a project under an org, GET
	// reads it back. No vulnerability here -- this is the "valid chain"
	// baseline the other properties build on top of.
	mux.HandleFunc("/organizations/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/organizations/")
		parts := strings.Split(rest, "/")
		switch {
		case len(parts) == 2 && parts[1] == "projects" && r.Method == http.MethodPost:
			org := parts[0]
			w.Header().Set("Location", "/organizations/"+org+"/projects/proj-1")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"visibility":"public"}`))
		case len(parts) == 3 && parts[1] == "projects" && r.Method == http.MethodGet:
			org, proj := parts[0], parts[2]
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"` + proj + `","org":"` + org + `"}`))
		case len(parts) == 2 && parts[1] == "users" && r.Method == http.MethodPost:
			// VULNERABLE (mass assignment): blindly echoes back whatever was
			// posted, including any over-posted privileged field -- a naive
			// "return what you submitted" create handler.
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	})

	// --- Cross-tenant read: returns the document's full content regardless
	// of who asks (VULNERABLE: BOLA). No ownership/tenant check at all.
	mux.HandleFunc("/documents/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/documents/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"` + id + `","title":"Q4 board minutes","body":"confidential financial detail for document ` + id + `"}`))
	})

	// --- Deleted-resource-still-mutable / ignored ETag: DELETE marks the
	// widget gone; GET returns a real ETag; PUT (VULNERABLE) succeeds
	// unconditionally -- ignores both the deleted flag and any If-Match header.
	deleted := map[string]bool{}
	mux.HandleFunc("/widgets/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/widgets/")
		switch r.Method {
		case http.MethodDelete:
			deleted[id] = true
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			w.Header().Set("ETag", `"widget-etag-1"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"` + id + `","name":"gadget"}`))
		case http.MethodPut:
			// VULNERABLE: no deleted-state check, no If-Match enforcement.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"` + id + `","name":"renamed"}`))
		}
	})

	// --- Approval bypass: /invoices creates a draft; /invoices/1/pay
	// (VULNERABLE) flips straight to paid with no check that it was ever sent.
	mux.HandleFunc("/invoices", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"1","status":"draft"}`))
	})
	mux.HandleFunc("/invoices/1/pay", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","status":"paid"}`))
	})

	// --- Double payment: every POST (VULNERABLE) creates a NEW payment id,
	// ignoring any Idempotency-Key -- a verbatim replay is never recognized.
	paymentSeq := 0
	mux.HandleFunc("/payments", func(w http.ResponseWriter, r *http.Request) {
		paymentSeq++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"pay-` + itoaTest(paymentSeq) + `","amount":100}`))
	})

	// --- Async import job: submit returns 202 + Retry-After; poll eventually
	// reports a terminal status. Correctly-behaving (contrast case, not a bug).
	mux.HandleFunc("/imports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"job-1","status":"pending"}`))
	})
	mux.HandleFunc("/imports/job-1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"job-1","status":"completed"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// itoaTest avoids pulling in strconv just for one small counter-to-string
// conversion in the fixture server above.
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// newStatefulSecuritySuiteFuzzer builds a real Fuzzer wired to srv -- every
// map recordAdversarialFinding/recordAccessControlFinding/recordResourceGraphStep/
// the oracle enqueue+handle functions touch, matching the established
// newAdversarialTestFuzzer/newMassAssignTestFuzzer pattern (adversarial_test.go/
// oracle_test.go), plus f.client/f.target so f.sendOne performs real round trips.
func newStatefulSecuritySuiteFuzzer(t *testing.T, srv *httptest.Server) *Fuzzer {
	t.Helper()
	dir := t.TempDir()
	uniqW, err := NewJSONLWriter(filepath.Join(dir, "unique.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	return &Fuzzer{
		client:                srv.Client(),
		target:                srv.URL,
		meta:                  map[int]TemplateMeta{},
		tmplEPKey:             map[int]string{},
		endpointStats:         map[string]*EndpointStats{},
		resourceGraph:         newResourceGraph(ResourceGraphLimits{}),
		oracleQueue:           make([]WorkItem, 0, 16),
		accessProbeCount:      map[string]int{},
		aclSeen:               map[string]struct{}{},
		adversarialProbeCount: map[string]int{},
		adversarialSeen:       map[string]struct{}{},
		authRequiredEndpoints: map[string]int{},
		raceBurstSuccess:      map[string]int{},
		raceBurstSeen:         map[string]int{},
		raceBurstEvaluated:    map[string]struct{}{},
		uniqueWriter:          uniqW,
		identities: []AuthIdentity{
			{Name: "alice", Token: "alice-tok"},
			{Name: "mallory", Token: "mallory-tok"},
		},
		cfg: config.Config{
			ResourceGraphEnabled:       true,
			ResourceGraphMinConfidence: 0,
			AccessProbe:                true,
			ProbeBOLA:                  true,
			ProbeMassAssign:            true,
			ProbeStaleObject:           true,
			ProbeStaleETag:             true,
			ProbeWorkflowBypass:        true,
			ProbeIdempotency:           true,
			AccessProbeMaxPerEndpoint:  10,
			AccessProbeQueueMax:        64,
			AccessProbeProb:            1.0,
		},
	}
}

// ---------------------------------------------------------------------------
// 1. Nested tenant resource -- chain depth + producer-binding provenance +
//    parent/tenant relations, all from real HTTP responses.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_NestedTenantChainDepthAndProducerBinding(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/organizations/{param}/projects/{param}"}
	seqID := "seq-tenant-1"
	seqState := &SequenceState{ID: seqID}

	// Depth 1: create the org's first project against the REAL server.
	create := WorkItem{Method: "POST", Path: "/organizations/acme/projects", Identity: "alice", SeqState: seqState}
	res1 := f.sendOne(create)
	if res1.Status != http.StatusCreated {
		t.Fatalf("expected 201 from fixture, got %d", res1.Status)
	}
	seqState.History = append(seqState.History, SequenceStep{Method: create.Method, Path: create.Path, Status: res1.Status})
	f.recordResourceGraphStep(create, res1, seqID, "POST /organizations/acme/projects")

	orgInst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "organization", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("organization", "scalar", "acme")})
	projInst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "project", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("project", "scalar", "proj-1")})
	if orgInst == nil || projInst == nil {
		t.Fatalf("expected both organization and project instances recorded from a real Location header response, org=%v prj=%v", orgInst, projInst)
	}
	if projInst.ParentKey != orgInst.Canonical.graphKey() || projInst.TenantKey != orgInst.Canonical.graphKey() {
		t.Fatalf("expected project's parent/tenant to resolve to the organization, got parent=%q tenant=%q want %q",
			projInst.ParentKey, projInst.TenantKey, orgInst.Canonical.graphKey())
	}

	// Depth 2: a real tenant-scoped follow-up GET, substituting the value the
	// resource graph learned from step 1's own response -- and recording the
	// producer-consumer binding the same way enqueueSequenceFollowups
	// (sequence.go) does at its own real call site.
	value, fromGraph, ok, pickedInst := f.pickFollowupPathValue(1, nil, orgInst.Canonical.graphKey())
	if !ok || !fromGraph || pickedInst == nil {
		t.Fatalf("expected a tenant-scoped graph hit for the follow-up, got ok=%v fromGraph=%v", ok, fromGraph)
	}
	followUpPath := "/organizations/acme/projects/" + value
	f.recordProducerConsumerBinding(ProducerConsumerBinding{
		ProducerOp: pickedInst.SourceOperation, ProducerField: pickedInst.Canonical.SourcePath,
		ConsumerOp: "GET " + normalizePath(followUpPath), ConsumerField: "path",
		ResourceType: pickedInst.ResourceType, Value: value, SequenceID: seqID,
	})
	read := WorkItem{Method: "GET", Path: followUpPath, Identity: "alice", SeqState: seqState}
	res2 := f.sendOne(read)
	if res2.Status != http.StatusOK {
		t.Fatalf("expected 200 from the real tenant-scoped follow-up, got %d", res2.Status)
	}
	seqState.History = append(seqState.History, SequenceStep{Method: read.Method, Path: read.Path, Status: res2.Status})

	if len(seqState.History) != 2 {
		t.Fatalf("expected a 2-step chain depth, got %d: %+v", len(seqState.History), seqState.History)
	}

	bindings := f.bindingsForSequence(seqID)
	if len(bindings) != 1 {
		t.Fatalf("expected exactly 1 producer-consumer binding recorded for this sequence, got %d: %+v", len(bindings), bindings)
	}
	if bindings[0].Value != value || bindings[0].ResourceType != "project" {
		t.Fatalf("expected the binding to record the real substituted project value, got %+v", bindings[0])
	}
}

// ---------------------------------------------------------------------------
// 2. Cross-tenant read (BOLA) -- a real cross-identity replay.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_CrossTenantReadIsBOLA(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)

	origin := WorkItem{Method: "GET", Path: "/documents/1", Identity: "alice"}
	res := f.sendOne(origin)
	if res.Status != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Status)
	}
	f.maybeEnqueueAccessProbes(res)
	if len(f.oracleQueue) == 0 {
		t.Fatal("expected at least one BOLA probe enqueued for a concrete-resource-ID GET by an authed identity")
	}

	// Send every enqueued probe for real and dispatch through the real
	// handleResult -- a genuine replay under a different identity, not a
	// fabricated result standing in for one.
	for _, probe := range f.oracleQueue {
		probeRes := f.sendOne(probe)
		f.handleResult(probeRes)
	}

	if f.accessFindings != 1 {
		t.Fatalf("expected 1 BOLA finding from the real cross-identity replay, got %d: %+v", f.accessFindings, f.findings)
	}
	reasons, _ := f.findings[0].Triage["reasons"].([]string)
	found := false
	for _, r := range reasons {
		if r == "bola_identical_cross_identity_response" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected bola_identical_cross_identity_response, got reasons=%v", reasons)
	}
}

// ---------------------------------------------------------------------------
// 3. Deleted-resource-still-mutable
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_DeletedResourceStillMutable(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "PUT", Norm: "/widgets/{param}"}
	seqID := "seq-stale-1"

	del := WorkItem{Method: "DELETE", Path: "/widgets/w1"}
	delRes := f.sendOne(del)
	if delRes.Status != http.StatusNoContent {
		t.Fatalf("expected 204 from real DELETE, got %d", delRes.Status)
	}
	f.recordResourceGraphStep(del, delRes, seqID, "DELETE /widgets/w1")

	put := WorkItem{Method: "PUT", Path: "/widgets/w1", Body: `{"name":"renamed"}`}
	putRes := f.sendOne(put)
	if putRes.Status != http.StatusOK {
		t.Fatalf("expected the vulnerable fixture to accept a write on a deleted resource with 200, got %d", putRes.Status)
	}
	f.recordResourceGraphStep(put, putRes, seqID, "PUT /widgets/w1")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 stale-object finding (update-after-delete), got %d: %+v", f.adversarialFindings, f.findings)
	}
	tr := f.findings[0].Triage
	if tr["oracle"] != "stale_object" || tr["severity_score"] != 8 {
		t.Fatalf("expected a high-severity stale_object finding, got %+v", tr)
	}
}

// ---------------------------------------------------------------------------
// 4. Approval bypass (workflow-state bypass)
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_ApprovalBypassWorkflow(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/invoices"}
	f.meta[2] = TemplateMeta{
		Method: "POST", Norm: "/invoices/{param}/pay",
		XStateTransition: &XStateTransitionHint{From: "sent", Action: "pay", To: "paid"},
	}
	seqID := "seq-approval-1"

	create := WorkItem{Method: "POST", Path: "/invoices"}
	createRes := f.sendOne(create)
	if createRes.Status != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createRes.Status)
	}
	f.recordResourceGraphStep(create, createRes, seqID, "POST /invoices")

	// Attack: pay() succeeds despite the invoice only ever having been "draft",
	// never "sent" -- skipping the approval step entirely.
	pay := WorkItem{Method: "POST", Path: "/invoices/1/pay", TemplateID: 2}
	payRes := f.sendOne(pay)
	if payRes.Status != http.StatusOK {
		t.Fatalf("expected the vulnerable fixture to accept the bypassed transition with 200, got %d", payRes.Status)
	}
	f.recordResourceGraphStep(pay, payRes, seqID, "POST /invoices/1/pay")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 workflow-bypass finding, got %d: %+v", f.adversarialFindings, f.findings)
	}
	if f.findings[0].Triage["oracle"] != "workflow_bypass" {
		t.Fatalf("expected oracle=workflow_bypass, got %+v", f.findings[0].Triage)
	}
}

// ---------------------------------------------------------------------------
// 5. Ignored ETag (optimistic locking not enforced) -- a real probe replay.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_IgnoredETagOptimisticLocking(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "PUT", Norm: "/widgets/{param}"}

	get := WorkItem{Method: "GET", Path: "/widgets/w1"}
	getRes := f.sendOne(get)
	if getRes.Status != http.StatusOK {
		t.Fatalf("expected 200, got %d", getRes.Status)
	}
	f.recordResourceGraphStep(get, getRes, "seq-etag-1", "GET /widgets/w1")

	put := WorkItem{Method: "PUT", Path: "/widgets/w1", Body: `{"name":"renamed"}`}
	putRes := f.sendOne(put)
	f.maybeEnqueueStaleETagProbe(putRes)
	if len(f.oracleQueue) != 1 {
		t.Fatalf("expected 1 stale-ETag probe enqueued now that a real ETag is known, got %d", len(f.oracleQueue))
	}

	probeRes := f.sendOne(f.oracleQueue[0])
	if probeRes.Status != http.StatusOK {
		t.Fatalf("expected the vulnerable fixture to accept a write with a fabricated stale If-Match, got %d", probeRes.Status)
	}
	f.handleResult(probeRes)

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 stale-ETag finding, got %d: %+v", f.adversarialFindings, f.findings)
	}
	if f.findings[0].Triage["oracle"] != "stale_etag" {
		t.Fatalf("expected oracle=stale_etag, got %+v", f.findings[0].Triage)
	}
}

// ---------------------------------------------------------------------------
// 6. Double payment (idempotency-replay) -- a real verbatim replay.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_DoublePaymentIdempotency(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)

	create := WorkItem{Method: "POST", Path: "/payments", Headers: map[string]string{"Idempotency-Key": "idem-abc"}, Body: `{"amount":100}`}
	res := f.sendOne(create)
	if res.Status != http.StatusCreated {
		t.Fatalf("expected 201, got %d", res.Status)
	}
	f.maybeEnqueueIdempotencyReplayProbe(res)
	if len(f.oracleQueue) != 1 {
		t.Fatalf("expected 1 idempotency-replay probe enqueued, got %d", len(f.oracleQueue))
	}

	// Real verbatim replay -- same headers (including the SAME Idempotency-Key), same body.
	replayRes := f.sendOne(f.oracleQueue[0])
	f.handleResult(replayRes)

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 idempotency finding (the replay created a second, different payment id), got %d: %+v", f.adversarialFindings, f.findings)
	}
	reasons, _ := f.findings[0].Triage["reasons"].([]string)
	hasNotEnforced := false
	for _, r := range reasons {
		if r == "idempotency_not_enforced" {
			hasNotEnforced = true
		}
	}
	if !hasNotEnforced {
		t.Fatalf("expected idempotency_not_enforced among reasons, got %v", reasons)
	}
}

// ---------------------------------------------------------------------------
// 7. Async import job (submit -> poll -> terminal) -- correctly-behaving
//    contrast case, proving the async model tracks real submit/poll state.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_AsyncImportJobPollToTerminal(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)
	seqID := "seq-async-1"

	submit := WorkItem{Method: "POST", Path: "/imports"}
	submitRes := f.sendOne(submit)
	if !isAsyncSubmission(submitRes.Status, submitRes.Headers) {
		t.Fatalf("expected the real 202+Retry-After response to be recognized as an async submission, status=%d headers=%v", submitRes.Status, submitRes.Headers)
	}
	f.recordResourceGraphStep(submit, submitRes, seqID, "POST /imports")

	jobInst := f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "import", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("import", "scalar", "job-1")})
	if jobInst == nil {
		t.Fatal("expected the job id to be extracted and recorded as a resource instance")
	}
	if !isAsyncOperationPending(jobInst) {
		t.Fatalf("expected the freshly-submitted job to be pending, got Attributes=%v", jobInst.Attributes)
	}

	poll := WorkItem{Method: "GET", Path: "/imports/job-1"}
	pollRes := f.sendOne(poll)
	if pollRes.Status != http.StatusOK {
		t.Fatalf("expected 200 from the real poll, got %d", pollRes.Status)
	}
	f.recordResourceGraphStep(poll, pollRes, seqID, "GET /imports/job-1")

	jobInst = f.resourceGraph.getInstance(ResourceIdentity{ResourceType: "import", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("import", "scalar", "job-1")})
	if isAsyncOperationPending(jobInst) {
		t.Fatalf("expected the job to no longer be pending after a real poll reported status=completed, got Attributes=%v", jobInst.Attributes)
	}
}

// ---------------------------------------------------------------------------
// 8. Privileged mass-assignment, valid-chain-gated -- single-factor attack
//    differentiation: the ONLY thing that differs between the two identities
//    below is whether the resource graph has already confirmed their org.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_PrivilegedMassAssignmentInValidChainContext(t *testing.T) {
	srv := newStatefulSecurityFixtureServer(t)
	f := newStatefulSecuritySuiteFuzzer(t, srv)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/organizations/{param}/projects/{param}"}
	f.meta[2] = TemplateMeta{Method: "POST", Norm: "/organizations/{param}/users"}

	// Unconfirmed org ("globex" was never established via a real prior
	// response) -- the probe must be suppressed entirely.
	unconfirmed := WorkItem{Method: "POST", Path: "/organizations/globex/users", Identity: "alice", TemplateID: 2, Body: `{"name":"eve"}`}
	unconfirmedRes := f.sendOne(unconfirmed)
	f.maybeEnqueueMassAssignProbe(unconfirmedRes)
	if len(f.oracleQueue) != 0 {
		t.Fatalf("expected the probe suppressed for an unconfirmed org (single-factor: no valid-chain context), got %d enqueued", len(f.oracleQueue))
	}

	// Now establish "acme" for real, via a genuine prior create step.
	create := WorkItem{Method: "POST", Path: "/organizations/acme/projects", Identity: "alice"}
	createRes := f.sendOne(create)
	f.recordResourceGraphStep(create, createRes, "seq-massassign-1", "POST /organizations/acme/projects")

	confirmed := WorkItem{Method: "POST", Path: "/organizations/acme/users", Identity: "alice", TemplateID: 2, Body: `{"name":"carol"}`}
	confirmedRes := f.sendOne(confirmed)
	f.maybeEnqueueMassAssignProbe(confirmedRes)
	if len(f.oracleQueue) != 1 {
		t.Fatalf("expected the probe to fire now that acme is a real, confirmed org (the ONLY factor that changed), got %d enqueued", len(f.oracleQueue))
	}

	probeRes := f.sendOne(f.oracleQueue[0])
	f.handleResult(probeRes)

	if f.accessFindings != 1 {
		t.Fatalf("expected 1 mass-assignment finding from the real over-posted, echoed-back response, got %d: %+v", f.accessFindings, f.findings)
	}
	if f.findings[0].Triage["oracle"] != oracleKindMassAssign {
		t.Fatalf("expected oracle=%s, got %+v", oracleKindMassAssign, f.findings[0].Triage)
	}
}

// ---------------------------------------------------------------------------
// 9. Minimized-chain validity -- proves the whole-chain minimizer's shrunk
//    output actually reaches CrashFinding (report.go/sarif.go's consumer),
//    and that Bindings correctly filters to just this crash's own sequence.
// ---------------------------------------------------------------------------

func TestStatefulSecurityFixture_MinimizedChainRoundTripsThroughCrashFinding(t *testing.T) {
	// Same consume-once-flag fixture design as minimize_test.go's
	// TestMinimizeChainCandidateDropsGenuinelyNonEssentialStep: /crash only
	// 500s if /setup was hit earlier in the SAME replay, so a correct
	// minimizer keeps /setup and drops the unrelated /noise step.
	var lastWasSetup bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/setup":
			lastWasSetup = true
			w.WriteHeader(http.StatusOK)
		case "/noise":
			w.WriteHeader(http.StatusOK)
		case "/crash":
			if lastWasSetup {
				lastWasSetup = false
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	f := newStatefulSecuritySuiteFuzzer(t, srv)
	crashW, err := NewJSONLWriter(filepath.Join(t.TempDir(), "crashes.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	f.crashWriter = crashW
	f.uniqueCrashKeys = map[string]struct{}{}
	f.crashesBySequence = map[string][]string{}
	f.crashBoost = map[string]int{}
	f.crashBoostCount = map[string]int{}
	f.cfg.MinimizeCrash = true
	f.cfg.MinimizeChain = true
	f.cfg.MinimizeMaxProbes = 100

	seqID := "seq-minimize-1"
	// Seed bindings for TWO different sequences -- only the matching one
	// should end up on this crash's own finding.
	f.producerConsumerBindings = []ProducerConsumerBinding{
		{ProducerOp: "POST /setup", ConsumerOp: "GET /crash", ResourceType: "widget", Value: "w1", SequenceID: seqID},
		{ProducerOp: "POST /other", ConsumerOp: "GET /other", ResourceType: "widget", Value: "w2", SequenceID: "unrelated-seq"},
	}

	res := SendResult{
		Item: WorkItem{
			Method: "GET", Path: "/crash",
			SeqState: &SequenceState{ID: seqID, History: []SequenceStep{
				{Method: "GET", Path: "/setup"},
				{Method: "GET", Path: "/noise"},
				{Method: "GET", Path: "/crash"},
			}},
		},
		Status: 500, ExceptionType: "BoomException", Body: "boom",
	}

	f.recordCrash(res)

	if len(f.findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(f.findings))
	}
	fd := f.findings[0]

	if len(fd.ChainTrace) != 2 {
		t.Fatalf("expected the minimized 2-step chain (noise dropped) to reach CrashFinding.ChainTrace, got %d steps: %+v", len(fd.ChainTrace), fd.ChainTrace)
	}
	for _, step := range fd.ChainTrace {
		if step.Path == "/noise" {
			t.Fatalf("expected /noise dropped from the minimized chain that reached the report, got %+v", fd.ChainTrace)
		}
	}
	if fd.ChainTrace[0].Path != "/setup" || fd.ChainTrace[len(fd.ChainTrace)-1].Path != "/crash" {
		t.Fatalf("expected the essential /setup step to survive and /crash to remain last, got %+v", fd.ChainTrace)
	}

	if len(fd.Bindings) != 1 || fd.Bindings[0].SequenceID != seqID {
		t.Fatalf("expected exactly 1 binding filtered to this crash's own sequence, got %+v", fd.Bindings)
	}
}
