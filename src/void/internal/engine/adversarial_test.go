package engine

import (
	"path/filepath"
	"testing"
	"void/internal/config"
)

// newAdversarialTestFuzzer builds a Fuzzer with everything
// recordAdversarialFinding/maybeEnqueueStaleETagProbe/recordResourceGraphStep
// actually touch -- real JSONLWriter (JSONLWriter.Write panics on a nil
// receiver, unlike most of this codebase's other nil-safe helpers), a fresh
// resource graph, and the three new probe flags on by default.
func newAdversarialTestFuzzer(t *testing.T) *Fuzzer {
	t.Helper()
	dir := t.TempDir()
	uniqW, err := NewJSONLWriter(filepath.Join(dir, "unique.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	return &Fuzzer{
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
		cfg: config.Config{
			ResourceGraphEnabled:       true,
			ResourceGraphMinConfidence: 0,
			AccessProbe:                true,
			ProbeStaleObject:           true,
			ProbeStaleETag:             true,
			ProbeWorkflowBypass:        true,
			AccessProbeMaxPerEndpoint:  10,
			AccessProbeQueueMax:        64,
		},
	}
}

// ---------------------------------------------------------------------------
// Stale-object (direct detection via recordResourceGraphStep)
// ---------------------------------------------------------------------------

func TestRecordResourceGraphStep_StaleReadRaisesFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}

	// 1. Delete the widget.
	del := WorkItem{Method: "DELETE", Path: "/widgets/1"}
	f.recordResourceGraphStep(del, SendResult{Item: del, Status: 204}, "seq-1", "DELETE /widgets/1")

	// 2. A GET against the SAME (now-deleted) widget unexpectedly succeeds.
	get := WorkItem{Method: "GET", Path: "/widgets/1"}
	f.recordResourceGraphStep(get, SendResult{Item: get, Status: 200, Body: `{"id":"1","name":"gadget"}`}, "seq-1", "GET /widgets/1")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 stale-object finding (stale read), got %d", f.adversarialFindings)
	}
	if len(f.findings) != 1 || f.findings[0].Triage["oracle"] != "stale_object" {
		t.Fatalf("expected a stale_object finding recorded, got %+v", f.findings)
	}
}

func TestRecordResourceGraphStep_UpdateAfterDeleteRaisesHighSeverityFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "PUT", Norm: "/widgets/{param}"}

	del := WorkItem{Method: "DELETE", Path: "/widgets/1"}
	f.recordResourceGraphStep(del, SendResult{Item: del, Status: 204}, "seq-1", "DELETE /widgets/1")

	put := WorkItem{Method: "PUT", Path: "/widgets/1"}
	f.recordResourceGraphStep(put, SendResult{Item: put, Status: 200, Body: `{"id":"1","name":"renamed"}`}, "seq-1", "PUT /widgets/1")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", f.adversarialFindings)
	}
	tr := f.findings[0].Triage
	if tr["severity_score"] != 8 || tr["classification"] != "likely_vuln_high" {
		t.Fatalf("expected update-after-delete to be high severity, got %+v", tr)
	}
}

func TestRecordResourceGraphStep_NormalLifecycleNeverFindings(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/widgets"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}

	create := WorkItem{Method: "POST", Path: "/widgets"}
	f.recordResourceGraphStep(create, SendResult{Item: create, Status: 201, Body: `{"id":"1"}`}, "seq-1", "POST /widgets")
	read := WorkItem{Method: "GET", Path: "/widgets/1"}
	f.recordResourceGraphStep(read, SendResult{Item: read, Status: 200, Body: `{"id":"1"}`}, "seq-1", "GET /widgets/1")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected 0 findings for an ordinary create->read, got %d: %+v", f.adversarialFindings, f.findings)
	}
}

func TestRecordResourceGraphStep_StaleObjectDisabledByFlag(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.cfg.ProbeStaleObject = false
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}

	del := WorkItem{Method: "DELETE", Path: "/widgets/1"}
	f.recordResourceGraphStep(del, SendResult{Item: del, Status: 204}, "seq-1", "DELETE /widgets/1")
	get := WorkItem{Method: "GET", Path: "/widgets/1"}
	f.recordResourceGraphStep(get, SendResult{Item: get, Status: 200, Body: `{"id":"1"}`}, "seq-1", "GET /widgets/1")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected -probe-stale-object=false to suppress the finding entirely, got %d", f.adversarialFindings)
	}
}

// ---------------------------------------------------------------------------
// Stale ETag (active probe)
// ---------------------------------------------------------------------------

func TestMaybeEnqueueStaleETagProbe_EnqueuesWhenVersionKnown(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "PUT", Norm: "/widgets/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"GET /widgets/1", "seq-1", LifecycleReadable, 0.9, RecordInstanceOpts{Version: `"etag-real"`},
	)

	res := SendResult{Item: WorkItem{Method: "PUT", Path: "/widgets/1", Identity: "alice"}, Status: 200}
	f.maybeEnqueueStaleETagProbe(res)

	if len(f.oracleQueue) != 1 {
		t.Fatalf("expected 1 probe enqueued, got %d", len(f.oracleQueue))
	}
	p := f.oracleQueue[0]
	if p.OracleKind != oracleKindStaleETag {
		t.Fatalf("expected OracleKind=%s, got %q", oracleKindStaleETag, p.OracleKind)
	}
	if p.Headers["If-Match"] != staleETagFabricatedValue {
		t.Fatalf("expected the fabricated stale If-Match header, got %q", p.Headers["If-Match"])
	}
	if p.OracleOriginFP != `"etag-real"` {
		t.Fatalf("expected the real known ETag stashed for the finding log, got %q", p.OracleOriginFP)
	}
}

func TestMaybeEnqueueStaleETagProbe_NoOpWithoutKnownVersion(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "PUT", Norm: "/widgets/{param}"}
	// No ETag ever recorded for this instance.
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"GET /widgets/1", "seq-1", LifecycleReadable, 0.9,
	)
	res := SendResult{Item: WorkItem{Method: "PUT", Path: "/widgets/1"}, Status: 200}
	f.maybeEnqueueStaleETagProbe(res)
	if len(f.oracleQueue) != 0 {
		t.Fatalf("expected no probe without a known Version, got %d", len(f.oracleQueue))
	}
}

func TestMaybeEnqueueStaleETagProbe_OnlyMutatingMethods(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/widgets/{param}"}
	f.resourceGraph.recordInstance(
		ResourceIdentity{ResourceType: "widget", IdentityKind: "scalar", NormalizedValue: normalizeResourceValue("widget", "scalar", "1"), RawValue: "1"},
		"GET /widgets/1", "seq-1", LifecycleReadable, 0.9, RecordInstanceOpts{Version: `"etag-real"`},
	)
	res := SendResult{Item: WorkItem{Method: "GET", Path: "/widgets/1"}, Status: 200}
	f.maybeEnqueueStaleETagProbe(res)
	if len(f.oracleQueue) != 0 {
		t.Fatalf("expected GET to never trigger a stale-ETag probe, got %d", len(f.oracleQueue))
	}
}

func TestHandleOracleResult_StaleETagAcceptedRaisesFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	item := WorkItem{Method: "PUT", Path: "/widgets/1", OracleKind: oracleKindStaleETag, OracleOriginFP: `"etag-real"`}
	// 204 No Content, empty body -- must NOT be suppressed by the
	// trivial-body/empty-body guards that gate the BOLA path.
	f.handleOracleResult(SendResult{Item: item, Status: 204, Body: ""})

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding for a stale-ETag write accepted with 204, got %d", f.adversarialFindings)
	}
}

func TestHandleOracleResult_StaleETagRejectedNoFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	item := WorkItem{Method: "PUT", Path: "/widgets/1", OracleKind: oracleKindStaleETag, OracleOriginFP: `"etag-real"`}
	f.handleOracleResult(SendResult{Item: item, Status: 412, Body: "Precondition Failed"})

	if f.adversarialFindings != 0 {
		t.Fatalf("expected 0 findings when the server correctly rejects with 412, got %d", f.adversarialFindings)
	}
}

// ---------------------------------------------------------------------------
// Workflow bypass (direct detection, x-state-transition-gated)
// ---------------------------------------------------------------------------

func TestRecordResourceGraphStep_WorkflowBypassRaisesFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/invoices"}
	f.meta[2] = TemplateMeta{
		Method: "POST", Norm: "/invoices/{param}/pay",
		XStateTransition: &XStateTransitionHint{From: "sent", Action: "pay", To: "paid"},
	}

	// Invoice created with status "draft" (never sent).
	create := WorkItem{Method: "POST", Path: "/invoices"}
	f.recordResourceGraphStep(create, SendResult{Item: create, Status: 201, Body: `{"id":"1","status":"draft"}`}, "seq-1", "POST /invoices")

	// pay() succeeds despite the invoice never having been "sent".
	pay := WorkItem{Method: "POST", Path: "/invoices/1/pay", TemplateID: 2}
	f.recordResourceGraphStep(pay, SendResult{Item: pay, Status: 200, Body: `{"id":"1","status":"paid"}`}, "seq-1", "POST /invoices/1/pay")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 workflow-bypass finding, got %d: %+v", f.adversarialFindings, f.findings)
	}
	tr := f.findings[0].Triage
	if tr["oracle"] != "workflow_bypass" {
		t.Fatalf("expected oracle=workflow_bypass, got %+v", tr)
	}
}

func TestRecordResourceGraphStep_WorkflowBypassNoFindingWhenStateMatches(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/invoices"}
	f.meta[2] = TemplateMeta{
		Method: "POST", Norm: "/invoices/{param}/pay",
		XStateTransition: &XStateTransitionHint{From: "sent", Action: "pay", To: "paid"},
	}

	create := WorkItem{Method: "POST", Path: "/invoices"}
	f.recordResourceGraphStep(create, SendResult{Item: create, Status: 201, Body: `{"id":"1","status":"sent"}`}, "seq-1", "POST /invoices")

	pay := WorkItem{Method: "POST", Path: "/invoices/1/pay", TemplateID: 2}
	f.recordResourceGraphStep(pay, SendResult{Item: pay, Status: 200, Body: `{"id":"1","status":"paid"}`}, "seq-1", "POST /invoices/1/pay")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding when the predecessor state genuinely matched, got %d", f.adversarialFindings)
	}
}

func TestRecordResourceGraphStep_WorkflowBypassNoOpWithoutXStateTransition(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/invoices"}
	f.meta[2] = TemplateMeta{Method: "POST", Norm: "/invoices/{param}/pay"} // no XStateTransition declared

	create := WorkItem{Method: "POST", Path: "/invoices"}
	f.recordResourceGraphStep(create, SendResult{Item: create, Status: 201, Body: `{"id":"1","status":"draft"}`}, "seq-1", "POST /invoices")
	pay := WorkItem{Method: "POST", Path: "/invoices/1/pay", TemplateID: 2}
	f.recordResourceGraphStep(pay, SendResult{Item: pay, Status: 200, Body: `{"id":"1","status":"paid"}`}, "seq-1", "POST /invoices/1/pay")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding without an x-state-transition declaration (Tier 1 only), got %d", f.adversarialFindings)
	}
}

// TestRecordResourceGraphStep_WorkflowBypassDedupsAcrossMultipleCandidatesSameStep
// is a regression test for a real bug found while fixing
// resourceTypeFromEndpointPath (Phase 4 #122): once BOTH the structural "id"
// field extraction AND the request-path route-template match correctly agree
// on the resource type, they produce TWO candidates for the SAME underlying
// resource within one step. Without per-step dedup, the second candidate's
// "prior state" read would observe the FIRST candidate's own already-applied
// recordInstance update (mutated in place) instead of the true prior state --
// both misreporting the violation and double-firing the finding.
func TestRecordResourceGraphStep_WorkflowBypassDedupsAcrossMultipleCandidatesSameStep(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "POST", Norm: "/invoices"}
	f.meta[2] = TemplateMeta{
		Method: "POST", Norm: "/invoices/{param}/pay",
		XStateTransition: &XStateTransitionHint{From: "sent", Action: "pay", To: "paid"},
	}
	// Registering template 2 in activeIDs means the pay step's OWN request
	// path also matches via matchRouteTemplateCandidates, producing a SECOND
	// "invoice" candidate alongside the structural "id" field extraction --
	// exactly the multi-candidate-same-resource shape this test targets.

	create := WorkItem{Method: "POST", Path: "/invoices"}
	f.recordResourceGraphStep(create, SendResult{Item: create, Status: 201, Body: `{"id":"1","status":"draft"}`}, "seq-1", "POST /invoices")
	pay := WorkItem{Method: "POST", Path: "/invoices/1/pay", TemplateID: 2}
	f.recordResourceGraphStep(pay, SendResult{Item: pay, Status: 200, Body: `{"id":"1","status":"paid"}`}, "seq-1", "POST /invoices/1/pay")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected exactly 1 finding despite multiple candidates resolving to the same resource this step, got %d", f.adversarialFindings)
	}
	if got := f.findings[0].Triage["reasons"]; got != nil {
		reasons, _ := got.([]string)
		for _, r := range reasons {
			if r == "actual_state:paid" {
				t.Fatalf("expected the finding to report the TRUE prior state (draft), not this step's own already-applied update (paid): reasons=%v", reasons)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Shared finding sink dedup
// ---------------------------------------------------------------------------

func TestRecordAdversarialFinding_DedupsRepeatedFindings(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	item := WorkItem{Method: "GET", Path: "/widgets/1"}
	res := SendResult{Item: item, Status: 200}
	f.recordAdversarialFinding(item, res, "stale_object", "likely_vuln", 6, []string{"stale_object_stale_read", "widget_already_deleted_this_run"})
	f.recordAdversarialFinding(item, res, "stale_object", "likely_vuln", 6, []string{"stale_object_stale_read", "widget_already_deleted_this_run"})

	if f.adversarialFindings != 1 {
		t.Fatalf("expected the second identical finding to be deduped, got %d", f.adversarialFindings)
	}
}
