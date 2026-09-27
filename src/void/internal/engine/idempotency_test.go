package engine

import (
	"testing"
	"void/internal/config"
)

func newIdempotencyTestFuzzer() *Fuzzer {
	return &Fuzzer{
		cfg: config.Config{
			AccessProbe:               true,
			ProbeIdempotency:          true,
			AccessProbeProb:           1.0,
			AccessProbeMaxPerEndpoint: 10,
			AccessProbeQueueMax:       256,
		},
		meta:                  map[int]TemplateMeta{},
		accessProbeCount:      map[string]int{},
		adversarialProbeCount: map[string]int{},
		adversarialSeen:       map[string]struct{}{},
		oracleQueue:           make([]WorkItem, 0, 8),
	}
}

func TestMaybeEnqueueIdempotencyReplayProbe_EnqueuesVerbatimReplay(t *testing.T) {
	f := newIdempotencyTestFuzzer()
	res := SendResult{
		Item: WorkItem{
			Method: "POST", Path: "/orders", Identity: "alice",
			Body:    `{"amount":100}`,
			Headers: map[string]string{"Idempotency-Key": "abc-123"},
		},
		Status: 201, Body: `{"id":"order-1","amount":100}`,
	}
	f.maybeEnqueueIdempotencyReplayProbe(res)

	if len(f.oracleQueue) != 1 {
		t.Fatalf("expected 1 probe enqueued, got %d", len(f.oracleQueue))
	}
	p := f.oracleQueue[0]
	if p.OracleKind != oracleKindIdempotency {
		t.Fatalf("expected OracleKind=%s, got %q", oracleKindIdempotency, p.OracleKind)
	}
	if p.Body != res.Item.Body {
		t.Fatalf("expected the replay body to be verbatim identical, got %q want %q", p.Body, res.Item.Body)
	}
	if p.Headers["Idempotency-Key"] != "abc-123" {
		t.Fatalf("expected the client's own idempotency-key header preserved verbatim, got %+v", p.Headers)
	}
	if p.OracleOriginFP != "order-1" {
		t.Fatalf("expected the original created id stashed for comparison, got %q", p.OracleOriginFP)
	}
}

func TestMaybeEnqueueIdempotencyReplayProbe_OnlyPOST(t *testing.T) {
	f := newIdempotencyTestFuzzer()
	res := SendResult{Item: WorkItem{Method: "PUT", Path: "/orders/1"}, Status: 200, Body: `{"id":"1"}`}
	f.maybeEnqueueIdempotencyReplayProbe(res)
	if len(f.oracleQueue) != 0 {
		t.Fatalf("expected PUT to never trigger an idempotency probe, got %d", len(f.oracleQueue))
	}
}

func TestMaybeEnqueueIdempotencyReplayProbe_NoOpWithoutExtractableID(t *testing.T) {
	f := newIdempotencyTestFuzzer()
	res := SendResult{Item: WorkItem{Method: "POST", Path: "/orders"}, Status: 204, Body: ""}
	f.maybeEnqueueIdempotencyReplayProbe(res)
	if len(f.oracleQueue) != 0 {
		t.Fatalf("expected no probe when there's no id to compare a replay against, got %d", len(f.oracleQueue))
	}
}

func TestHandleIdempotencyReplayResult_DifferentIDRaisesFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	item := WorkItem{Method: "POST", Path: "/orders", OracleKind: oracleKindIdempotency, OracleOriginFP: "order-1"}
	f.handleIdempotencyReplayResult(SendResult{Item: item, Status: 201, Body: `{"id":"order-2"}`})

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding for a replay that created a DIFFERENT resource, got %d", f.adversarialFindings)
	}
	if f.findings[0].Triage["classification"] != "likely_vuln" {
		t.Fatalf("expected a plain (non-sensitive) create to be classified likely_vuln, got %v", f.findings[0].Triage["classification"])
	}
}

func TestHandleIdempotencyReplayResult_SameIDIsIdempotentNoFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	item := WorkItem{Method: "POST", Path: "/orders", OracleKind: oracleKindIdempotency, OracleOriginFP: "order-1"}
	f.handleIdempotencyReplayResult(SendResult{Item: item, Status: 200, Body: `{"id":"order-1"}`})

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding when the replay correctly returned the SAME id, got %d", f.adversarialFindings)
	}
}

func TestHandleIdempotencyReplayResult_RejectedReplayNoFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	item := WorkItem{Method: "POST", Path: "/orders", OracleKind: oracleKindIdempotency, OracleOriginFP: "order-1"}
	f.handleIdempotencyReplayResult(SendResult{Item: item, Status: 409, Body: `{"error":"duplicate request"}`})

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding when the replay was correctly rejected (409), got %d", f.adversarialFindings)
	}
}

func TestHandleIdempotencyReplayResult_SensitiveActionIsHighSeverity(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.meta[7] = TemplateMeta{Method: "POST", Norm: "/invoices/{param}/refund"}
	item := WorkItem{Method: "POST", Path: "/invoices/1/refund", TemplateID: 7, OracleKind: oracleKindIdempotency, OracleOriginFP: "refund-1"}
	f.handleIdempotencyReplayResult(SendResult{Item: item, Status: 201, Body: `{"id":"refund-2"}`})

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", f.adversarialFindings)
	}
	tr := f.findings[0].Triage
	if tr["classification"] != "likely_vuln_high" || tr["severity_score"] != 9 {
		t.Fatalf("expected a duplicate REFUND to be classified likely_vuln_high/9, got %+v", tr)
	}
}
