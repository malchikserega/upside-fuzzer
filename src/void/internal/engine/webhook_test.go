package engine

import "testing"

func TestIsSoftDisabledAttributes(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		want  bool
	}{
		{"active false", map[string]any{"active": false}, true},
		{"enabled false", map[string]any{"enabled": false}, true},
		{"isActive false (case-insensitive)", map[string]any{"isActive": false}, true},
		{"active true", map[string]any{"active": true}, false},
		{"no relevant field", map[string]any{"name": "hook-1"}, false},
		{"non-bool value ignored", map[string]any{"active": "false"}, false},
		{"nil map", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSoftDisabledAttributes(c.attrs); got != c.want {
				t.Errorf("isSoftDisabledAttributes(%+v) = %v, want %v", c.attrs, got, c.want)
			}
		})
	}
}

func TestEqualFoldASCII(t *testing.T) {
	if !equalFoldASCII("Active", "active") {
		t.Error("expected case-insensitive match")
	}
	if !equalFoldASCII("ISENABLED", "isenabled") {
		t.Error("expected case-insensitive match for all-caps")
	}
	if equalFoldASCII("active", "enabled") {
		t.Error("expected different strings to not match")
	}
	if equalFoldASCII("active", "activee") {
		t.Error("expected different lengths to not match")
	}
}

// ---------------------------------------------------------------------------
// Integration: recordResourceGraphStep detects a disabled-but-triggered webhook
// ---------------------------------------------------------------------------

func TestRecordResourceGraphStep_DisabledWebhookStillTriggersRaisesFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "PATCH", Norm: "/webhooks/{param}"}
	f.meta[2] = TemplateMeta{Method: "POST", Norm: "/webhooks/{param}/trigger"}

	// Disable the webhook via PATCH {"active": false} -- NOT a DELETE.
	disable := WorkItem{Method: "PATCH", Path: "/webhooks/1", TemplateID: 1}
	f.recordResourceGraphStep(disable, SendResult{
		Item: disable, Status: 200, Body: `{"id":"1","active":false}`,
	}, "seq-1", "PATCH /webhooks/1")

	// Trigger it anyway -- succeeds despite being disabled.
	trigger := WorkItem{Method: "POST", Path: "/webhooks/1/trigger", TemplateID: 2}
	f.recordResourceGraphStep(trigger, SendResult{
		Item: trigger, Status: 200, Body: `{"id":"1","delivered":true}`,
	}, "seq-1", "POST /webhooks/1/trigger")

	if f.adversarialFindings != 1 {
		t.Fatalf("expected 1 finding for a disabled webhook that still triggered, got %d: %+v", f.adversarialFindings, f.findings)
	}
	tr := f.findings[0].Triage
	if tr["oracle"] != "disabled_resource_still_active" {
		t.Fatalf("expected oracle=disabled_resource_still_active, got %+v", tr)
	}
	if tr["classification"] != "likely_vuln_high" || tr["severity_score"] != 8 {
		t.Fatalf("expected likely_vuln_high/8, got %+v", tr)
	}
}

func TestRecordResourceGraphStep_EnabledWebhookTriggerNoFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "PATCH", Norm: "/webhooks/{param}"}
	f.meta[2] = TemplateMeta{Method: "POST", Norm: "/webhooks/{param}/trigger"}

	enable := WorkItem{Method: "PATCH", Path: "/webhooks/1", TemplateID: 1}
	f.recordResourceGraphStep(enable, SendResult{Item: enable, Status: 200, Body: `{"id":"1","active":true}`}, "seq-1", "PATCH /webhooks/1")

	trigger := WorkItem{Method: "POST", Path: "/webhooks/1/trigger", TemplateID: 2}
	f.recordResourceGraphStep(trigger, SendResult{Item: trigger, Status: 200, Body: `{"id":"1","delivered":true}`}, "seq-1", "POST /webhooks/1/trigger")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding for a still-enabled webhook, got %d", f.adversarialFindings)
	}
}

func TestRecordResourceGraphStep_DisabledResourceNonTriggerActionNoFinding(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "PATCH", Norm: "/webhooks/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/webhooks/{param}"} // ordinary read, not a trigger verb

	disable := WorkItem{Method: "PATCH", Path: "/webhooks/1", TemplateID: 1}
	f.recordResourceGraphStep(disable, SendResult{Item: disable, Status: 200, Body: `{"id":"1","active":false}`}, "seq-1", "PATCH /webhooks/1")

	read := WorkItem{Method: "GET", Path: "/webhooks/1", TemplateID: 2}
	f.recordResourceGraphStep(read, SendResult{Item: read, Status: 200, Body: `{"id":"1","active":false}`}, "seq-1", "GET /webhooks/1")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected no finding for a harmless read of a disabled resource, got %d", f.adversarialFindings)
	}
}

func TestRecordResourceGraphStep_DisabledWebhookDisabledByFlag(t *testing.T) {
	f := newAdversarialTestFuzzer(t)
	f.cfg.ProbeWorkflowBypass = false
	f.activeIDs = []int{1, 2}
	f.meta[1] = TemplateMeta{Method: "PATCH", Norm: "/webhooks/{param}"}
	f.meta[2] = TemplateMeta{Method: "POST", Norm: "/webhooks/{param}/trigger"}

	disable := WorkItem{Method: "PATCH", Path: "/webhooks/1", TemplateID: 1}
	f.recordResourceGraphStep(disable, SendResult{Item: disable, Status: 200, Body: `{"id":"1","active":false}`}, "seq-1", "PATCH /webhooks/1")
	trigger := WorkItem{Method: "POST", Path: "/webhooks/1/trigger", TemplateID: 2}
	f.recordResourceGraphStep(trigger, SendResult{Item: trigger, Status: 200, Body: `{"id":"1","delivered":true}`}, "seq-1", "POST /webhooks/1/trigger")

	if f.adversarialFindings != 0 {
		t.Fatalf("expected -probe-workflow-bypass=false to suppress the finding, got %d", f.adversarialFindings)
	}
}
