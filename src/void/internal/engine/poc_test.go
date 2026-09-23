package engine

import (
	"os"
	"strings"
	"testing"
	"void/internal/config"
)

func TestRedactedCrashHeaders(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer real.jwt.token",
		"Cookie":        "session=secret",
		"X-Api-Key":     "api-secret",
		"X-Tenant":      "acme",
	}

	got := redactedCrashHeaders(headers)

	if got["Authorization"] != "Bearer ${AUTH_TOKEN:?set AUTH_TOKEN}" {
		t.Fatalf("Authorization was not redacted: %q", got["Authorization"])
	}
	if got["Cookie"] != "${AUTH_COOKIE:?set AUTH_COOKIE}" {
		t.Fatalf("Cookie was not redacted: %q", got["Cookie"])
	}
	if got["X-Api-Key"] != "${X_API_KEY:?set X_API_KEY}" {
		t.Fatalf("X-Api-Key was not redacted: %q", got["X-Api-Key"])
	}
	if got["X-Tenant"] != "acme" {
		t.Fatalf("non-sensitive header changed: %q", got["X-Tenant"])
	}
}

func TestWriteCrashPoC_TraceCommentShowsIdentityAndStatus(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{PocDir: t.TempDir()}, target: "http://localhost:5200"}
	pocItem := WorkItem{
		Method: "GET", Path: "/tasks/42", Identity: "fuzzuser1",
		Trace: []TraceStep{
			{Method: "POST", Path: "/orgs/acme/projects", Identity: "acme-admin", Status: 201},
			{Method: "GET", Path: "/tasks/42", Identity: "fuzzuser1", Status: 500},
		},
	}
	path := f.writeCrashPoC("abc123", SendResult{Status: 500}, pocItem, nil, nil, nil)
	if path == "" {
		t.Fatal("expected a non-empty PoC file path")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	script := string(content)
	if !strings.Contains(script, "[identity=acme-admin]") {
		t.Fatalf("expected the trace comment to show the first step's identity, got:\n%s", script)
	}
	if !strings.Contains(script, "-> 201") {
		t.Fatalf("expected the trace comment to show the first step's real status (201), got:\n%s", script)
	}
	if !strings.Contains(script, "[identity=fuzzuser1]") {
		t.Fatalf("expected the trace comment to show the crashing step's identity, got:\n%s", script)
	}
}

func TestWriteExploitTimeline_ShowsRealIntermediateStatus(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{TimelineDir: t.TempDir()}}
	pocItem := WorkItem{
		Method: "GET", Path: "/tasks/42", Identity: "fuzzuser1",
		Trace: []TraceStep{
			{Method: "POST", Path: "/orgs/acme/projects", Identity: "acme-admin", Status: 201},
			{Method: "GET", Path: "/tasks/42", Identity: "fuzzuser1"},
		},
	}
	path := f.writeExploitTimeline("abc123", SendResult{Status: 500}, pocItem)
	if path == "" {
		t.Fatal("expected a non-empty timeline file path")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	diagram := string(content)
	if !strings.Contains(diagram, "API-->>F: 201") {
		t.Fatalf("expected the real patched status (201) for the intermediate step, not the old 'success/transition' placeholder, got:\n%s", diagram)
	}
	if !strings.Contains(diagram, "(acme-admin)") {
		t.Fatalf("expected the intermediate step's identity in the diagram, got:\n%s", diagram)
	}
	if !strings.Contains(diagram, "API-->>F: 500 crash") {
		t.Fatalf("expected the final step to still show the crash status, got:\n%s", diagram)
	}
}

func TestMaskedAuthContextKeepsFingerprintWithoutSecret(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer header.payload.signature",
		"Cookie":        "session=secret; xsrf=abc",
	}

	ctx := maskedAuthContext("admin", headers)
	if ctx["identity"] != "admin" {
		t.Fatalf("identity = %v", ctx["identity"])
	}
	creds, ok := ctx["credentials"].([]map[string]any)
	if !ok {
		t.Fatalf("credentials type = %T", ctx["credentials"])
	}
	if len(creds) != 2 {
		t.Fatalf("credentials len = %d", len(creds))
	}
	asText := toString(ctx)
	for _, cred := range creds {
		asText += toString(cred)
	}
	if strings.Contains(asText, "header.payload.signature") || strings.Contains(asText, "session=secret") {
		t.Fatalf("auth context leaked secret: %#v", ctx)
	}
	if !strings.Contains(asText, "sha256:") {
		t.Fatalf("auth context missing fingerprint: %#v", ctx)
	}
	if !strings.Contains(asText, "jwt") {
		t.Fatalf("auth context missing token format: %#v", ctx)
	}
}

func TestBuildInlineCurlCommandUsesRedactedAuthPlaceholder(t *testing.T) {
	f := &Fuzzer{target: "http://api:5000"}
	item := WorkItem{Method: "POST", Path: "/devices", Body: `{"name":"x"}`}
	headers := redactedCrashHeaders(map[string]string{
		"Authorization": "Bearer real.jwt.token",
		"Content-Type":  "application/json",
	})

	cmd := f.buildInlineCurlCommand(item, headers)
	if strings.Contains(cmd, "real.jwt.token") {
		t.Fatalf("curl command leaked token: %s", cmd)
	}
	if !strings.Contains(cmd, "Bearer ${AUTH_TOKEN:?set AUTH_TOKEN}") {
		t.Fatalf("curl command missing auth placeholder: %s", cmd)
	}
}
