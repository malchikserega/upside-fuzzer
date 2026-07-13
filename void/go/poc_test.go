package main

import (
	"strings"
	"testing"
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
