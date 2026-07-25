package main

import (
	"strings"
	"testing"
	"time"
)

func TestPathHasConcreteResourceID(t *testing.T) {
	yes := []string{
		"/organizations/566048da-ed19-4cd3-8e0a-b7e0e1ec4d72/users",
		"/orders/12345",
		"/api/v1/ciphers/9f8e7d6c5b4a3928",
	}
	// Regression: hyphenated route WORDS (no digit) are not resource ids — they
	// previously caused false-positive BOLA findings on non-object endpoints.
	no := []string{
		"/products", "/api/health", "/organizations",
		"/tax/is-country-supported",
		"/two-factor/get-device-verification-settings",
		"/accounts/key-management/key-rotation-data",
		"/emergency-access/granted",
	}
	for _, p := range yes {
		if !pathHasConcreteResourceID(p) {
			t.Errorf("expected %q to be resource-scoped", p)
		}
	}
	for _, p := range no {
		if pathHasConcreteResourceID(p) {
			t.Errorf("expected %q NOT to be resource-scoped", p)
		}
	}
}

func TestLooksLikeErrorBody(t *testing.T) {
	if !looksLikeErrorBody(200, `{"error":"access denied"}`) {
		t.Errorf("error envelope should be detected")
	}
	if looksLikeErrorBody(200, `{"id":42,"name":"alice","email":"a@b.c"}`) {
		t.Errorf("a real object body must not be treated as an error")
	}
}

func TestStripAuthHeaders(t *testing.T) {
	in := map[string]string{"Authorization": "Bearer x", "Cookie": "s=1", "Accept": "application/json"}
	out := stripAuthHeaders(in)
	if _, ok := out["Authorization"]; ok {
		t.Errorf("Authorization must be stripped")
	}
	if _, ok := out["Cookie"]; ok {
		t.Errorf("Cookie must be stripped")
	}
	if out["Accept"] != "application/json" {
		t.Errorf("non-auth headers must be preserved")
	}
}

func TestExploitationSignalsSSTIEvaluated(t *testing.T) {
	// Payload evaluated: product present, expression text absent.
	res := SendResult{
		Item: WorkItem{Method: "GET", Path: "/greet", Body: `{"name":"{{1337*1337}}"}`},
		Body: `{"greeting":"hello 1787569"}`,
	}
	found := false
	for _, s := range exploitationSignals(res) {
		if s == "ssti_evaluated" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ssti_evaluated when the product is reflected")
	}

	// Payload only reflected (not evaluated): expression text present -> no signal.
	res2 := SendResult{
		Item: WorkItem{Method: "GET", Path: "/greet", Body: `{"name":"{{1337*1337}}"}`},
		Body: `{"greeting":"hello {{1337*1337}}"}`,
	}
	for _, s := range exploitationSignals(res2) {
		if s == "ssti_evaluated" {
			t.Errorf("reflected-but-not-evaluated template must not flag ssti")
		}
	}
}

// TestExploitationSignalsSSRFEchoIsNotFlagged is a regression test for a real false
// positive found fuzzing Bitwarden's PUT /settings/domains: a store-then-return endpoint
// (save a user-submitted domain list, respond with the saved list) trivially "leaked
// cloud metadata" under the old marker set, because two of the four body markers were
// themselves literal substrings of the SSRF payload we sent -- so echoing our own input
// back was indistinguishable from the target actually fetching the URL.
func TestExploitationSignalsSSRFEchoIsNotFlagged(t *testing.T) {
	for _, payload := range ssrfMetadataPayloads {
		res := SendResult{
			Item: WorkItem{Method: "PUT", Path: "/settings/domains", Body: `{"equivalentDomains":[["` + payload + `"]]}`},
			Body: `{"equivalentDomains":[["` + payload + `"]],"object":"domains"}`,
		}
		for _, s := range exploitationSignals(res) {
			if s == "ssrf_metadata_reflected" {
				t.Errorf("payload %q: pure echo of the submitted value must not be flagged as SSRF, got signals %v", payload, exploitationSignals(res))
			}
		}
	}
}

// TestExploitationSignalsSSRFRealMetadataIsFlagged verifies genuine cloud-metadata-shaped
// content in the response -- content the target could only have produced by actually
// fetching the URL, not by echoing what we sent -- still fires the oracle.
func TestExploitationSignalsSSRFRealMetadataIsFlagged(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		body    string
	}{
		{"aws metadata directory listing", "http://169.254.169.254/latest/meta-data/",
			`{"proxyResponse":"ami-id\nami-launch-index\nhostname\ninstance-id\ninstance-type\n"}`},
		{"aws temp credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			`{"proxyResponse":"{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"...\",\"Token\":\"...\"}"}`},
		{"gcp service account", "http://metadata.google.internal/computeMetadata/v1/",
			`{"proxyResponse":"service-accounts/\nnumeric-project-id\n"}`},
	}
	for _, c := range cases {
		res := SendResult{
			Item: WorkItem{Method: "PUT", Path: "/proxy/fetch", Body: `{"url":"` + c.payload + `"}`},
			Body: c.body,
		}
		found := false
		for _, s := range exploitationSignals(res) {
			if s == "ssrf_metadata_reflected" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected ssrf_metadata_reflected for genuine metadata content, got none", c.name)
		}
	}
}

func TestMergePrivilegeFieldsJSON(t *testing.T) {
	body, injected, ok := mergePrivilegeFieldsJSON(`{"name":"alice","email":"a@b.c"}`)
	if !ok || len(injected) == 0 {
		t.Fatalf("expected a mergeable object with injected fields, got ok=%v injected=%v", ok, injected)
	}
	if !strings.Contains(body, `"isAdmin":true`) {
		t.Errorf("merged body should over-post isAdmin: %s", body)
	}

	// Existing privileged keys must not be clobbered.
	body2, injected2, ok2 := mergePrivilegeFieldsJSON(`{"isAdmin":false}`)
	if !ok2 {
		t.Fatalf("expected ok for object with an existing key")
	}
	for _, f := range injected2 {
		if f == "isAdmin" {
			t.Errorf("must not re-inject an existing isAdmin key")
		}
	}
	if strings.Contains(body2, `"isAdmin":true`) {
		t.Errorf("existing isAdmin:false must be preserved, not overwritten")
	}

	if _, _, ok := mergePrivilegeFieldsJSON(`[1,2,3]`); ok {
		t.Errorf("a JSON array is not a mergeable object")
	}
	if _, _, ok := mergePrivilegeFieldsJSON(`not json`); ok {
		t.Errorf("non-JSON must not be mergeable")
	}
}

func TestReflectedPrivilegeField(t *testing.T) {
	if got := reflectedPrivilegeField(`{"id":7,"name":"x","isAdmin":true}`); got != "isAdmin" {
		t.Errorf("expected isAdmin reflection, got %q", got)
	}
	if got := reflectedPrivilegeField(`{ "permissions" : ["*"] }`); got != "permissions" {
		t.Errorf("whitespace-insensitive match expected, got %q", got)
	}
	// Injected value NOT reflected -> no finding.
	if got := reflectedPrivilegeField(`{"isAdmin":false}`); got != "" {
		t.Errorf("isAdmin:false must not count as accepted, got %q", got)
	}
	if got := reflectedPrivilegeField(`{"name":"x"}`); got != "" {
		t.Errorf("no privileged field present, got %q", got)
	}
}

func TestMarkAuthRequiredStrength(t *testing.T) {
	f := &Fuzzer{authRequiredEndpoints: map[string]int{}}
	k := endpointKey("GET", normalizeEndpointPath("/orders/123"))

	// A 401/403 to an authenticated-but-unauthorized caller = weak evidence (1).
	f.markAuthRequired("GET", "/orders/123", false)
	if f.authRequiredEndpoints[k] != 1 {
		t.Fatalf("weak evidence should be strength 1, got %d", f.authRequiredEndpoints[k])
	}
	// Same endpoint template, this time rejecting an unauthenticated caller = strong (2).
	f.markAuthRequired("GET", "/orders/456", true)
	if f.authRequiredEndpoints[k] != 2 {
		t.Fatalf("unauth rejection should upgrade to strength 2, got %d", f.authRequiredEndpoints[k])
	}
	// A later weak observation must not downgrade the strong evidence.
	f.markAuthRequired("GET", "/orders/789", false)
	if f.authRequiredEndpoints[k] != 2 {
		t.Errorf("weak observation must not downgrade strong evidence, got %d", f.authRequiredEndpoints[k])
	}
	// A never-rejecting (public) endpoint has zero evidence -> auth-bypass won't fire.
	pub := endpointKey("GET", normalizeEndpointPath("/public/status"))
	if f.authRequiredEndpoints[pub] != 0 {
		t.Errorf("a public endpoint should have no auth-required evidence")
	}
}

func TestApplyProfileGatesIndividualOracles(t *testing.T) {
	cfg := Config{Profile: "fast", ProbeBOLA: true, ProbeAuthBypass: true, ProbeMassAssign: true}
	applyProfile(&cfg, map[string]bool{})
	if cfg.ProbeBOLA || cfg.ProbeAuthBypass || cfg.ProbeMassAssign {
		t.Errorf("fast profile should disable all three access-control probes")
	}
	// Explicitly keeping BOLA on survives the fast profile.
	cfg2 := Config{Profile: "fast", ProbeBOLA: true}
	applyProfile(&cfg2, map[string]bool{"probe-bola": true})
	if !cfg2.ProbeBOLA {
		t.Errorf("explicit -probe-bola=true must survive the fast profile")
	}
}

func TestApplyProfileRespectsExplicitFlags(t *testing.T) {
	// security profile turns access-probe on...
	cfg := Config{Profile: "security"}
	applyProfile(&cfg, map[string]bool{})
	if !cfg.AccessProbe {
		t.Errorf("security profile should enable access-probe")
	}
	// ...but an explicitly-set flag wins over the profile.
	cfg2 := Config{Profile: "security", AccessProbe: false}
	applyProfile(&cfg2, map[string]bool{"access-probe": true})
	if cfg2.AccessProbe {
		t.Errorf("explicit -access-probe=false must override the security profile")
	}
	// fast profile disables the oracles.
	cfg3 := Config{Profile: "fast", InjectionOracle: true, AccessProbe: true}
	applyProfile(&cfg3, map[string]bool{})
	if cfg3.InjectionOracle || cfg3.AccessProbe {
		t.Errorf("fast profile should disable oracles when not explicitly set")
	}
}

func TestIsTimeBasedSQLiHit(t *testing.T) {
	f := &Fuzzer{baselineLatMS: 120}
	f.cfg.InjectionOracle = true
	f.cfg.SQLiTimeThresholdSec = 1.5

	slow := SendResult{
		Item:    WorkItem{Method: "GET", Path: "/p", Body: "1' AND SLEEP(2)-- -", MutationLabel: "mcat_sqli"},
		Latency: 2100 * time.Millisecond,
	}
	if !f.isTimeBasedSQLiHit(slow) {
		t.Errorf("a 2.1s sleep payload over a 120ms baseline should flag time-based SQLi")
	}

	fast := slow
	fast.Latency = 90 * time.Millisecond
	if f.isTimeBasedSQLiHit(fast) {
		t.Errorf("a fast response must not flag time-based SQLi")
	}

	nonSleep := SendResult{
		Item:    WorkItem{Method: "GET", Path: "/p", Body: "' OR '1'='1", MutationLabel: "mcat_sqli"},
		Latency: 3 * time.Second,
	}
	if f.isTimeBasedSQLiHit(nonSleep) {
		t.Errorf("a non-sleep payload must not flag time-based SQLi even if slow")
	}
}

// TestSwapPathSegmentCase covers the Top-20 #18 route-case differential probe.
func TestSwapPathSegmentCase(t *testing.T) {
	if got := swapPathSegmentCase("/orders/123"); got != "/Orders/123" {
		t.Errorf("expected /Orders/123, got %q", got)
	}
	// No letter anywhere to flip -> unchanged.
	if got := swapPathSegmentCase("/123/456"); got != "/123/456" {
		t.Errorf("expected an all-numeric path to be unchanged, got %q", got)
	}
	// Query string must be preserved verbatim.
	if got := swapPathSegmentCase("/orders/123?x=1"); got != "/Orders/123?x=1" {
		t.Errorf("expected query string preserved, got %q", got)
	}
}

// TestLastPathSegmentAndAppendQueryParam covers the Top-20 #18 param-location
// differential probe's building blocks.
func TestLastPathSegmentAndAppendQueryParam(t *testing.T) {
	if got := lastPathSegment("/orders/123"); got != "123" {
		t.Errorf("expected 123, got %q", got)
	}
	if got := lastPathSegment("/orders/123/"); got != "123" {
		t.Errorf("expected trailing slash stripped, got %q", got)
	}
	if got := lastPathSegment("/orders/123?x=1"); got != "123" {
		t.Errorf("expected query string stripped, got %q", got)
	}
	if got := appendQueryParam("/orders/123", "id", "123"); got != "/orders/123?id=123" {
		t.Errorf("expected ?id=123 appended, got %q", got)
	}
	if got := appendQueryParam("/orders/123?x=1", "id", "123"); got != "/orders/123?x=1&id=123" {
		t.Errorf("expected &id=123 appended to an existing query, got %q", got)
	}
}

// TestMaybeEnqueueDifferentialProbesGatedOnStrongAuthEvidence verifies the
// Top-20 #18 differential oracle only fires with STRONG evidence the endpoint
// enforces auth (authRequiredEndpoints strength 2) -- weak evidence (strength
// 1, "rejected someone" but not necessarily a truly unauthenticated caller)
// must not trigger it, since that's exactly what distinguishes this oracle
// from the plain authbypass replay.
func TestMaybeEnqueueDifferentialProbesGatedOnStrongAuthEvidence(t *testing.T) {
	epKey := endpointKey("GET", normalizeEndpointPath("/orders/123"))
	mkFuzzer := func(strength int) *Fuzzer {
		return &Fuzzer{
			cfg: Config{
				AccessProbe:               true,
				ProbeDifferential:         true,
				AccessProbeProb:           1.0,
				AccessProbeMaxPerEndpoint: 10,
				AccessProbeQueueMax:       256,
			},
			identities:            []AuthIdentity{{Name: "alice", Token: "tok123"}},
			authRequiredEndpoints: map[string]int{epKey: strength},
			accessProbeCount:      map[string]int{},
			oracleQueue:           make([]WorkItem, 0, 8),
		}
	}
	res := SendResult{
		Item: WorkItem{
			Method:   "GET",
			Path:     "/orders/123",
			Identity: "alice",
			Headers:  map[string]string{"Content-Type": "application/json"},
			Body:     `{"note":"n/a"}`,
		},
		Status: 200,
		Body:   `{"id":123,"total":42.50,"items":["a","b","c"]}`,
	}

	weak := mkFuzzer(1)
	weak.maybeEnqueueDifferentialProbes(res)
	if len(weak.oracleQueue) != 0 {
		t.Fatalf("expected no differential probes with only weak (strength=1) auth evidence, got %d", len(weak.oracleQueue))
	}

	strong := mkFuzzer(2)
	strong.maybeEnqueueDifferentialProbes(res)
	wantTechniques := map[string]bool{"verb": false, "content-type": false, "route-case": false, "param-location": false}
	for _, p := range strong.oracleQueue {
		if p.OracleKind != oracleKindDifferential {
			t.Errorf("expected OracleKind=%q, got %q", oracleKindDifferential, p.OracleKind)
		}
		if !p.NoAuth {
			t.Errorf("differential probes must strip auth (NoAuth=true)")
		}
		if _, known := wantTechniques[p.DiffTechnique]; !known {
			t.Errorf("unexpected DiffTechnique %q", p.DiffTechnique)
		}
		wantTechniques[p.DiffTechnique] = true
	}
	for technique, seen := range wantTechniques {
		if !seen {
			t.Errorf("expected a %q differential probe given the fixture request shape, none enqueued", technique)
		}
	}
}

// TestApplyProfileGatesProbeDifferential mirrors the existing probe-gating
// coverage for the three older access-control probes (Top-20 #18).
func TestApplyProfileGatesProbeDifferential(t *testing.T) {
	cfg := Config{Profile: "fast", ProbeDifferential: true}
	applyProfile(&cfg, map[string]bool{})
	if cfg.ProbeDifferential {
		t.Errorf("fast profile should disable probe-differential")
	}

	cfg2 := Config{Profile: "fast", ProbeDifferential: true}
	applyProfile(&cfg2, map[string]bool{"probe-differential": true})
	if !cfg2.ProbeDifferential {
		t.Errorf("explicit -probe-differential=true must survive the fast profile")
	}

	for _, p := range []string{"deep", "security"} {
		cfg3 := Config{Profile: p}
		applyProfile(&cfg3, map[string]bool{})
		if !cfg3.ProbeDifferential {
			t.Errorf("%s profile should enable probe-differential", p)
		}
	}
}
