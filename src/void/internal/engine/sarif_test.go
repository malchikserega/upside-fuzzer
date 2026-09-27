package engine

import (
	"testing"
	"void/internal/config"
)

func TestBuildSARIFReportExcludesNoiseAndMisconfig(t *testing.T) {
	f := &Fuzzer{findings: []CrashFinding{
		{Method: "GET", Path: "/a", Status: 500, Triage: map[string]any{"classification": "noise", "severity_score": 1}},
		{Method: "GET", Path: "/b", Status: 500, Triage: map[string]any{"classification": "target_misconfiguration", "severity_score": 5}},
	}}
	sarif := f.buildSARIFReport()
	runs := sarif["runs"].([]map[string]any)
	results := runs[0]["results"].([]map[string]any)
	if len(results) != 0 {
		t.Errorf("expected noise/target_misconfiguration findings excluded from SARIF, got %d results", len(results))
	}
	rules := runs[0]["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 0 {
		t.Errorf("expected no rules when every finding is excluded, got %d", len(rules))
	}
}

func TestBuildSARIFReportMapsClassificationToLevel(t *testing.T) {
	f := &Fuzzer{findings: []CrashFinding{
		{Method: "POST", Path: "/devices/{id}/retrieve-keys", Status: 200,
			Triage: map[string]any{"classification": "likely_vuln_high", "severity_score": 9, "reasons": []any{"bola_identical_cross_identity_response"}}},
		{Method: "POST", Path: "/ciphers/0/attachment-admin", Status: 500, ClusterKey: "nullref123", ClusterLabel: "Object reference not set to an instance of an object. @ CiphersController.ValidateAttachment",
			Triage: map[string]any{"classification": "confirmed_unhandled_exception", "severity_score": 8, "reasons": []any{"server_error", "dev_stack"}}},
		{Method: "GET", Path: "/organizations/0/users/0", Status: 500, ClusterKey: "routing456", ClusterLabel: "A route decorated with '[Authorize<IOrganizationRequirement>]' must include a route value",
			Triage: map[string]any{"classification": "needs_review", "severity_score": 4, "reasons": []any{"server_error"}}},
	}}
	sarif := f.buildSARIFReport()
	runs := sarif["runs"].([]map[string]any)
	results := runs[0]["results"].([]map[string]any)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	byRule := map[string]map[string]any{}
	for _, r := range results {
		byRule[r["ruleId"].(string)] = r
	}

	bola, ok := byRule["bola_identical_cross_identity_response"]
	if !ok {
		t.Fatalf("expected a result with ruleId=bola_identical_cross_identity_response, got rules %v", keysOfResults(results))
	}
	if bola["level"] != "error" {
		t.Errorf("likely_vuln_high must map to SARIF level=error, got %v", bola["level"])
	}

	// Regression: a generic contextual tag (server_error/dev_stack, present on nearly
	// every 500) must NOT become the rule id -- it must fall through to the finding's
	// own cluster key, so distinct root causes stay distinct rules instead of every
	// non-oracle finding collapsing onto one "server_error" bucket.
	exc, ok := byRule["cluster_nullref123"]
	if !ok {
		t.Fatalf("expected a result falling back to ruleId=cluster_nullref123 (generic reason tags must not win), got rules %v", keysOfResults(results))
	}
	if exc["level"] != "warning" {
		t.Errorf("confirmed_unhandled_exception must map to SARIF level=warning, got %v", exc["level"])
	}

	rev, ok := byRule["cluster_routing456"]
	if !ok {
		t.Fatalf("expected a result falling back to ruleId=cluster_routing456, got rules %v", keysOfResults(results))
	}
	if rev["level"] != "note" {
		t.Errorf("needs_review must map to SARIF level=note, got %v", rev["level"])
	}

	// Every result needs a physicalLocation.artifactLocation.uri or GitHub code
	// scanning silently drops it -- verify the shape is present, not just that the
	// map key exists.
	loc := bola["locations"].([]map[string]any)[0]["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
	if loc == "" {
		t.Errorf("expected a non-empty artifactLocation.uri")
	}
}

// TestBuildSARIFReportGenericReasonTagsNeverBecomeRuleID is a focused regression test
// for the exact bug found running SARIF export against a real Bitwarden campaign:
// "server_error" alone accounted for 1601 of 1602 rule-id picks before the strong-tag
// allowlist existed, because it's appended to nearly every 500-status finding
// regardless of what actually caused it.
func TestBuildSARIFReportGenericReasonTagsNeverBecomeRuleID(t *testing.T) {
	genericTags := []string{
		"server_error", "dev_stack", "backend_exception", "post_auth_execution",
		"pre_auth_model_binding", "pre_auth_deserialization", "stateful_trigger",
		"synthetic_path", "content_type_noise", "benign_input_validation",
		"needs_manual_verification", "endpoint_rejected_unauth_401_403",
		"identical_response_to_authenticated",
	}
	for _, tag := range genericTags {
		f := &Fuzzer{findings: []CrashFinding{
			{Method: "GET", Path: "/x", Status: 500, ClusterKey: "abc123",
				Triage: map[string]any{"classification": "needs_review", "severity_score": 4, "reasons": []any{tag}}},
		}}
		sarif := f.buildSARIFReport()
		results := sarif["runs"].([]map[string]any)[0]["results"].([]map[string]any)
		if len(results) != 1 {
			t.Fatalf("tag %q: expected 1 result, got %d", tag, len(results))
		}
		if got := results[0]["ruleId"].(string); got != "cluster_abc123" {
			t.Errorf("generic tag %q must not become the rule id, expected fallback to cluster_abc123, got %q", tag, got)
		}
	}
}

func TestBuildSARIFReportRuleCatalogMatchesResults(t *testing.T) {
	// Two findings sharing the same rule (same reason tag) must produce exactly
	// one rule entry, not one per finding -- a rule is a finding *type*, not an
	// instance, per the SARIF spec's own object model.
	f := &Fuzzer{findings: []CrashFinding{
		{Method: "POST", Path: "/accounts/verify-password", Status: 400,
			Triage: map[string]any{"classification": "likely_vuln_high", "severity_score": 9, "reasons": []any{"sqli_time_based"}}},
		{Method: "DELETE", Path: "/accounts", Status: 400,
			Triage: map[string]any{"classification": "likely_vuln_high", "severity_score": 9, "reasons": []any{"sqli_time_based"}}},
	}}
	sarif := f.buildSARIFReport()
	runs := sarif["runs"].([]map[string]any)
	results := runs[0]["results"].([]map[string]any)
	rules := runs[0]["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]map[string]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 rule (shared by both findings), got %d", len(rules))
	}
	if rules[0]["id"] != "sqli_time_based" {
		t.Errorf("expected the single rule id to be sqli_time_based, got %v", rules[0]["id"])
	}
}

// TestBuildSARIFReportStripsDynamicReasonSuffix verifies tags carrying a dynamic
// ":field"/":technique" suffix (mass_assignment_privileged_field_accepted:isAdmin,
// differential_auth_bypass:verb) collapse onto their stable base tag as the rule id --
// otherwise every distinct field/technique value would mint its own one-off rule.
func TestBuildSARIFReportStripsDynamicReasonSuffix(t *testing.T) {
	f := &Fuzzer{findings: []CrashFinding{
		{Method: "PUT", Path: "/users/0", Status: 200,
			Triage: map[string]any{"classification": "likely_vuln", "severity_score": 6, "reasons": []any{"mass_assignment_privileged_field_accepted:isAdmin"}}},
		{Method: "PUT", Path: "/users/1", Status: 200,
			Triage: map[string]any{"classification": "likely_vuln", "severity_score": 6, "reasons": []any{"mass_assignment_privileged_field_accepted:role"}}},
	}}
	sarif := f.buildSARIFReport()
	rules := sarif["runs"].([]map[string]any)[0]["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 1 {
		t.Fatalf("expected the two field-specific tags to collapse onto one rule, got %d: %v", len(rules), rules)
	}
	if rules[0]["id"] != "mass_assignment_privileged_field_accepted" {
		t.Errorf("expected the dynamic :field suffix stripped, got rule id %v", rules[0]["id"])
	}
}

func TestSarifSecuritySeverityClamps(t *testing.T) {
	if got := sarifSecuritySeverity(-5); got != "0.0" {
		t.Errorf("expected clamping to 0.0 for negative score, got %s", got)
	}
	if got := sarifSecuritySeverity(999); got != "10.0" {
		t.Errorf("expected clamping to 10.0 for an out-of-range score, got %s", got)
	}
	if got := sarifSecuritySeverity(9); got != "10.0" {
		t.Errorf("expected max in-range score 9 to map to 10.0, got %s", got)
	}
}

// TestBuildSARIFReportCarriesRunManifest verifies the run-level properties bag
// (Phase 5 #127) exposes the same reproducibility manifest report.go's JSON
// output carries, so a SARIF-only consumer doesn't lose that provenance.
func TestBuildSARIFReportCarriesRunManifest(t *testing.T) {
	f := &Fuzzer{
		cfg:    config.Config{RunID: "run-7", Seed: 99},
		target: "http://localhost:5200",
	}
	sarif := f.buildSARIFReport()
	run := sarif["runs"].([]map[string]any)[0]
	props, ok := run["properties"].(map[string]any)
	if !ok {
		t.Fatal("expected run.properties to be present")
	}
	manifest, ok := props["run_manifest"].(map[string]any)
	if !ok {
		t.Fatal("expected run.properties.run_manifest to be present")
	}
	if manifest["run_id"] != "run-7" {
		t.Errorf("expected run_manifest.run_id=run-7, got %v", manifest["run_id"])
	}
	if manifest["target_host"] != "http://localhost:5200" {
		t.Errorf("expected run_manifest.target_host set, got %v", manifest["target_host"])
	}
}

// TestBuildSARIFReportIncludesChainForSequenceFindings verifies a finding
// with a sequence ChainTrace surfaces it under result.properties.chain, and
// that a non-sequence finding leaves it absent (nil, not an empty chain).
func TestBuildSARIFReportIncludesChainForSequenceFindings(t *testing.T) {
	f := &Fuzzer{findings: []CrashFinding{
		{Method: "PUT", Path: "/widgets/1", Status: 500, ClusterKey: "c1",
			Triage:     map[string]any{"classification": "needs_review", "severity_score": 4},
			SequenceID: "seq-9",
			ChainTrace: []SequenceStep{
				{Method: "GET", Path: "/widgets", Status: 200},
				{Method: "PUT", Path: "/widgets/1", Status: 500},
			}},
		{Method: "GET", Path: "/other", Status: 500, ClusterKey: "c2",
			Triage: map[string]any{"classification": "needs_review", "severity_score": 4}},
	}}
	sarif := f.buildSARIFReport()
	results := sarif["runs"].([]map[string]any)[0]["results"].([]map[string]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	byCluster := map[string]map[string]any{}
	for _, r := range results {
		fp := r["partialFingerprints"].(map[string]any)
		byCluster[fp["upsidefuzzClusterKey/v1"].(string)] = r
	}

	chained := byCluster["c1"]["properties"].(map[string]any)["chain"]
	chainMap, ok := chained.(map[string]any)
	if !ok {
		t.Fatalf("expected c1's chain property to be a populated map, got %v", chained)
	}
	if chainMap["sequence_id"] != "seq-9" {
		t.Errorf("expected chain.sequence_id=seq-9, got %v", chainMap["sequence_id"])
	}
	if chainMap["depth"] != 2 {
		t.Errorf("expected chain.depth=2, got %v", chainMap["depth"])
	}

	if got := byCluster["c2"]["properties"].(map[string]any)["chain"]; got != nil {
		t.Errorf("expected c2 (non-sequence finding) to have a nil chain property, got %v", got)
	}
}

func keysOfResults(results []map[string]any) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r["ruleId"].(string)
	}
	return out
}
