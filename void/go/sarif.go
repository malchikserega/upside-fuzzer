package main

import (
	"fmt"
	"sort"
	"strings"
)

// sarif.go — SARIF 2.1.0 findings export (ARCHITECTURE_REVIEW.md §7 weakness #3,
// Top-20 §16). Opt-in (-sarif-file), so findings drop directly into GitHub code
// scanning, DefectDojo, or any other SARIF-consuming security dashboard without a
// custom parser for this project's own JSON report shape.
//
// Modeling choice: a SARIF "rule" is a stable finding *type* (a checker), not an
// individual result -- so each distinct oracle reason tag (bola_identical_cross_
// identity_response, sqli_time_based, ...) becomes its own rule when the finding has
// one of those specific tags, falling back to the finding's own root-cause cluster key
// (see sarifRuleID) for everything else -- generic contextual tags like server_error
// are never allowed to become the rule id themselves, or nearly every finding in a run
// would collapse onto one bucket. This mirrors how the project's own honest-triage
// taxonomy already separates "what kind of thing is this" (rule) from "did this
// specific request trigger it" (result) -- SARIF just gives that structure a standard
// wire format. "noise" and "target_misconfiguration" findings are excluded entirely:
// consistent with every other report this project emits, SARIF output should carry
// only classifications the tool itself trusts.
const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// sarifExcludedClassifications are never emitted as SARIF results -- see the comment
// above buildSARIFReport.
var sarifExcludedClassifications = map[string]bool{
	"noise":                   true,
	"target_misconfiguration": true,
	"":                        true,
	"unclassified":            true,
}

// sarifLevel maps this project's classification tiers to SARIF's fixed level enum
// (error/warning/note) -- the field GitHub code scanning and most SARIF viewers use
// to sort/filter findings by how seriously to take them.
func sarifLevel(classification string) string {
	switch classification {
	case "likely_vuln_high", "likely_vuln":
		return "error"
	case "confirmed_unhandled_exception":
		return "warning"
	default: // needs_review and anything else that survives sarifExcludedClassifications
		return "note"
	}
}

// sarifSecuritySeverity renders severity_score (this project's own 0-9 heuristic
// scale, already documented as "not CVSS" -- ARCHITECTURE_REVIEW.md §7 weakness #2)
// onto SARIF's conventional 0.0-10.0 security-severity property string, the field
// GitHub's UI reads to color-code and sort alerts.
func sarifSecuritySeverity(score int) string {
	if score < 0 {
		score = 0
	}
	if score > 9 {
		score = 9
	}
	return fmt.Sprintf("%.1f", float64(score)/9.0*10.0)
}

// sarifStrongReasonTags are the oracle-specific reason tags worth being a SARIF rule
// identity on their own -- each names a distinct, specific finding *type* a security
// engineer would want to filter/triage by. Everything else `identity.go`/`oracle.go`
// append to a finding's reasons (server_error, dev_stack, post_auth_execution,
// synthetic_path, needs_manual_verification, endpoint_rejected_unauth_401_403, ...) is
// contextual scaffolding present on nearly every finding regardless of what kind of bug
// it actually is -- an allowlist here (checked explicitly) rather than a denylist, so a
// future new contextual tag defaults to being treated as non-specific instead of
// silently becoming a rule id and drowning out the real signal (found the hard way:
// "server_error" alone accounted for 1601 of 1602 rule-id picks in a real Bitwarden
// run before this allowlist existed, collapsing every distinct exception type --
// NullReferenceException, GUID-parse failures, a routing assertion -- into one rule).
// Two tags carry a dynamic ":suffix" (the specific field/technique) that must be
// stripped for the id to stay a stable finding *type* rather than one-rule-per-value.
var sarifStrongReasonTags = map[string]bool{
	"sqli_time_based":                           true,
	"sqli_error_reflected":                      true,
	"ssti_evaluated":                            true,
	"xss_reflected_unescaped":                   true,
	"file_read_success":                         true,
	"ssrf_metadata_reflected":                   true,
	"bola_identical_cross_identity_response":    true,
	"bola_suspected_cross_identity_access":      true,
	"auth_bypass_unauthenticated_access":        true,
	"mass_assignment_privileged_field_accepted": true,
	"differential_auth_bypass":                  true,
}

// sarifRuleID picks the most specific *stable* identifier available for a finding:
//  1. A strong oracle reason tag, if present (sqli_time_based, bola_*, ...).
//  2. Otherwise the finding's own root-cause cluster key -- this project's existing
//     clustering (cluster.go) already groups by normalized exception message + top
//     app stack frame, which is exactly the granularity a SARIF rule wants, and reusing
//     it means a distinct rule per distinct real bug (NullReferenceException in
//     ValidateAttachment, GUID-parse failures, the routing assertion, ...) instead of
//     every non-oracle finding collapsing onto the shared classification.
//  3. The coarse classification, only if neither of the above is available.
func sarifRuleID(fd CrashFinding, reasons []any) string {
	for _, r := range reasons {
		s := toString(r)
		if i := strings.IndexByte(s, ':'); i >= 0 {
			s = s[:i]
		}
		if sarifStrongReasonTags[s] {
			return s
		}
	}
	if fd.ClusterKey != "" {
		return "cluster_" + fd.ClusterKey
	}
	return toString(fd.Triage["classification"])
}

var sarifRuleDescriptions = map[string]string{
	"likely_vuln_high":                          "A concrete exploitation signal fired with high confidence.",
	"likely_vuln":                               "A concrete exploitation signal fired.",
	"confirmed_unhandled_exception":             "A reproducible unhandled exception with a captured stack trace -- a robustness/DoS-class bug, not by itself proof of a security vulnerability.",
	"needs_review":                              "A 500 response that could not be confidently attributed to a specific root cause.",
	"sqli_time_based":                           "Response latency consistent with a time-based SQL injection payload (sleep/waitfor/pg_sleep/benchmark) actually executing.",
	"sqli_error_reflected":                      "A database engine error message was reflected in the response body.",
	"ssti_evaluated":                            "A server-side template injection payload's numeric product appeared in the response, indicating the expression was evaluated, not just reflected.",
	"xss_reflected_unescaped":                   "An injected script payload was reflected back unescaped in an HTML response.",
	"file_read_success":                         "Contents of a well-known system file appeared in the response, indicating a path traversal / local file read.",
	"ssrf_metadata_reflected":                   "Genuine cloud-metadata-service content appeared in the response after a metadata-service URL was submitted.",
	"bola_identical_cross_identity_response":    "A byte-identical response was returned for the same resource request replayed under a different identity.",
	"bola_suspected_cross_identity_access":      "A different identity successfully accessed a resource-scoped endpoint originally reached under another identity; body differed, so ownership could not be confirmed from response content alone.",
	"auth_bypass_unauthenticated_access":        "A credential-free request succeeded on an endpoint already observed rejecting unauthenticated access.",
	"differential_auth_bypass":                  "A verb/content-type/route-case/param-location confusion variant bypassed authorization enforcement the literal unauthenticated replay did not.",
	"mass_assignment_privileged_field_accepted": "A privileged field over-posted on a write was accepted (echoed back or otherwise not rejected).",
}

// sarifRuleDescription resolves a rule's description: the static catalog above for
// oracle-tag rule ids, or -- for the far more common cluster_<key> rule ids -- the
// finding's own cluster label (the normalized exception message + top app stack
// frame), which is already the human-readable description of that exact root cause.
func sarifRuleDescription(ruleID, clusterLabel string) string {
	if d, ok := sarifRuleDescriptions[ruleID]; ok {
		return d
	}
	if clusterLabel != "" {
		return clusterLabel
	}
	return "UpsideFuzz finding: " + ruleID
}

// sarifArtifactURI turns an endpoint into a synthetic but stable, valid relative URI
// for SARIF's required physicalLocation.artifactLocation.uri -- there is no real file
// for a REST endpoint, but SARIF viewers (including GitHub's) expect a location to
// group and display results, so the endpoint path itself, method-prefixed, stands in
// for one. Not a claim that this URI resolves to anything on disk.
func sarifArtifactURI(method, path string) string {
	p := strings.TrimPrefix(path, "/")
	if p == "" {
		p = "root"
	}
	return "endpoints/" + strings.ToUpper(method) + "/" + p
}

// buildSARIFReport converts this run's findings (f.findings, the same source
// buildStructuredCrashReport reads) into a SARIF 2.1.0 log. One rule per distinct
// ruleID actually used this run (not the full static catalog above -- an empty rule
// with zero results is noise), one result per finding that survives the exclusion
// list.
func (f *Fuzzer) buildSARIFReport() map[string]any {
	rulesByID := map[string]map[string]any{}
	var ruleOrder []string
	results := make([]map[string]any, 0, len(f.findings))

	for _, fd := range f.findings {
		cls := toString(fd.Triage["classification"])
		if sarifExcludedClassifications[cls] {
			continue
		}
		var reasons []any
		if r, ok := fd.Triage["reasons"].([]any); ok {
			reasons = r
		} else if r, ok := fd.Triage["reasons"].([]string); ok {
			for _, s := range r {
				reasons = append(reasons, s)
			}
		}
		ruleID := sarifRuleID(fd, reasons)
		if _, seen := rulesByID[ruleID]; !seen {
			rulesByID[ruleID] = map[string]any{
				"id":               ruleID,
				"name":             ruleID,
				"shortDescription": map[string]any{"text": sarifRuleDescription(ruleID, fd.ClusterLabel)},
				"properties": map[string]any{
					"security-severity": sarifSecuritySeverity(toInt(fd.Triage["severity_score"])),
					"tags":              []string{"security", "upsidefuzz"},
				},
			}
			ruleOrder = append(ruleOrder, ruleID)
		}

		msg := fmt.Sprintf("%s %s -> HTTP %d (%s)", strings.ToUpper(fd.Method), fd.Path, fd.Status, cls)
		if fd.ClusterLabel != "" {
			msg = fmt.Sprintf("%s: %s", msg, fd.ClusterLabel)
		}

		result := map[string]any{
			"ruleId":  ruleID,
			"level":   sarifLevel(cls),
			"message": map[string]any{"text": msg},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": sarifArtifactURI(fd.Method, fd.Path)},
					},
				},
			},
			"partialFingerprints": map[string]any{
				"upsidefuzzClusterKey/v1": fd.ClusterKey,
				"upsidefuzzSignature/v1":  fd.Signature,
			},
			"properties": map[string]any{
				"identity":       fd.Identity,
				"severity_score": toInt(fd.Triage["severity_score"]),
				"repro_stable":   fd.Repro["stable_reproducible"],
				"poc_file":       fd.PocFile,
			},
		}
		results = append(results, result)
	}

	sort.Strings(ruleOrder)
	rules := make([]map[string]any, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rules = append(rules, rulesByID[id])
	}

	return map[string]any{
		"$schema": sarifSchemaURI,
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":             "UpsideFuzz",
						"informationUri":   "https://github.com/upsidefuzz/upsidefuzz",
						"version":          "1.0.0",
						"rules":            rules,
						"organization":     "UpsideFuzz",
						"shortDescription": map[string]any{"text": "Coverage-guided REST API fuzzer for .NET"},
					},
				},
				"results": results,
			},
		},
	}
}
