package engine

import (
	"testing"
	"void/internal/config"
)

// TestBuildStructuredCrashReportCarriesRunManifest verifies the top-level JSON
// report (Phase 5 #127) exposes the run manifest alongside its existing
// triage_summary/bugs sections.
func TestBuildStructuredCrashReportCarriesRunManifest(t *testing.T) {
	f := &Fuzzer{
		cfg:    config.Config{RunID: "run-1", Seed: 7},
		target: "http://localhost:5200",
	}
	report := f.buildStructuredCrashReport(nil)
	manifest, ok := report["run_manifest"].(map[string]any)
	if !ok {
		t.Fatal("expected report.run_manifest to be present")
	}
	if manifest["run_id"] != "run-1" {
		t.Errorf("expected run_manifest.run_id=run-1, got %v", manifest["run_id"])
	}
}

// TestBuildStructuredCrashReportIncludesChainForSequenceFindings verifies a
// sequence-originated bug's full chain (method/path/status per step) is
// carried in the JSON report, and that a non-sequence bug's chain is absent.
func TestBuildStructuredCrashReportIncludesChainForSequenceFindings(t *testing.T) {
	f := &Fuzzer{
		findings: []CrashFinding{
			{
				Signature: "sig-chained", Method: "PUT", Path: "/widgets/1", Status: 500,
				Triage:     map[string]any{"classification": "needs_review", "severity_score": 4},
				SequenceID: "seq-1",
				ChainTrace: []SequenceStep{
					{Method: "GET", Path: "/widgets", Status: 200, CoverageDelta: 3},
					{Method: "PUT", Path: "/widgets/1", Status: 500},
				},
			},
			{
				Signature: "sig-plain", Method: "GET", Path: "/other", Status: 500,
				Triage: map[string]any{"classification": "needs_review", "severity_score": 4},
			},
		},
	}
	report := f.buildStructuredCrashReport(nil)
	bugs := report["bugs"].([]map[string]any)
	if len(bugs) != 2 {
		t.Fatalf("expected 2 bugs, got %d", len(bugs))
	}

	bySig := map[string]map[string]any{}
	for _, b := range bugs {
		bySig[b["signature"].(string)] = b
	}

	chain, ok := bySig["sig-chained"]["chain"].(map[string]any)
	if !ok {
		t.Fatalf("expected sig-chained's chain to be a populated map, got %v", bySig["sig-chained"]["chain"])
	}
	if chain["sequence_id"] != "seq-1" {
		t.Errorf("expected chain.sequence_id=seq-1, got %v", chain["sequence_id"])
	}
	steps, ok := chain["steps"].([]map[string]any)
	if !ok || len(steps) != 2 {
		t.Fatalf("expected 2 chain steps, got %v", chain["steps"])
	}
	if steps[0]["path"] != "/widgets" || steps[1]["path"] != "/widgets/1" {
		t.Errorf("expected chain steps in order, got %v", steps)
	}

	if got := bySig["sig-plain"]["chain"]; got != nil {
		t.Errorf("expected sig-plain (non-sequence finding) to have a nil chain, got %v", got)
	}
}

func TestClusterRollup_SortsBySeverityThenVariantsThenKey(t *testing.T) {
	f := &Fuzzer{clusters: map[string]*ClusterInfo{
		"low":  {Key: "low", Label: "Low", MaxSeverity: 2, Variants: 5, RepMethod: "get", RepPath: "/a", Status: 200},
		"high": {Key: "high", Label: "High", MaxSeverity: 8, Variants: 1, RepMethod: "post", RepPath: "/b", Status: 500},
		"mid":  {Key: "mid", Label: "Mid", MaxSeverity: 8, Variants: 3, RepMethod: "put", RepPath: "/c", Status: 500},
	}}
	out := f.clusterRollup()
	if len(out) != 3 {
		t.Fatalf("expected 3 clusters, got %d", len(out))
	}
	// Same top severity (8): "mid" (3 variants) must outrank "high" (1 variant).
	if out[0]["cluster_key"] != "mid" || out[1]["cluster_key"] != "high" || out[2]["cluster_key"] != "low" {
		t.Errorf("expected order [mid,high,low], got %v", []any{out[0]["cluster_key"], out[1]["cluster_key"], out[2]["cluster_key"]})
	}
	if out[0]["representative_endpoint"] != "PUT /c" {
		t.Errorf("expected the representative_endpoint to be uppercased method + path, got %v", out[0]["representative_endpoint"])
	}
}

func TestClusterRollup_EmptyClustersReturnsEmptySlice(t *testing.T) {
	f := &Fuzzer{clusters: map[string]*ClusterInfo{}}
	if got := f.clusterRollup(); len(got) != 0 {
		t.Errorf("expected an empty slice for no clusters, got %v", got)
	}
}

func TestFindingsReportData(t *testing.T) {
	f := &Fuzzer{
		cfg:      config.Config{ReproTargetPct: 80, MultiIdentity: true, IdentitySampleMode: "round_robin"},
		clusters: map[string]*ClusterInfo{"c1": {Key: "c1", Label: "Cluster 1", MaxSeverity: 5}},
		findings: []CrashFinding{
			{
				Signature: "sig-a", ClusterKey: "c1", Method: "POST", Path: "/orders", Status: 500,
				Triage: map[string]any{"classification": "confirmed_bug", "severity_score": 9, "dev_mode": "true", "crash_layer": "service"},
				Repro:  map[string]any{"stability_pct": "95"},
			},
			{
				Signature: "sig-b", Method: "GET", Path: "/health", Status: 500,
				Triage: map[string]any{"severity_score": 2},
				Repro:  map[string]any{"stability_pct": "10"},
			},
		},
	}
	summary, top := f.findingsReportData()

	if summary["total_findings"] != 2 {
		t.Errorf("expected total_findings=2, got %v", summary["total_findings"])
	}
	if summary["distinct_root_causes"] != 1 {
		t.Errorf("expected distinct_root_causes=1, got %v", summary["distinct_root_causes"])
	}
	if summary["dev_mode_findings"] != 1 {
		t.Errorf("expected dev_mode_findings=1, got %v", summary["dev_mode_findings"])
	}
	if summary["stable_repro_findings"] != 1 {
		t.Errorf("expected stable_repro_findings=1 (only sig-a's 95%% clears ReproTargetPct=80), got %v", summary["stable_repro_findings"])
	}
	counts, ok := summary["classification_counts"].(map[string]int)
	if !ok || counts["confirmed_bug"] != 1 || counts["unclassified"] != 1 {
		t.Errorf("expected classification_counts confirmed_bug=1 unclassified=1, got %v", counts)
	}

	if len(top) != 2 {
		t.Fatalf("expected 2 top findings, got %d", len(top))
	}
	// Higher severity_score (9) must sort first.
	if top[0]["signature"] != "sig-a" {
		t.Errorf("expected sig-a (severity 9) sorted first, got %v", top[0]["signature"])
	}
}

func TestFindingsReportData_EmptyFindings(t *testing.T) {
	f := &Fuzzer{clusters: map[string]*ClusterInfo{}}
	summary, top := f.findingsReportData()
	if summary["total_findings"] != 0 || len(top) != 0 {
		t.Errorf("expected empty summary/top for no findings, got summary=%v top=%v", summary, top)
	}
}
