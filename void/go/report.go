package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// report.go — Final crash report building: findings summary, structured
// JSON bug report, and classification roll-up.

func (f *Fuzzer) findingsReportData() (map[string]any, []map[string]any) {
	classCounts := map[string]int{}
	devMode := 0
	stable := 0
	top := make([]map[string]any, 0, len(f.findings))
	for _, fd := range f.findings {
		cls := toString(fd.Triage["classification"])
		if cls == "" {
			cls = "unclassified"
		}
		classCounts[cls]++
		if strings.EqualFold(toString(fd.Triage["dev_mode"]), "true") {
			devMode++
		}
		stability := toString(fd.Repro["stability_pct"])
		if strings.TrimSpace(stability) != "" {
			if pct, err := strconvAtof(stability); err == nil && pct >= f.cfg.ReproTargetPct {
				stable++
			}
		}
		top = append(top, map[string]any{
			"signature":       fd.Signature,
			"method":          fd.Method,
			"path":            fd.Path,
			"status":          fd.Status,
			"identity":        fd.Identity,
			"classification":  cls,
			"severity_score":  toInt(fd.Triage["severity_score"]),
			"crash_layer":     toString(fd.Triage["crash_layer"]),
			"dev_mode":        fd.Triage["dev_mode"],
			"repro_stability": toString(fd.Repro["stability_pct"]),
			"poc_file":        fd.PocFile,
			"timeline_file":   fd.Timeline,
		})
	}
	sort.Slice(top, func(i, j int) bool {
		si := toInt(top[i]["severity_score"])
		sj := toInt(top[j]["severity_score"])
		if si != sj {
			return si > sj
		}
		ri, _ := strconvAtof(toString(top[i]["repro_stability"]))
		rj, _ := strconvAtof(toString(top[j]["repro_stability"]))
		if ri != rj {
			return ri > rj
		}
		return toString(top[i]["signature"]) < toString(top[j]["signature"])
	})

	summary := map[string]any{
		"total_findings":         len(f.findings),
		"classification_counts":  classCounts,
		"dev_mode_findings":      devMode,
		"stable_repro_findings":  stable,
		"generated_poc_files":    f.pocCount,
		"repro_target_pct":       f.cfg.ReproTargetPct,
		"source_aware_priority":  f.cfg.SourceAwarePriority,
		"multi_identity_enabled": f.cfg.MultiIdentity,
		"identity_mode":          f.cfg.IdentitySampleMode,
		"identity_count":         len(f.identities),
		"identity_include_guest": f.cfg.IdentityIncludeGuest,
		"auth_file_configured":   strings.TrimSpace(f.cfg.AuthFile) != "",
		"race_mode_enabled":      f.cfg.RaceMode,
		"race_prob":              f.cfg.RaceProb,
		"race_burst":             f.cfg.RaceBurst,
		"sequence_prob":          f.cfg.SequenceProb,
		"sequence_max_depth":     f.cfg.SequenceMaxDepth,
		"sequence_fanout":        f.cfg.SequenceFanout,
		"skip_on_crash":          f.cfg.SkipOnCrash,
		"skip_endpoint_on_500":   f.cfg.SkipEndpointOn500,
		"crash_replay_count":     f.cfg.CrashReplayCount,
		"crash_boost_requests":   f.cfg.CrashBoostRequests,
	}
	return summary, top
}

func (f *Fuzzer) buildStructuredCrashReport(triageSummary map[string]any) map[string]any {
	if triageSummary == nil {
		triageSummary, _ = f.findingsReportData()
	}

	rows := make([]CrashFinding, 0, len(f.findings))
	rows = append(rows, f.findings...)
	sort.Slice(rows, func(i, j int) bool {
		si := toInt(rows[i].Triage["severity_score"])
		sj := toInt(rows[j].Triage["severity_score"])
		if si != sj {
			return si > sj
		}
		ri, _ := strconvAtof(toString(rows[i].Repro["stability_pct"]))
		rj, _ := strconvAtof(toString(rows[j].Repro["stability_pct"]))
		if ri != rj {
			return ri > rj
		}
		return rows[i].Signature < rows[j].Signature
	})

	bugs := make([]map[string]any, 0, len(rows))
	for i, fd := range rows {
		triage := cloneAnyMap(fd.Triage)
		repro := cloneAnyMap(fd.Repro)
		minimized := cloneAnyMap(fd.Minimized)
		classification := strings.TrimSpace(toString(triage["classification"]))
		if classification == "" {
			classification = "unclassified"
		}
		endpoint := strings.TrimSpace(strings.ToUpper(fd.Method)) + " " + strings.TrimSpace(fd.Path)
		if endpoint == "" {
			endpoint = "unknown"
		}
		bugs = append(bugs, map[string]any{
			"id":             i + 1,
			"signature":      fd.Signature,
			"timestamp":      fd.TS,
			"elapsed_secs":   fd.ElapsedSec,
			"classification": classification,
			"severity_score": toInt(triage["severity_score"]),
			"crash_layer":    toString(triage["crash_layer"]),
			"request": map[string]any{
				"endpoint":             endpoint,
				"method":               fd.Method,
				"path":                 fd.Path,
				"identity":             fd.Identity,
				"auth_context":         cloneAnyMap(fd.AuthContext),
				"mutation":             fd.Mutation,
				"headers":              cloneStringMap(fd.RequestHeads),
				"payload":              fd.Payload,
				"payload_length_bytes": len([]byte(fd.Payload)),
				"status_code":          fd.Status,
			},
			"response": map[string]any{
				"status_code":    fd.Status,
				"exception_type": fd.Exception,
				"body":           fd.Response,
			},
			"triage":    triage,
			"repro":     repro,
			"minimized": minimized,
			"artifacts": map[string]any{
				"poc_file":      fd.PocFile,
				"timeline_file": fd.Timeline,
			},
			"copyables": map[string]any{
				"endpoint":     endpoint,
				"path":         fd.Path,
				"signature":    fd.Signature,
				"curl_command": fd.CurlCommand,
			},
		})
	}

	elapsed := time.Since(f.startTime).Seconds()
	return map[string]any{
		"report_version": "void-bug-report-v1",
		"generated_at":   time.Now().Format(time.RFC3339),
		"target_host":    f.target,
		"stats": map[string]any{
			"elapsed_secs":   elapsed,
			"requests_done":  f.totalDone,
			"requests_sent":  f.totalSent,
			"errors":         f.totalErrors,
			"crashes_total":  f.totalCrashes,
			"crashes_unique": f.uniqueCrashes,
			"coverage_edges": f.currentEdges,
			"coverage_new":   f.currentEdges - f.startEdges,
			// coverage_baseline_ceiling: edges found after all templates sent unmutated.
			// This is the real denominator — the total application surface reachable under
			// normal traffic. 0 means the Baseline epoch has not yet completed.
			"coverage_baseline_ceiling": f.baselineEdgesCeiling,
			// coverage_above_baseline_pct: % of baseline ceiling covered additionally by mutations.
			"coverage_above_baseline_pct": func() string {
				if f.baselineEdgesCeiling <= 0 {
					return "n/a"
				}
				aboveBaseline := f.currentEdges - f.baselineEdgesCeiling
				pct := float64(aboveBaseline) / float64(f.baselineEdgesCeiling) * 100.0
				if pct < 0 {
					pct = 0
				}
				return fmt.Sprintf("%.1f%%", pct)
			}(),
			"coverage_sat_pct": f.coverageSaturationPct(),
		},
		"files": map[string]any{
			"crash_log_file":        f.cfg.CrashFile,
			"unique_crash_log_file": f.cfg.UniqueCrashFile,
			"summary_file":          f.cfg.SummaryFile,
			"report_file":           f.cfg.ReportFile,
		},
		"triage_summary": triageSummary,
		"bugs":           bugs,
	}
}
