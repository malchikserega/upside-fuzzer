package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ui.go — Terminal dashboard: live fuzzing progress display,
// endpoint stats tables, and final session report.

func (f *Fuzzer) useDashboardUI() bool {
	if f.cfg.NoUI || f.cfg.PlainUI {
		return false
	}
	return f.uiInline || f.cfg.ForceUI
}

func (f *Fuzzer) dashboardWidth() int {
	if f.uiWidthLocked > 0 {
		return f.uiWidthLocked
	}
	w := 0
	if f.cfg.UIWidth > 0 {
		w = f.cfg.UIWidth
	}
	if w == 0 {
		if ev := strings.TrimSpace(os.Getenv("SMART_FUZZER_UI_WIDTH")); ev != "" {
			if v, err := strconv.Atoi(ev); err == nil {
				w = v
			}
		}
	}
	if w == 0 {
		if ev := strings.TrimSpace(os.Getenv("COLUMNS")); ev != "" {
			if v, err := strconv.Atoi(ev); err == nil {
				w = v
			}
		}
	}
	if w == 0 {
		w = 120
	}
	f.uiWidthLocked = clampInt(w, 80, 200)
	return f.uiWidthLocked
}

func (f *Fuzzer) dashboardHeightHint() int {
	if ev := strings.TrimSpace(os.Getenv("LINES")); ev != "" {
		if v, err := strconv.Atoi(ev); err == nil {
			return clampInt(v, 20, 120)
		}
	}
	return 44
}

func (f *Fuzzer) clearDashboard() {
	if f.cfg.UINoClear {
		return
	}
	fmt.Print("\033[H\033[2J")
}

func dashProgressBar(frac float64, width int, ascii bool) string {
	frac = clampFloat(frac, 0.0, 1.0)
	filled := int(frac * float64(width))
	if ascii {
		return strings.Repeat("#", filled) + strings.Repeat("-", maxInt(0, width-filled))
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", maxInt(0, width-filled))
}

func dashTruncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	s = sanitizeText(s, maxInt(8, maxLen*2))
	rs := []rune(s)
	if len(rs) <= maxLen {
		return s
	}
	if maxLen <= 2 {
		return string(rs[:maxLen])
	}
	return string(rs[:maxLen-2]) + ".."
}

func dashTopBorder(width int, ascii bool) string {
	if ascii {
		return "+" + strings.Repeat("-", maxInt(0, width-2)) + "+"
	}
	return "┌" + strings.Repeat("─", maxInt(0, width-2)) + "┐"
}

func dashBottomBorder(width int, ascii bool) string {
	if ascii {
		return "+" + strings.Repeat("-", maxInt(0, width-2)) + "+"
	}
	return "└" + strings.Repeat("─", maxInt(0, width-2)) + "┘"
}

func dashHLine(width int, ascii bool) string {
	if ascii {
		return "+" + strings.Repeat("-", maxInt(0, width-2)) + "+"
	}
	return "├" + strings.Repeat("─", maxInt(0, width-2)) + "┤"
}

func dashRow(content string, width int, ascii bool) string {
	content = sanitizeText(content, 4000)
	inner := maxInt(0, width-3)
	content = dashTruncate(content, inner)
	visible := len([]rune(content))
	pad := maxInt(0, inner-visible)
	if ascii {
		return "| " + content + strings.Repeat(" ", pad) + "|"
	}
	return "│ " + content + strings.Repeat(" ", pad) + "│"
}

func formatMMSS(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	total := int(seconds)
	hh := total / 3600
	mm := (total % 3600) / 60
	ss := total % 60
	if hh > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hh, mm, ss)
	}
	return fmt.Sprintf("%02d:%02d", mm, ss)
}

func sortEndpointsForUI(eps []*EndpointStats, mode string) {
	m := strings.ToLower(strings.TrimSpace(mode))
	sort.Slice(eps, func(i, j int) bool {
		a := eps[i]
		b := eps[j]
		switch m {
		case "req", "requests":
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
			if a.NewEdges != b.NewEdges {
				return a.NewEdges > b.NewEdges
			}
		case "edge", "edges", "coverage":
			if a.NewEdges != b.NewEdges {
				return a.NewEdges > b.NewEdges
			}
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
		case "recent", "last":
			if a.LastSeen != b.LastSeen {
				return a.LastSeen > b.LastSeen
			}
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
		case "alpha", "path":
			ak := endpointKey(a.Method, a.Path)
			bk := endpointKey(b.Method, b.Path)
			return ak < bk
		default:
			// "hot": prioritize crashy/hot endpoints.
			if a.S500 != b.S500 {
				return a.S500 > b.S500
			}
			if a.S5xx != b.S5xx {
				return a.S5xx > b.S5xx
			}
			if a.Reqs != b.Reqs {
				return a.Reqs > b.Reqs
			}
			if a.NewEdges != b.NewEdges {
				return a.NewEdges > b.NewEdges
			}
		}
		return endpointKey(a.Method, a.Path) < endpointKey(b.Method, b.Path)
	})
}

func (f *Fuzzer) renderUI(epochName string, epochIdx int, inFlight int) {
	f.checkTokenExpiryDuringRun()
	if f.cfg.WebUI {
		now := time.Now()
		if f.lastUIRender.IsZero() || now.Sub(f.lastUIRender) >= 200*time.Millisecond {
			f.lastUIRender = now

			eps := make([]EndpointStats, 0, len(f.endpointStats))
			epsPtrs := make([]*EndpointStats, 0, len(f.endpointStats))
			for _, ep := range f.endpointStats {
				epsPtrs = append(epsPtrs, ep)
			}
			sortEndpointsForUI(epsPtrs, f.cfg.UIEndpointSort)
			for i, ep := range epsPtrs {
				if i >= 15 {
					break
				}
				eps = append(eps, *ep)
			}

			avgLat := 0.0
			if f.latencySamples > 0 {
				avgLat = f.latencyTotalMS / float64(f.latencySamples)
			}

			satPct := 0.0
			if f.coverageCapacity > 0 {
				satPct = f.coverageSaturationPct()
			}

			// Capture recent events
			f.eventMu.Lock()
			recentEvents := make([]string, len(f.eventLog))
			copy(recentEvents, f.eventLog)
			f.eventMu.Unlock()

			recentCrashes := make([]CrashRecord, len(f.recentCrashes))
			copy(recentCrashes, f.recentCrashes)

			timeRem := ""
			if f.cfg.TimeBudgetMinutes > 0 {
				timeBudget := time.Duration(f.cfg.TimeBudgetMinutes * float64(time.Minute))
				rem := time.Until(f.startTime.Add(timeBudget)).Round(time.Second)
				if rem > 0 {
					timeRem = rem.String()
				} else {
					timeRem = "Finishing..."
				}
			}

			elapsed := time.Since(f.startTime).Seconds()
			reqPerSec := 0.0
			if elapsed > 0 {
				reqPerSec = float64(f.totalDone) / elapsed
			}

			stats := WebUIStats{
				EpochName:        epochName,
				EpochIdx:         epochIdx,
				InFlight:         inFlight,
				TotalDone:        f.totalDone,
				TotalSent:        f.totalSent,
				CurrentEdges:     f.currentEdges,
				StartEdges:       f.startEdges,
				NewEdges:         f.currentEdges - f.startEdges,
				CoverageSatPct:   satPct,
				TotalErrors:      f.totalErrors,
				TotalCrashes:     f.totalCrashes,
				UniqueCrashes:    f.uniqueCrashes,
				AvgLatency:       avgLat,
				Concurrency:      f.currentConcurrency,
				CorpusSize:       len(f.corpus),
				ElapsedSecs:      elapsed,
				RequestsPerSec:   reqPerSec,
				AuthBlockedCount: len(f.authBlocked),
				IdentityCount:    len(f.identities),
				TimeBudgetSecs:   f.cfg.TimeBudgetMinutes * 60,
				TopEndpoints:     eps,
				RecentEvents:     recentEvents,
				RecentCrashes:    recentCrashes,
				TimeRemaining:    timeRem,
			}

			f.WebUIHub.broadcast(stats)
		}
		if f.cfg.NoUI {
			return
		}
	} else if f.cfg.NoUI {
		return
	}
	now := time.Now()
	if !f.lastUIRender.IsZero() && now.Sub(f.lastUIRender) < time.Duration(f.cfg.UIIntervalSec*float64(time.Second)) {
		return
	}
	elapsed := now.Sub(f.startTime).Seconds()
	doneRate := 0.0
	sentRate := 0.0
	if elapsed > 0 {
		doneRate = float64(f.totalDone) / elapsed
		sentRate = float64(f.totalSent) / elapsed
	}
	avgLat := 0.0
	if f.latencySamples > 0 {
		avgLat = f.latencyTotalMS / float64(f.latencySamples)
	}

	satSuffix := ""
	if f.coverageCapacity > 0 {
		satSuffix = fmt.Sprintf(" sat=%.1f%%", f.coverageSaturationPct())
	}
	if !f.useDashboardUI() {
		fmt.Printf("[UI] t=%6.1fs epoch=%-13s edges=%d(+%d)%s done=%.1f sent=%.1f req/s lat=%.1fms in_flight=%d conc=%d corpus=%d crashes=%d uniq=%d err=%d\n",
			elapsed,
			epochName,
			f.currentEdges,
			f.currentEdges-f.startEdges,
			satSuffix,
			doneRate,
			sentRate,
			avgLat,
			inFlight,
			f.currentConcurrency,
			len(f.corpus),
			f.totalCrashes,
			f.uniqueCrashes,
			f.totalErrors,
		)
		f.lastUIRender = now
		return
	}

	width := f.dashboardWidth()
	height := f.dashboardHeightHint()
	pathColWidth := maxInt(20, width-62)
	mutColWidth := maxInt(20, width-52)
	maxCrashRows := 5
	maxMutRows := 6
	maxSampleRows := 4
	maxEventRows := 4
	if height < 52 {
		maxCrashRows = 4
		maxMutRows = 4
		maxSampleRows = 3
		maxEventRows = 3
	}
	if height < 44 {
		maxCrashRows = 3
		maxMutRows = 2
		maxSampleRows = 2
		maxEventRows = 2
	}
	if height < 38 {
		maxCrashRows = 2
		maxMutRows = 1
		maxSampleRows = 1
		maxEventRows = 2
	}
	maxEndpoints := clampInt(height-(25+maxCrashRows+maxMutRows+maxSampleRows+maxEventRows), 4, 40)
	frac := 0.0
	timeBudgetSecs := f.cfg.TimeBudgetMinutes * 60.0
	if timeBudgetSecs > 0 {
		frac = elapsed / timeBudgetSecs
	}
	elapsedStr := formatMMSS(elapsed)
	budgetStr := formatMMSS(timeBudgetSecs)
	eps := make([]*EndpointStats, 0, len(f.endpointStats))
	for _, ep := range f.endpointStats {
		eps = append(eps, ep)
	}
	sortEndpointsForUI(eps, f.cfg.UIEndpointSort)
	totalEndpoints := len(eps)
	totalPages := 0
	pageIdx := 0
	pageStart := 0
	pageEnd := 0
	if maxEndpoints > 0 {
		totalPages = (totalEndpoints + maxEndpoints - 1) / maxEndpoints
	}
	if totalPages > 0 {
		if f.cfg.UIEndpointRotate {
			rotateEvery := math.Max(0.5, f.cfg.UIEndpointRotateSec)
			pageIdx = int(elapsed/rotateEvery) % totalPages
		}
		pageStart = pageIdx * maxEndpoints
		pageEnd = minInt(pageStart+maxEndpoints, totalEndpoints)
		eps = eps[pageStart:pageEnd]
	}
	crashEps := make([]*EndpointStats, 0, len(f.endpointStats))
	for _, ep := range f.endpointStats {
		if ep.Logged500 > 0 {
			crashEps = append(crashEps, ep)
		}
	}
	sort.Slice(crashEps, func(i, j int) bool {
		if crashEps[i].Logged500 != crashEps[j].Logged500 {
			return crashEps[i].Logged500 > crashEps[j].Logged500
		}
		if crashEps[i].Logged5xx != crashEps[j].Logged5xx {
			return crashEps[i].Logged5xx > crashEps[j].Logged5xx
		}
		if crashEps[i].Reqs != crashEps[j].Reqs {
			return crashEps[i].Reqs > crashEps[j].Reqs
		}
		return endpointKey(crashEps[i].Method, crashEps[i].Path) < endpointKey(crashEps[j].Method, crashEps[j].Path)
	})

	muts := make([]*MutationStats, 0, len(f.mutationStats))
	for _, ms := range f.mutationStats {
		muts = append(muts, ms)
	}
	sort.Slice(muts, func(i, j int) bool {
		if muts[i].NewEdges == muts[j].NewEdges {
			return muts[i].Attempts > muts[j].Attempts
		}
		return muts[i].NewEdges > muts[j].NewEdges
	})

	lines := make([]string, 0, 96)
	lines = append(lines, dashTopBorder(width, f.cfg.ASCIIUI))
	title := fmt.Sprintf(" Void ── %s ── stop: type 'stop' + Enter / Ctrl+C ", sanitizeText(f.target, 120))
	lines = append(lines, dashRow(title, width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
	bar := dashProgressBar(frac, 28, f.cfg.ASCIIUI)
	lines = append(lines, dashRow(fmt.Sprintf("  TIME  %s %s / %s      EPOCH %d: %s", bar, elapsedStr, budgetStr, epochIdx+1, epochName), width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashRow(
		fmt.Sprintf(
			"  COVERAGE %d edges (+%d new)%s    SPEED done:%.1f sent:%.1f req/s    CORPUS %d seeds",
			f.currentEdges, f.currentEdges-f.startEdges, satSuffix, doneRate, sentRate, len(f.corpus),
		),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow(
		fmt.Sprintf("  LATENCY %.1f ms(avg)    IN-FLIGHT %d", avgLat, inFlight),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow(
		fmt.Sprintf("  REQUESTS %d total       CRASHES %d (%d uniq)    ERRORS %d", f.totalDone, f.totalCrashes, f.uniqueCrashes, f.totalErrors),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	endpointHeader := fmt.Sprintf("  %-*s %6s %6s %6s %6s %6s %6s %7s", pathColWidth+6, "ENDPOINT", "reqs", "2xx", "401/3", "4xx", "500", "5xx", "edges")
	sortLabel := strings.ToLower(strings.TrimSpace(f.cfg.UIEndpointSort))
	if sortLabel == "" {
		sortLabel = "hot"
	}
	pageLabel := "1/1"
	if totalPages > 0 {
		pageLabel = fmt.Sprintf("%d/%d", pageIdx+1, totalPages)
	}
	viewFrom := 0
	viewTo := 0
	if totalEndpoints > 0 {
		viewFrom = pageStart + 1
		viewTo = maxInt(pageStart, pageEnd)
	}
	lines = append(lines, dashRow(
		fmt.Sprintf("  ENDPOINT VIEW  sort=%s  page=%s  rows=%d-%d/%d  rotate=%v(%.1fs)",
			sortLabel, pageLabel, viewFrom, viewTo, totalEndpoints, f.cfg.UIEndpointRotate, f.cfg.UIEndpointRotateSec),
		width,
		f.cfg.ASCIIUI,
	))
	lines = append(lines, dashRow(
		endpointHeader,
		width,
		f.cfg.ASCIIUI,
	))
	for i := 0; i < maxEndpoints; i++ {
		if i < len(eps) {
			ep := eps[i]
			pathDisp := dashTruncate(ep.Path, pathColWidth)
			label := fmt.Sprintf("  %-5s %-*s", ep.Method, pathColWidth, pathDisp)
			lines = append(lines, dashRow(
				fmt.Sprintf("%s %6d %6d %6d %6d %6d %6d +%5d", label, ep.Reqs, ep.S2xx, ep.S401403, ep.S4xx, ep.S500, ep.S5xx, ep.NewEdges),
				width,
				f.cfg.ASCIIUI,
			))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow(
		fmt.Sprintf("  %-*s %6s %6s %6s", pathColWidth+6, "ENDPOINTS WITH LOGGED 500", "reqs", "500", "5xx"),
		width,
		f.cfg.ASCIIUI,
	))
	for i := 0; i < maxCrashRows; i++ {
		if i < len(crashEps) {
			ep := crashEps[i]
			pathDisp := dashTruncate(ep.Path, pathColWidth)
			label := fmt.Sprintf("  %-5s %-*s", ep.Method, pathColWidth, pathDisp)
			lines = append(lines, dashRow(
				fmt.Sprintf("%s %6d %6d %6d", label, ep.Reqs, ep.Logged500, ep.Logged5xx),
				width,
				f.cfg.ASCIIUI,
			))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow(
		fmt.Sprintf("  %-*s %6s %7s %7s", mutColWidth+2, "MUTATION", "hits", "edges", "eff%"),
		width,
		f.cfg.ASCIIUI,
	))
	for i := 0; i < maxMutRows; i++ {
		if i < len(muts) {
			ms := muts[i]
			nameDisp := dashTruncate(ms.Name, mutColWidth)
			eff := 0.0
			if ms.Attempts > 0 {
				eff = float64(ms.NewEdges) / float64(ms.Attempts) * 100.0
			}
			lines = append(lines, dashRow(
				fmt.Sprintf("  %-*s %6d +%5d %6.1f%%", mutColWidth, nameDisp, ms.Attempts, ms.NewEdges, eff),
				width,
				f.cfg.ASCIIUI,
			))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("  RECENT REQUEST VALUES", width, f.cfg.ASCIIUI))
	for i := 0; i < maxSampleRows; i++ {
		ri := len(f.requestSamples) - 1 - i
		if ri >= 0 {
			lines = append(lines, dashRow("  "+dashTruncate(f.requestSamples[ri], width-6), width, f.cfg.ASCIIUI))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))

	lines = append(lines, dashHLine(width, f.cfg.ASCIIUI))
	lines = append(lines, dashRow("  RECENT EVENTS", width, f.cfg.ASCIIUI))
	f.eventMu.Lock()
	evSnap := make([]string, len(f.eventLog))
	copy(evSnap, f.eventLog)
	f.eventMu.Unlock()
	for i := 0; i < maxEventRows; i++ {
		// Events are appended (newest at end), so read backwards for most-recent-first display.
		ri := len(evSnap) - 1 - i
		if ri >= 0 {
			lines = append(lines, dashRow("  "+dashTruncate(evSnap[ri], width-6), width, f.cfg.ASCIIUI))
		} else {
			lines = append(lines, dashRow("", width, f.cfg.ASCIIUI))
		}
	}
	lines = append(lines, dashBottomBorder(width, f.cfg.ASCIIUI))

	f.clearDashboard()
	fmt.Print(strings.Join(lines, "\n"))
	if !strings.HasSuffix(lines[len(lines)-1], "\n") {
		fmt.Print("\n")
	}
	f.lastUIRender = now
}

func (f *Fuzzer) printFinalReport() {
	if f.stoppedByUser {
		fmt.Printf("\n\nFuzzing stopped by user.\n")
	} else {
		fmt.Printf("\n\nFuzzing complete.\n")
	}
	elapsed := time.Since(f.startTime).Seconds()
	doneRate := 0.0
	sentRate := 0.0
	avgLat := 0.0
	if elapsed > 0 {
		doneRate = float64(f.totalDone) / elapsed
		sentRate = float64(f.totalSent) / elapsed
	}
	if f.latencySamples > 0 {
		avgLat = f.latencyTotalMS / float64(f.latencySamples)
	}
	fmt.Printf("Requests done=%d sent=%d done/s=%.1f sent/s=%.1f\n", f.totalDone, f.totalSent, doneRate, sentRate)
	if f.baselineEdgesCeiling > 0 {
		aboveBaseline := f.currentEdges - f.baselineEdgesCeiling
		abovePct := 0.0
		if f.baselineEdgesCeiling > 0 {
			abovePct = float64(aboveBaseline) / float64(f.baselineEdgesCeiling) * 100.0
		}
		if abovePct < 0 {
			abovePct = 0
		}
		fmt.Printf("Coverage: %d baseline-ceiling=%d mutations-above=+%d (%.1f%% beyond baseline)\n",
			f.currentEdges, f.baselineEdgesCeiling, aboveBaseline, abovePct)
	} else if f.coverageCapacity > 0 {
		fmt.Printf("Coverage: %d -> %d (+%d) [bitmap=%.1f%% of %d]\n", f.startEdges, f.currentEdges, f.currentEdges-f.startEdges, f.coverageSaturationPct(), f.coverageCapacity)
	} else {
		fmt.Printf("Coverage: %d -> %d (+%d)\n", f.startEdges, f.currentEdges, f.currentEdges-f.startEdges)
	}
	fmt.Printf("Latency avg=%.1fms errors=%d crashes=%d uniq=%d\n", avgLat, f.totalErrors, f.totalCrashes, f.uniqueCrashes)
	fmt.Printf("Sequence engine: new_states_found=%d unique_workflows_persisted=%d\n", f.newStatesFound, f.workflowsPersisted)
	fmt.Printf("Sequence stop reasons: max_depth=%d failed_step=%d no_producible_value=%d no_followup_candidate=%d render_failed=%d\n",
		f.seqStopMaxDepth, f.seqStopFailedStep, f.seqStopNoProducedValue, f.seqStopNoFollowupCandidate, f.seqStopRenderFailed)
	if f.cfg.ResourceGraphEnabled {
		fmt.Printf("Dedup diagnostic: shape_duplicates_rejected=%d of_which_real_id_chain=%d upgraded_exemplar=%d\n",
			f.dedupDuplicateRejected, f.dedupRealIDChainRejected, f.dedupRealIDChainUpgrades)
	}
	if f.cfg.AutoAntiForgery {
		fmt.Printf("Anti-forgery tokens learned=%d pool=%d\n", atomic.LoadInt64(&f.antiForgeryLearned), f.antiForgeryTokenPoolSize())
	}

	type epRow struct {
		Key string
		S   *EndpointStats
	}
	rows := make([]epRow, 0, len(f.endpointStats))
	for k, v := range f.endpointStats {
		rows = append(rows, epRow{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].S.S500 != rows[j].S.S500 {
			return rows[i].S.S500 > rows[j].S.S500
		}
		if rows[i].S.S5xx != rows[j].S.S5xx {
			return rows[i].S.S5xx > rows[j].S.S5xx
		}
		if rows[i].S.Reqs != rows[j].S.Reqs {
			return rows[i].S.Reqs > rows[j].S.Reqs
		}
		if rows[i].S.NewEdges != rows[j].S.NewEdges {
			return rows[i].S.NewEdges > rows[j].S.NewEdges
		}
		return rows[i].Key < rows[j].Key
	})
	fmt.Printf("Top endpoints:\n")
	for i := 0; i < minInt(12, len(rows)); i++ {
		r := rows[i].S
		fmt.Printf("  %-5s %-46s req=%5d 2xx=%4d 401/3=%4d 4xx=%4d 500=%4d 5xx=%4d edges=+%d\n",
			r.Method, truncate(r.Path, 46), r.Reqs, r.S2xx, r.S401403, r.S4xx, r.S500, r.S5xx, r.NewEdges)
	}
	fmt.Printf("Endpoints with logged 500:\n")
	count500 := 0
	for _, row := range rows {
		if row.S.Logged500 <= 0 {
			continue
		}
		r := row.S
		fmt.Printf("  %-5s %-46s req=%5d 500=%4d 5xx=%4d\n",
			r.Method, truncate(r.Path, 46), r.Reqs, r.Logged500, r.Logged5xx)
		count500++
	}
	if count500 == 0 {
		fmt.Printf("  <none>\n")
	}
	blockedEndpoints := mapKeys(f.blockedEndpoints)
	sort.Strings(blockedEndpoints)
	endpoints500 := make([]map[string]any, 0, 16)
	endpoints500Observed := make([]map[string]any, 0, 16)
	filtered500Total := 0
	logged500Total := 0
	for _, row := range rows {
		if row.S.S500 > 0 {
			endpoints500Observed = append(endpoints500Observed, map[string]any{
				"method":       row.S.Method,
				"path":         row.S.Path,
				"reqs":         row.S.Reqs,
				"500":          row.S.S500,
				"5xx":          row.S.S5xx,
				"logged_500":   row.S.Logged500,
				"logged_5xx":   row.S.Logged5xx,
				"filtered_500": row.S.Filtered500,
				"filtered_5xx": row.S.Filtered5xx,
			})
			filtered500Total += row.S.Filtered500
			logged500Total += row.S.Logged500
		}
		if row.S.Logged500 <= 0 {
			continue
		}
		endpoints500 = append(endpoints500, map[string]any{
			"method": row.S.Method,
			"path":   row.S.Path,
			"reqs":   row.S.Reqs,
			"500":    row.S.Logged500,
			"5xx":    row.S.Logged5xx,
		})
		if len(endpoints500) >= 64 {
			break
		}
	}
	if len(endpoints500Observed) > 64 {
		endpoints500Observed = endpoints500Observed[:64]
	}
	triageSummary, topFindings := f.findingsReportData()
	if len(topFindings) > 0 {
		fmt.Printf("Top triaged findings:\n")
		for i := 0; i < minInt(8, len(topFindings)); i++ {
			tf := topFindings[i]
			score := toInt(tf["severity_score"])
			classification := toString(tf["classification"])
			stability := toString(tf["repro_stability"])
			fmt.Printf("  #%d [%d] %-12s %s %s (%s)\n", i+1, score, truncate(classification, 12), toString(tf["method"]), truncate(toString(tf["path"]), 52), stability)
		}
	}

	summary := map[string]any{
		"timestamp":                    time.Now().Format(time.RFC3339),
		"target_host":                  f.target,
		"elapsed_secs":                 elapsed,
		"requests_done":                f.totalDone,
		"requests_sent":                f.totalSent,
		"done_req_per_sec":             doneRate,
		"sent_req_per_sec":             sentRate,
		"avg_latency_ms":               avgLat,
		"antiforgery_tokens_learned":   atomic.LoadInt64(&f.antiForgeryLearned),
		"antiforgery_token_pool_size":  f.antiForgeryTokenPoolSize(),
		"errors":                       f.totalErrors,
		"crashes_total":                f.totalCrashes,
		"crashes_unique":               f.uniqueCrashes,
		"coverage_start_edges":         f.startEdges,
		"coverage_end_edges":           f.currentEdges,
		"coverage_new_edges":           f.currentEdges - f.startEdges,
		"coverage_capacity":            f.coverageCapacity,
		"coverage_saturation_pct":      f.coverageSaturationPct(),
		"corpus_size":                  len(f.corpus),
		"stopped_by_user":              f.stoppedByUser,
		"sequence_prob":                f.cfg.SequenceProb,
		"sequence_max_depth":           f.cfg.SequenceMaxDepth,
		"sequence_fanout":              f.cfg.SequenceFanout,
		"workflows_persisted":          f.workflowsPersisted,
		"dedup_duplicate_rejected":     f.dedupDuplicateRejected,
		"dedup_real_id_chain_rejected": f.dedupRealIDChainRejected,
		"dedup_real_id_chain_upgrades": f.dedupRealIDChainUpgrades,
		"seq_stop_max_depth":           f.seqStopMaxDepth,
		"seq_stop_failed_step":         f.seqStopFailedStep,
		"seq_stop_no_produced_value":   f.seqStopNoProducedValue,
		"seq_stop_no_followup_cand":    f.seqStopNoFollowupCandidate,
		"seq_stop_render_failed":       f.seqStopRenderFailed,
		"crash_log_file":               f.cfg.CrashFile,
		"unique_crash_log_file":        f.cfg.UniqueCrashFile,
		"structured_report_file":       f.cfg.ReportFile,
		"endpoints_500":                endpoints500,
		"endpoints_500_observed":       endpoints500Observed,
		"logged_500_total":             logged500Total,
		"filtered_500_total":           filtered500Total,
		"blocked_endpoints_500":        blockedEndpoints,
		"auth_blocked_endpoints":       f.authBlocked,
		"client_error_samples":         f.clientSamples,
		"request_value_samples":        f.requestSamples,
		"triage_summary":               triageSummary,
		"top_findings":                 topFindings,
	}
	writeJSONReport(f.cfg.SummaryFile, "Summary", summary)
	report := f.buildStructuredCrashReport(triageSummary)
	writeJSONReport(f.cfg.ReportFile, "Report", report)
	fmt.Printf("Crash log file: %s\n", f.cfg.CrashFile)
	fmt.Printf("Unique crash file: %s\n", f.cfg.UniqueCrashFile)
	fmt.Printf("Summary file: %s\n", f.cfg.SummaryFile)
	fmt.Printf("Report file: %s\n", f.cfg.ReportFile)
	if strings.TrimSpace(f.cfg.SARIFFile) != "" {
		sarif := f.buildSARIFReport()
		writeJSONReport(f.cfg.SARIFFile, "SARIF", sarif)
		fmt.Printf("SARIF file: %s\n", f.cfg.SARIFFile)
	}
}

// writeJSONReport marshals v as indented JSON and writes it to path, printing a loud
// WARNING (not silently discarding the error) if either the marshal or the write
// fails. A crash-finding report failing to write -- a full disk, a bad path, a
// permission error -- used to be swallowed here (`_ = os.WriteFile(...)`), so a run
// could finish, print "Summary file: <path>" as if it had succeeded, and leave the
// operator believing their findings were saved when the file was never written.
func writeJSONReport(path string, kind string, v any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Printf("WARNING: could not create directory for %s file %q: %v\n", kind, path, err)
		return
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("WARNING: could not encode %s file %q: %v\n", kind, path, err)
		return
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		fmt.Printf("WARNING: could not write %s file %q: %v\n", kind, path, err)
	}
}
