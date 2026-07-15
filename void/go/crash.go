package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// crash.go — Crash detection and deduplication: signature generation,
// JSONL recording, crash log management, exception type extraction.

// recordCrash logs the crash and returns true if it was a previously-unseen unique crash.
func (f *Fuzzer) recordCrash(res SendResult) bool {
	f.totalCrashes++
	f.addEvent(fmt.Sprintf("CRASH %d  %s %s  %s", res.Status, res.Item.Method, truncate(normalizePath(res.Item.Path), 60), truncate(res.Item.MutationName, 28)))
	elapsed := time.Since(f.startTime).Seconds()
	sig := f.crashSignature(res.Item.Method, res.Item.Path, res.Status, res.Item.MutationLabel, res.ExceptionType, res.Body)
	triage := f.triageCrash(res)
	crashHeaders := f.resolvedCrashHeaders(res.Item)
	crashAuthContext := maskedAuthContext(res.Item.Identity, crashHeaders)
	rec := CrashRecord{
		TS:            time.Now().Format(time.RFC3339),
		ElapsedSec:    fmt.Sprintf("%.3f", elapsed),
		Signature:     sig,
		Status:        res.Status,
		Method:        sanitizeText(res.Item.Method, 32),
		Path:          sanitizeText(res.Item.Path, 1024),
		Identity:      sanitizeText(res.Item.Identity, 64),
		Mutation:      sanitizeText(res.Item.MutationLabel, 2048),
		Payload:       sanitizeText(res.Item.Body, 8000),
		Response:      sanitizeText(res.Body, 8000),
		ExceptionType: res.ExceptionType,
		AuthContext:   crashAuthContext,
		Triage:        triage,
	}
	_ = f.crashWriter.Write(rec)
	if _, ok := f.uniqueCrashKeys[sig]; ok {
		return false
	}
	f.uniqueCrashKeys[sig] = struct{}{}
	f.uniqueCrashes++

	triageBudget := time.Duration(f.cfg.TimeBudgetMinutes * float64(time.Minute) * 0.15)
	skipExpensive := f.triageTimeSpent > triageBudget

	minimized := map[string]any{}
	pocItem := res.Item
	if f.cfg.MinimizeCrash && !skipExpensive {
		t0 := time.Now()
		if mi, changed, probes := f.minimizeCrashCandidate(res.Item, res.Status); changed {
			minimized = map[string]any{
				"changed":  true,
				"probes":   probes,
				"path":     sanitizeText(mi.Path, 1024),
				"payload":  sanitizeText(mi.Body, 8000),
				"mutation": sanitizeText(mi.MutationLabel, 1024),
			}
			pocItem = mi
			rec.Minimized = minimized
		} else if probes > 0 {
			minimized = map[string]any{
				"changed": false,
				"probes":  probes,
			}
		}
		f.triageTimeSpent += time.Since(t0)
	}

	repro := map[string]any{}
	if f.cfg.ReproRuns > 0 && !skipExpensive {
		t0 := time.Now()
		repro = f.reproCheckCrash(pocItem, res.Status)
		rec.Repro = repro
		f.triageTimeSpent += time.Since(t0)
	}
	actualReportHeaders := f.resolvedCrashHeaders(pocItem)
	authContext := maskedAuthContext(pocItem.Identity, actualReportHeaders)
	reportHeaders := redactedCrashHeaders(actualReportHeaders)
	curlCommand := f.buildInlineCurlCommand(pocItem, reportHeaders)
	reportPath := strings.ToValidUTF8(pocItem.Path, "?")
	if strings.TrimSpace(reportPath) == "" {
		reportPath = "/"
	}
	reportPayload := strings.ToValidUTF8(pocItem.Body, "?")
	reportMutation := strings.ToValidUTF8(pocItem.MutationLabel, "?")
	if strings.TrimSpace(reportMutation) == "" {
		reportMutation = strings.ToValidUTF8(pocItem.MutationName, "?")
	}
	pocFile := f.writeCrashPoC(sig, res, pocItem, triage, repro, minimized)
	timelineFile := f.writeExploitTimeline(sig, res, pocItem)
	rec.PocFile = pocFile
	rec.TimelineFile = timelineFile
	// Queue targeted follow-up requests for this unique crash to find bug variants.
	f.enqueueCrashReplay(res.Item, f.cfg.CrashReplayCount)

	uniq := map[string]any{
		"signature":      sig,
		"ts":             rec.TS,
		"elapsed_secs":   rec.ElapsedSec,
		"status_code":    rec.Status,
		"method":         rec.Method,
		"path":           rec.Path,
		"identity":       rec.Identity,
		"mutation":       rec.Mutation,
		"payload":        truncate(rec.Payload, 4000),
		"response_body":  truncate(rec.Response, 4000),
		"exception_type": rec.ExceptionType,
		"auth_context":   authContext,
		"triage":         triage,
		"repro":          repro,
		"minimized":      minimized,
		"poc_file":       pocFile,
		"timeline_file":  timelineFile,
	}
	_ = f.uniqueWriter.Write(uniq)

	// Boost this endpoint's weight for a bounded number of requests and activations.
	epKey := endpointKey(res.Item.Method, normalizePath(res.Item.Path))
	if f.cfg.CrashBoostRequests > 0 && f.cfg.CrashBoostWeight > 0 && f.crashBoostCount[epKey] < f.cfg.CrashBoostMaxPerEndpoint {
		f.crashBoost[epKey] = f.cfg.CrashBoostRequests
		f.crashBoostCount[epKey]++
	}

	f.findings = append(f.findings, CrashFinding{
		Signature:    sig,
		TS:           rec.TS,
		ElapsedSec:   rec.ElapsedSec,
		Method:       strings.ToValidUTF8(pocItem.Method, "?"),
		Path:         reportPath,
		Status:       rec.Status,
		Identity:     strings.ToValidUTF8(pocItem.Identity, "?"),
		Mutation:     reportMutation,
		Payload:      reportPayload,
		Response:     strings.ToValidUTF8(res.Body, "?"),
		Exception:    rec.ExceptionType,
		RequestHeads: cloneStringMap(reportHeaders),
		AuthContext:  cloneAnyMap(authContext),
		CurlCommand:  curlCommand,
		Triage:       cloneAnyMap(triage),
		Repro:        cloneAnyMap(repro),
		Minimized:    cloneAnyMap(minimized),
		PocFile:      pocFile,
		Timeline:     timelineFile,
	})
	f.crashLog = append(f.crashLog, map[string]any{
		"method":   rec.Method,
		"path":     rec.Path,
		"code":     rec.Status,
		"mutation": rec.Mutation,
		"triage":   triage,
	})
	f.recentCrashes = append(f.recentCrashes, rec)
	if len(f.recentCrashes) > 20 {
		f.recentCrashes = f.recentCrashes[len(f.recentCrashes)-20:]
	}
	return true
}

// exceptionTypeRe matches .NET exception class names in response bodies.
// Covers: "System.ArgumentException:", "Nop.Core.NopException:" etc.
var exceptionTypeRe = regexp.MustCompile(`(?:^|\s)((?:[A-Za-z0-9]+\.)+[A-Za-z]*Exception)\s*:`)

// extractExceptionType pulls the first .NET exception class name out of a response body.
// Used when the X-Exception-Type response header is unavailable (HasStarted race).
func extractExceptionType(body string) string {
	if len(body) == 0 {
		return ""
	}
	// Scan first 4096 bytes — stack traces always start at the top of the response.
	scan := body
	if len(scan) > 4096 {
		scan = scan[:4096]
	}
	if m := exceptionTypeRe.FindStringSubmatch(scan); len(m) > 1 {
		// Return only the short class name (last segment), e.g. "ArgumentException"
		full := m[1]
		if dot := strings.LastIndex(full, "."); dot >= 0 {
			return full[dot+1:]
		}
		return full
	}
	return ""
}

func hashWithFNV(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum64())
}

func normalizeCrashPathSignature(path string, includeQueryValues bool) string {
	norm := strings.TrimSpace(normalizePath(path))
	if norm == "" {
		return "/"
	}
	base := norm
	rawQuery := ""
	if i := strings.Index(norm, "?"); i >= 0 {
		base, rawQuery = norm[:i], norm[i+1:]
	}
	baseNorm := normalizeEndpointPath(base)
	if strings.TrimSpace(rawQuery) == "" {
		return baseNorm
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || len(q) == 0 {
		if includeQueryValues {
			return baseNorm + "?" + truncate(strings.TrimSpace(rawQuery), 120)
		}
		return baseNorm
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		ck := canonicalKey(k)
		if ck == "" {
			continue
		}
		if !includeQueryValues {
			parts = append(parts, ck)
			continue
		}
		v := normalizeValue(q.Get(k))
		if len(v) > 80 {
			v = v[:80]
		}
		parts = append(parts, ck+"="+v)
	}
	if len(parts) == 0 {
		return baseNorm
	}
	return baseNorm + "?" + strings.Join(parts, "&")
}

func normalizeCrashMutationLabel(label string) string {
	src := strings.TrimSpace(label)
	if src == "" {
		return ""
	}
	raw := strings.Split(src, "+")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		switch {
		case strings.HasPrefix(p, "mcat_"):
			out = append(out, p)
		case strings.HasPrefix(p, "havoc("):
			out = append(out, "havoc")
		case strings.HasPrefix(p, "mutate_"):
			out = append(out, p)
		case strings.HasPrefix(p, "crash_replay"):
			out = append(out, "crash_replay")
		}
	}
	if len(out) == 0 {
		return truncate(src, 64)
	}
	return strings.Join(dedupStrings(out), "+")
}

func stableResponseFingerprint(body string) string {
	s := strings.TrimSpace(body)
	if s == "" {
		return ""
	}
	if len(s) > 4096 {
		s = s[:4096]
	}

	var obj map[string]any
	if json.Unmarshal([]byte(s), &obj) == nil && len(obj) > 0 {
		keys := []string{"type", "title", "status", "error", "message", "detail", "exception"}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			v, ok := obj[k]
			if !ok {
				continue
			}
			vv := ""
			switch tv := v.(type) {
			case string:
				vv = tv
			case bool, json.Number, float64, float32, int, int32, int64, uint, uint32, uint64:
				vv = toString(tv)
			default:
				if b, err := json.Marshal(tv); err == nil {
					vv = string(b)
				} else {
					vv = toString(tv)
				}
			}
			vv = strings.TrimSpace(vv)
			if vv == "" {
				continue
			}
			vv = reUUIDBody.ReplaceAllString(vv, "<uuid>")
			vv = reHexLongBody.ReplaceAllString(vv, "<hex>")
			vv = reNumLongBody.ReplaceAllString(vv, "<num>")
			if len(vv) > 120 {
				vv = vv[:120]
			}
			parts = append(parts, canonicalKey(k)+"="+vv)
		}
		if len(parts) > 0 {
			return hashWithFNV(strings.Join(parts, "|"))
		}
	}

	s = reTraceIDField.ReplaceAllString(s, `"traceId":"<id>"`)
	s = reRequestIDField.ReplaceAllString(s, `"requestId":"<id>"`)
	s = reUUIDBody.ReplaceAllString(s, "<uuid>")
	s = reHexLongBody.ReplaceAllString(s, "<hex>")
	s = reNumLongBody.ReplaceAllString(s, "<num>")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return hashWithFNV(s)
}

func (f *Fuzzer) crashSignature(method, path string, status int, mutation, exceptionType, responseBody string) string {
	normPath := normalizeCrashPathSignature(path, f.cfg.CrashSigQueryValues)
	ex := strings.ToLower(strings.TrimSpace(exceptionType))
	mut := normalizeCrashMutationLabel(mutation)
	respFP := stableResponseFingerprint(responseBody)

	parts := []string{
		strings.ToUpper(strings.TrimSpace(method)),
		normPath,
		strconv.Itoa(status),
	}

	switch f.cfg.CrashSignatureMode {
	case "strict":
		if ex != "" {
			parts = append(parts, "ex="+ex)
		}
		if respFP != "" {
			parts = append(parts, "resp="+respFP)
		}
		if f.cfg.CrashSigMutation && mut != "" {
			parts = append(parts, "mut="+mut)
		}
	case "coarse":
		if ex != "" {
			parts = append(parts, "ex="+ex)
		} else if respFP != "" {
			parts = append(parts, "resp="+respFP)
		}
	default: // balanced
		if ex != "" {
			parts = append(parts, "ex="+ex)
		} else if respFP != "" {
			parts = append(parts, "resp="+respFP)
		}
		if f.cfg.CrashSigMutation && mut != "" {
			parts = append(parts, "mut="+mut)
		}
	}
	if len(parts) == 3 {
		if respFP != "" {
			parts = append(parts, "resp="+respFP)
		} else if mut != "" {
			parts = append(parts, "mut="+mut)
		} else {
			parts = append(parts, "generic")
		}
	}
	return hashWithFNV(strings.Join(parts, "|"))
}
