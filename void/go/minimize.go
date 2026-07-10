package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)


// minimize.go — Crash minimization (binary field removal) and repro verification.

func (f *Fuzzer) reproCheckCrash(item WorkItem, status int) map[string]any {
	runs := clampInt(f.cfg.ReproRuns, 0, 20)
	if runs <= 0 {
		return map[string]any{}
	}
	probeClient := &http.Client{
		Timeout:       time.Duration(f.cfg.ReproTimeoutSec * float64(time.Second)),
		Transport:     f.client.Transport,
		CheckRedirect: f.client.CheckRedirect,
		Jar:           f.client.Jar,
	}

	statuses := make([]int, 0, runs)
	hits := 0
	for i := 0; i < runs; i++ {
		res := f.sendOneWithClient(item, probeClient)
		if res.Err != nil {
			statuses = append(statuses, 0)
			continue
		}
		statuses = append(statuses, res.Status)
		if res.Status >= 500 {
			hits++
		}
	}
	pct := float64(hits) / math.Max(1, float64(runs)) * 100.0
	ok := pct >= clampFloat(f.cfg.ReproTargetPct, 1.0, 100.0)
	return map[string]any{
		"runs":                runs,
		"hits":                hits,
		"stability_pct":       formatPct(pct),
		"target_pct":          formatPct(f.cfg.ReproTargetPct),
		"stable_reproducible": ok,
		"probe_statuses":      statuses,
		"repro_status_class":  "5xx",
	}
}

// formatPct formats a float as "XX.X%" string for stability percentages.
func formatPct(pct float64) string {
	return fmt.Sprintf("%.1f", pct)
}


func (f *Fuzzer) minimizeCrashCandidate(item WorkItem, status int) (WorkItem, bool, int) {
	maxProbes := maxInt(0, f.cfg.MinimizeMaxProbes)
	if maxProbes == 0 {
		return item, false, 0
	}
	probes := 0
	changed := false

	probe := func(candidate WorkItem) bool {
		if probes >= maxProbes {
			return false
		}
		probes++
		r := f.sendOne(candidate)
		if r.Err != nil {
			return false
		}
		return r.Status >= 500
	}

	trySet := func(candidate WorkItem) bool {
		if candidate.Path == item.Path && candidate.Body == item.Body {
			return false
		}
		if probe(candidate) {
			item = candidate
			changed = true
			return true
		}
		return false
	}

	item = f.minimizeQueryPart(item, trySet)
	item = f.minimizeFormBody(item, trySet)
	item = f.minimizeJSONBody(item, trySet)
	item = f.minimizePathSegments(item, trySet)

	return item, changed, probes
}

func (f *Fuzzer) minimizeQueryPart(item WorkItem, trySet func(WorkItem) bool) WorkItem {
	p := item.Path
	idx := strings.Index(p, "?")
	if idx < 0 {
		return item
	}
	base := p[:idx]
	rawQuery := p[idx+1:]
	vals, err := url.ParseQuery(rawQuery)
	if err != nil || len(vals) == 0 {
		return item
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		candVals := cloneURLValues(vals)
		candVals.Del(k)
		candPath := base
		if q := candVals.Encode(); q != "" {
			candPath += "?" + q
		}
		cand := item
		cand.Path = candPath
		if trySet(cand) {
			item = cand
			vals = candVals
		}
	}
	return item
}

func (f *Fuzzer) minimizeFormBody(item WorkItem, trySet func(WorkItem) bool) WorkItem {
	ct := canonicalContentType(item.Headers)
	if !strings.Contains(ct, "application/x-www-form-urlencoded") {
		return item
	}
	vals, err := url.ParseQuery(item.Body)
	if err != nil || len(vals) == 0 {
		return item
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		candVals := cloneURLValues(vals)
		candVals.Del(k)
		cand := item
		cand.Body = candVals.Encode()
		if trySet(cand) {
			item = cand
			vals = candVals
		}
	}
	return item
}

func (f *Fuzzer) minimizeJSONBody(item WorkItem, trySet func(WorkItem) bool) WorkItem {
	ct := canonicalContentType(item.Headers)
	if !strings.Contains(ct, "json") && !reJSONStartAny.MatchString(item.Body) {
		return item
	}
	src := strings.TrimSpace(item.Body)
	if src == "" || !strings.HasPrefix(src, "{") {
		return item
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(src), &obj); err != nil || len(obj) == 0 {
		return item
	}
	keys := mapKeysAny(obj)
	sort.Strings(keys)
	for _, k := range keys {
		candObj := map[string]any{}
		for kk, vv := range obj {
			if kk == k {
				continue
			}
			candObj[kk] = vv
		}
		buf, _ := json.Marshal(candObj)
		cand := item
		cand.Body = string(buf)
		if trySet(cand) {
			item = cand
			obj = candObj
		}
	}
	return item
}

func (f *Fuzzer) minimizePathSegments(item WorkItem, trySet func(WorkItem) bool) WorkItem {
	raw := item.Path
	query := ""
	if idx := strings.Index(raw, "?"); idx >= 0 {
		query = raw[idx:]
		raw = raw[:idx]
	}
	segs := splitPathTokens(raw)
	if len(segs) == 0 {
		return item
	}
	for i := 0; i < len(segs); i++ {
		if !looksDynamicSegment(segs[i]) {
			continue
		}
		for _, repl := range []string{"0", "1", "id", "a"} {
			candSegs := append([]string{}, segs...)
			candSegs[i] = repl
			candPath := "/" + strings.Join(candSegs, "/") + query
			cand := item
			cand.Path = candPath
			if trySet(cand) {
				item = cand
				segs = candSegs
				break
			}
		}
	}
	return item
}

func looksDynamicSegment(seg string) bool {
	s := strings.TrimSpace(seg)
	if s == "" {
		return false
	}
	if isPathPlaceholderValue(s) {
		return true
	}
	if reAllDigits.MatchString(s) || reUUIDLike.MatchString(s) || reBizIDLike.MatchString(s) {
		return true
	}
	if len(s) >= 8 && (hasASCIIDigit(s) || strings.ContainsAny(s, "-_")) {
		return true
	}
	return false
}
