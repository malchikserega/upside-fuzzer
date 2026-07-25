package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sequence.go — Stateful sequences: producer→consumer chain discovery,
// runtime value extraction from requests/responses, followup prioritization.

// stateNoveltyBonus is the Energy award for a sequence step reaching a
// never-seen workflow-state signature (Top-20 #12). Chosen to be comparable to
// a solid multi-edge CoverageDelta hit (edgeShare of a few units per request in
// practice), so state novelty competes with, rather than being drowned out by,
// ordinary coverage-driven energy.
const stateNoveltyBonus = 5.0

func (f *Fuzzer) enqueueSequenceFollowups(res SendResult) int {
	source := res.Item
	if source.SeqDepth >= maxInt(1, f.cfg.SequenceMaxDepth) {
		f.maybePersistSequence(res)
		return 0
	}

	state := source.SeqState
	if state == nil {
		// Start a new sequence state
		state = &SequenceState{
			ID:         fmt.Sprintf("seq-%d", rand.Int63()),
			Depth:      0,
			Values:     make(map[string]string),
			Provenance: make(map[string]string),
			History:    []SequenceStep{},
		}
	}

	// Record this step in the history
	// Clone headers to prevent mutation
	clonedHeaders := make(map[string]string)
	for k, v := range source.Headers {
		clonedHeaders[k] = v
	}

	step := SequenceStep{
		TemplateID:    source.TemplateID,
		Method:        source.Method,
		Path:          source.Path,
		Headers:       clonedHeaders,
		Body:          source.Body,
		Status:        res.Status,
		CoverageDelta: res.CoverageDelta,
		MutationLabel: source.MutationLabel,
	}
	state.History = append(state.History, step)

	if res.CoverageDelta > 0 {
		state.Energy += float64(res.CoverageDelta)
	}

	// Top-20 #12 -- state-reward sequence search: reward reaching a workflow
	// SHAPE (ordered method+normpath+status-class triples) never seen before in
	// this run, not just a new edge. This is deliberately coarse (no resource
	// lifecycle/typed state graph -- see ARCHITECTURE_REVIEW.md §5) but it is
	// enough to make the sequence engine's own search prioritize genuinely novel
	// multi-step workflows over re-treading ones it has already explored, which
	// plain edge-coverage reward can't distinguish (a 3rd identical GET after a
	// POST looks the same to the coverage bitmap as the 1st).
	sig := sequenceStateSignature(state)
	newState := false
	if _, seen := f.seenStateSigs[sig]; !seen {
		f.seenStateSigs[sig] = struct{}{}
		newState = true
		state.Energy += stateNoveltyBonus
		f.newStatesFound++
		if f.newStatesFound <= 5 || f.newStatesFound%25 == 0 {
			f.addEvent(fmt.Sprintf("NEW STATE  seq(d%d) %s  (%d total)", state.Depth+1, truncate(sig, 80), f.newStatesFound))
		}
	}

	// Extract values and bind to this sequence context
	info := f.depIndex[source.TemplateID]
	producedDeps := mapKeys(info.Writes)
	producedIDKeys := mapKeys(info.IDWrites)
	entityIDs := extractEntityIDs(res.Body, res.Headers)

	provKey := fmt.Sprintf("%s %s", source.Method, source.Path)

	if rid := inferResourceIDKeyFromPath(source.Path); rid != "" {
		for _, eid := range entityIDs {
			state.Values[rid] = eid
			state.Values["id"] = eid
			state.Provenance[rid] = provKey
			state.Provenance["id"] = provKey

			// Also add to global runtime store for baseline epoch (fallback)
			_ = f.runtime.addValue(rid, eid)
			_ = f.runtime.addValue("id", eid)
		}
	}

	if len(entityIDs) > 0 {
		for _, dep := range producedDeps {
			state.Values[dep] = entityIDs[0]
			state.Provenance[dep] = provKey
			f.runtime.addDepValue(dep, entityIDs[0])
		}
	}

	// If the step failed (4xx/5xx), we might still persist if we reached depth, but we don't branch further
	if res.Status >= 400 {
		f.maybePersistSequence(res)
		return 0
	}

	if len(producedDeps) == 0 && len(entityIDs) == 0 {
		meta := f.meta[source.TemplateID]
		if meta.Method != "POST" && meta.Method != "PUT" && meta.Method != "PATCH" {
			return 0
		}
	}

	followups := f.findFollowups(source.TemplateID, source.Method, normalizePath(source.Path), producedDeps, producedIDKeys)
	if len(followups) == 0 {
		f.maybePersistSequence(res)
		return 0
	}

	fanout := minInt(maxInt(1, f.cfg.SequenceFanout), len(followups))
	if newState {
		// A sequence that just reached a never-seen workflow shape gets one extra
		// branch of search budget -- it's exactly the kind of exploration DeepREST/
		// EvoMaster's state-based search prioritizes over re-treading known states.
		fanout = minInt(fanout+1, len(followups))
	}
	enqueued := 0
	for _, tid := range followups[:fanout] {
		// Clone state for branching
		nextState := &SequenceState{
			ID:         state.ID,
			Depth:      state.Depth + 1,
			Values:     make(map[string]string, len(state.Values)),
			Provenance: make(map[string]string, len(state.Provenance)),
			History:    make([]SequenceStep, len(state.History)),
			Energy:     state.Energy,
		}
		for k, v := range state.Values {
			nextState.Values[k] = v
		}
		for k, v := range state.Provenance {
			nextState.Provenance[k] = v
		}
		copy(nextState.History, state.History)

		// We need a dummy item to pass the SeqState to renderTemplate so it prioritizes it
		dummy := &WorkItem{SeqState: nextState}
		mode := "none"
		if rand.Float64() >= 0.75 {
			mode = "mutate"
		}

		item, err := f.renderTemplateContext(tid, mode, 1, -1, dummy)
		if err != nil {
			continue
		}

		if len(entityIDs) > 0 && strings.Contains(item.Path, "{") {
			item.Path = rePathParam.ReplaceAllString(item.Path, entityIDs[0])
		}

		item.SeqDepth = nextState.Depth
		item.SeqState = nextState
		item.EpochName = "Sequence"
		item.EpochIdx = source.EpochIdx
		item.Identity = source.Identity
		seqLabel := fmt.Sprintf("seq(d%d:%s %s->%s)", item.SeqDepth, source.Method, normalizePath(source.Path), item.Method)
		if item.MutationLabel != "seed" {
			seqLabel += "+" + item.MutationLabel
		}
		item.MutationLabel = seqLabel
		item.MutationName = "sequence"
		item.Trace = f.extendTrace(source.Trace, item)

		if len(f.sequenceQueue) >= sequenceQueueMax {
			f.sequenceQueue = f.sequenceQueue[1:]
		}
		f.sequenceQueue = append(f.sequenceQueue, item)
		enqueued++
	}

	if enqueued == 0 {
		f.maybePersistSequence(res)
	}

	return enqueued
}

func (f *Fuzzer) maybePersistSequence(res SendResult) {
	state := res.Item.SeqState
	if state == nil || state.Depth < 2 { // Depth is 0-indexed, so 2 means length 3
		return
	}

	// Must be mostly successful
	successCount := 0
	for _, step := range state.History {
		if step.Status >= 200 && step.Status < 400 {
			successCount++
		}
	}
	successRatio := float64(successCount) / float64(len(state.History))

	// Benchmark event stream (BENCHMARK_PLAN.md §12 sequence_event.jsonl, a
	// no-op unless -event-log was passed): every sequence that reached this
	// terminal point (depth>=2) is logged here, regardless of whether it goes
	// on to be persisted to disk below -- "sequences attempted" needs the full
	// population, not just the successful subset.
	f.logSequenceEvent(state, successRatio >= 0.5)

	// Must have produced some coverage overall
	if state.Energy <= 0 {
		return
	}

	if successRatio < 0.5 {
		return
	}

	// Dedup by final workflow shape (Top-20 #12): many sequences reach the exact
	// same (method,normpath,status-class) shape via different concrete IDs/values
	// -- those are equivalent workflows for reporting purposes, so only the first
	// one is persisted to disk. Addresses ARCHITECTURE_REVIEW.md §5 weakness #3
	// ("no dedup of equivalent workflows").
	sig := sequenceStateSignature(state)
	if _, dup := f.persistedWorkflowSigs[sig]; dup {
		return
	}
	f.persistedWorkflowSigs[sig] = struct{}{}

	// Save to disk
	f.persistWorkflow(state)
	f.workflowsPersisted++
}

// logSequenceEvent appends one row to sequence_event.jsonl (BENCHMARK_PLAN.md
// §12), a no-op unless -event-log was passed. new_coverage reports
// state.Energy as the closest available proxy -- it blends real coverage
// gain with the state-novelty bonus (Top-20 #12, stateNoveltyBonus), not a
// pure edge count; produced_bug_id is left empty, since this codebase has no
// mechanism today correlating a specific crash/finding back to the sequence
// that produced it (a genuine gap, not silently faked here).
func (f *Fuzzer) logSequenceEvent(state *SequenceState, successFlag bool) {
	if f.sequenceEventWriter == nil {
		return
	}
	steps := make([]map[string]any, 0, len(state.History))
	for _, step := range state.History {
		steps = append(steps, map[string]any{
			"method": step.Method,
			"path":   step.Path,
			"status": step.Status,
		})
	}
	row := map[string]any{
		"run_id":             f.cfg.RunID,
		"ts":                 time.Now().Unix(),
		"sequence_id":        state.ID,
		"shape_signature":    sequenceStateSignature(state),
		"depth":              state.Depth,
		"steps":              steps,
		"harvested_entities": state.Values,
		"success_flag":       successFlag,
		"new_coverage":       state.Energy,
		"produced_bug_id":    "",
	}
	_ = f.sequenceEventWriter.Write(row)
}

// sequenceStateSignature computes a coarse state signature for a sequence: the
// ordered SHAPE of (method, normalized-path, status-class) steps taken so far.
// Two sequences that reach the same shape via different concrete IDs/payloads
// are treated as the same "state" -- intentionally coarse (no resource
// lifecycle/typed state graph), but enough to reward reaching a new workflow
// shape instead of only a new coverage edge (Top-20 #12).
func sequenceStateSignature(state *SequenceState) string {
	parts := make([]string, 0, len(state.History))
	for _, step := range state.History {
		// normalizeEndpointPath (not normalizePath) so different concrete resource
		// ids collapse to the same route template -- otherwise every sequence would
		// look "new" purely because it touched a different numeric/UUID id.
		parts = append(parts, fmt.Sprintf("%s %s:%d", step.Method, normalizeEndpointPath(step.Path), statusClass(step.Status)))
	}
	return strings.Join(parts, "|")
}

// statusClass buckets an HTTP status into a coarse class for state-signature
// purposes (2xx/3xx/4xx/5xx), so e.g. 200 vs 201 don't count as different states
// but 200 vs 404 do.
func statusClass(status int) int {
	switch {
	case status >= 200 && status < 300:
		return 2
	case status >= 300 && status < 400:
		return 3
	case status >= 400 && status < 500:
		return 4
	case status >= 500:
		return 5
	default:
		return 0
	}
}

func (f *Fuzzer) persistWorkflow(state *SequenceState) {
	if f.cfg.TimelineDir == "" {
		return
	}
	outDir := filepath.Join(filepath.Dir(f.cfg.TimelineDir), "workflows")
	_ = os.MkdirAll(outDir, 0o755)

	fnameBase := fmt.Sprintf("workflow_d%d_%s", state.Depth+1, state.ID)
	fpathJSON := filepath.Join(outDir, fnameBase+".json")
	fpathSH := filepath.Join(outDir, fnameBase+".sh")

	buf, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = os.WriteFile(fpathJSON, buf, 0o644)
	}

	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString(fmt.Sprintf("# Auto-generated Deep Workflow Reproduction Script (Depth: %d, Energy: %.0f)\n\n", state.Depth+1, state.Energy))
	sb.WriteString(fmt.Sprintf("TARGET=\"%s\"\n\n", f.target))

	for i, step := range state.History {
		sb.WriteString(fmt.Sprintf("# Step %d: %s %s (Expected Status: %d, Mut: %s)\n", i+1, step.Method, step.Path, step.Status, step.MutationLabel))
		sb.WriteString(fmt.Sprintf("curl -i -X %s \"$TARGET%s\" \\\n", step.Method, step.Path))

		for k, v := range step.Headers {
			sb.WriteString(fmt.Sprintf("  -H '%s: %s' \\\n", k, strings.ReplaceAll(v, "'", "'\\''")))
		}

		if step.Body != "" {
			sb.WriteString(fmt.Sprintf("  -d '%s'\n", strings.ReplaceAll(step.Body, "'", "'\\''")))
		} else {
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	_ = os.WriteFile(fpathSH, []byte(sb.String()), 0o755)
}

func (f *Fuzzer) findFollowups(sourceID int, sourceMethod, sourceNorm string, producedDeps, producedIDKeys []string) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, 16)
	for _, dep := range producedDeps {
		for _, tid := range f.depConsumers[dep] {
			if tid == sourceID {
				continue
			}
			if f.isTemplateBlocked(tid) {
				continue
			}
			if _, ok := seen[tid]; ok {
				continue
			}
			seen[tid] = struct{}{}
			out = append(out, tid)
		}
	}
	for _, idk := range producedIDKeys {
		for _, tid := range f.idConsumers[canonicalKey(idk)] {
			if tid == sourceID {
				continue
			}
			if f.isTemplateBlocked(tid) {
				continue
			}
			if _, ok := seen[tid]; ok {
				continue
			}
			seen[tid] = struct{}{}
			out = append(out, tid)
		}
	}
	for _, tid := range f.activeIDs {
		if tid == sourceID {
			continue
		}
		if f.isTemplateBlocked(tid) {
			continue
		}
		if _, ok := seen[tid]; ok {
			continue
		}
		m := f.meta[tid]
		sameFamily := m.Norm == sourceNorm || strings.HasPrefix(m.Norm, sourceNorm+"/") || strings.HasPrefix(sourceNorm, m.Norm+"/")
		if !sameFamily {
			continue
		}
		if m.Method == sourceMethod && m.Norm == sourceNorm {
			continue
		}
		seen[tid] = struct{}{}
		out = append(out, tid)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a := f.meta[out[i]]
		b := f.meta[out[j]]
		return followupPriority(sourceMethod, sourceNorm, a.Method, a.Norm) < followupPriority(sourceMethod, sourceNorm, b.Method, b.Norm)
	})
	return out
}

func followupPriority(sourceMethod, sourceNorm, candMethod, candNorm string) int {
	s := strings.ToUpper(sourceMethod)
	c := strings.ToUpper(candMethod)
	score := 100
	if s == "POST" {
		switch c {
		case "GET":
			score -= 40
		case "PUT", "PATCH":
			score -= 25
		case "DELETE":
			score -= 12
		}
	} else if s == "PUT" || s == "PATCH" {
		switch c {
		case "GET":
			score -= 35
		case "DELETE":
			score -= 18
		}
	} else if s == "GET" {
		switch c {
		case "PUT", "PATCH":
			score -= 20
		case "DELETE":
			score -= 10
		}
	}
	if candNorm == sourceNorm && c == "GET" {
		score -= 8
	}
	if len(candNorm) > len(sourceNorm) {
		score -= 5
	}
	if strings.Contains(candNorm, "{") && strings.Contains(candNorm, "}") {
		score -= 3
	}
	return score
}

func (f *Fuzzer) learnFromRequestContext(path, body string) int {
	learned := 0
	vals := make([][2]string, 0, 32)
	rels := make([][4]string, 0, 64)

	pathVals := extractPathTokens(path)
	vals = append(vals, pathVals...)
	if rid := inferResourceIDKeyFromPath(path); rid != "" && len(pathVals) > 0 {
		vals = append(vals, [2]string{rid, pathVals[len(pathVals)-1][1]})
	}

	bodyVals := make([][2]string, 0, 32)
	bodyRels := make([][4]string, 0, 64)
	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			extractJSONRuntimeValues(js, &bodyVals, &bodyRels, 0)
		}
	} else if strings.Contains(body, "=") {
		if valsQ, err := url.ParseQuery(body); err == nil {
			for k, arr := range valsQ {
				if strings.TrimSpace(k) == "" || len(arr) == 0 {
					continue
				}
				v := normalizeValue(arr[0])
				if !isUsefulValue(v) {
					continue
				}
				bodyVals = append(bodyVals, [2]string{k, v})
			}
		}
	}
	vals = append(vals, bodyVals...)
	rels = append(rels, bodyRels...)

	pathIDs := filterIDLikePairs(pathVals)
	bodyIDs := filterIDLikePairs(bodyVals)
	for i := 0; i < minInt(8, len(pathIDs)); i++ {
		for j := 0; j < minInt(12, len(bodyIDs)); j++ {
			rels = append(rels, [4]string{pathIDs[i][0], pathIDs[i][1], bodyIDs[j][0], bodyIDs[j][1]})
		}
	}

	for _, kv := range vals {
		if f.runtime.addValue(kv[0], kv[1]) {
			learned++
		}
	}
	for _, rr := range rels {
		if f.runtime.addRelation(rr[0], rr[1], rr[2], rr[3]) {
			learned++
		}
	}
	return learned
}

func (f *Fuzzer) learnFromResponse(body string, headers map[string]string) int {
	learned := 0
	vals := make([][2]string, 0, 32)
	rels := make([][4]string, 0, 64)

	location := headers["Location"]
	if location == "" {
		location = headers["location"]
	}
	if location != "" {
		if u, err := url.Parse(location); err == nil {
			vals = append(vals, extractPathTokens(u.Path)...)
		} else {
			vals = append(vals, extractPathTokens(location)...)
		}
	}

	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			extractJSONRuntimeValues(js, &vals, &rels, 0)
		}
	}
	for _, kv := range vals {
		if f.runtime.addValue(kv[0], kv[1]) {
			learned++
		}
	}
	for _, rr := range rels {
		if f.runtime.addRelation(rr[0], rr[1], rr[2], rr[3]) {
			learned++
		}
	}
	return learned
}

var (
	depNameNoise = map[string]struct{}{
		"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}, "post": {}, "put": {}, "get": {}, "delete": {},
		"patch": {}, "query": {}, "header": {}, "body": {}, "path": {}, "data": {}, "audit": {}, "created": {},
		"updated": {}, "writer": {}, "reader": {}, "response": {}, "request": {}, "status": {}, "name": {},
		"primary": {}, "reverse": {}, "notes": {}, "revision": {}, "true": {}, "false": {},
	}
	pathTokenNoise = map[string]struct{}{
		"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}, "pairs": {}, "pair": {}, "rates": {}, "rate": {},
		"currencies": {}, "currency": {}, "users": {}, "user": {}, "accounts": {}, "account": {},
	}
	resourcePathNoise = map[string]struct{}{"v1": {}, "v2": {}, "v3": {}, "api": {}, "exchange": {}}
	runtimeLearnKeys  = []string{"id", "code", "name", "externalid", "status", "type", "revision", "key", "slug"}
)

func inferDependencyKeys(depName string) []string {
	dep := strings.ToLower(depName)
	tokens := splitNonAlnum(dep)
	keys := []string{}
	hasAnyID := false
	for _, t := range tokens {
		if t == "id" || strings.HasSuffix(t, "id") {
			hasAnyID = true
			break
		}
	}
	for _, m := range reWordID.FindAllStringSubmatch(dep, -1) {
		if len(m) < 2 {
			continue
		}
		base := m[1]
		if _, bad := depNameNoise[base]; !bad && base != "" {
			keys = append(keys, base+"Id")
		}
	}
	for i, t := range tokens {
		if _, bad := depNameNoise[t]; bad || t == "" {
			continue
		}
		if strings.HasSuffix(t, "id") && len(t) > 2 {
			base := t[:len(t)-2]
			if _, bad := depNameNoise[base]; !bad && base != "" {
				keys = append(keys, base+"Id")
			}
		}
		if t == "id" {
			if i > 0 {
				prev := tokens[i-1]
				if _, bad := depNameNoise[prev]; !bad && prev != "" {
					keys = append(keys, singularize(prev)+"Id")
				}
			}
			keys = append(keys, "id")
		}
	}
	if hasAnyID {
		for _, t := range tokens {
			if _, bad := depNameNoise[t]; bad || t == "" {
				continue
			}
			keys = append(keys, singularize(t)+"Id")
		}
	}
	if !hasAnyID && len(keys) == 0 {
		return nil
	}
	keys = append(keys, "id")
	keys = dedupStrings(keys)
	if len(keys) > 10 {
		keys = keys[:10]
	}
	return keys
}

func extractPathTokens(path string) [][2]string {
	out := make([][2]string, 0, 16)
	if path == "" {
		return out
	}
	for _, token := range strings.Split(path, "/") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		if _, bad := pathTokenNoise[strings.ToLower(t)]; bad {
			continue
		}
		hasShape := strings.ContainsAny(t, "0123456789") || strings.Contains(t, "-") || strings.Contains(t, "_")
		if !hasShape {
			continue
		}
		if len(t) > 128 {
			continue
		}
		out = append(out, [2]string{"id", t})
	}
	return out
}

func inferResourceIDKeyFromPath(path string) string {
	if path == "" {
		return ""
	}
	tokens := []string{}
	for _, token := range strings.Split(path, "/") {
		t := strings.ToLower(strings.TrimSpace(token))
		if t == "" {
			continue
		}
		if _, bad := resourcePathNoise[t]; bad {
			continue
		}
		if strings.Contains(t, "{") || strings.Contains(t, "}") || t == "-" {
			continue
		}
		if _, err := strconv.Atoi(t); err == nil {
			continue
		}
		if strings.ContainsAny(t, "0123456789") {
			continue
		}
		tokens = append(tokens, t)
	}
	if len(tokens) == 0 {
		return ""
	}
	return singularize(tokens[len(tokens)-1]) + "Id"
}

func extractJSONRuntimeValues(node any, outVals *[][2]string, outRels *[][4]string, depth int) {
	if depth > 6 {
		return
	}
	switch tv := node.(type) {
	case map[string]any:
		locals := make([][2]string, 0, len(tv))
		for k, v := range tv {
			kn := canonicalKey(k)
			isLearnable := strings.HasSuffix(kn, "id")
			if !isLearnable {
				for _, rk := range runtimeLearnKeys {
					if kn == rk || strings.HasSuffix(kn, rk) {
						isLearnable = true
						break
					}
				}
			}
			if isLearnable {
				if scalar, ok := toUsefulScalar(v); ok {
					*outVals = append(*outVals, [2]string{k, scalar})
					locals = append(locals, [2]string{k, scalar})
				}
			}
			if m, ok := v.(map[string]any); ok {
				if nested, ok := m["id"]; ok {
					if scalar, ok := toUsefulScalar(nested); ok {
						nk := k + "Id"
						*outVals = append(*outVals, [2]string{nk, scalar})
						locals = append(locals, [2]string{nk, scalar})
					}
				} else if nested, ok := m["Id"]; ok {
					if scalar, ok := toUsefulScalar(nested); ok {
						nk := k + "Id"
						*outVals = append(*outVals, [2]string{nk, scalar})
						locals = append(locals, [2]string{nk, scalar})
					}
				}
			}
			extractJSONRuntimeValues(v, outVals, outRels, depth+1)
		}
		if len(locals) > 1 {
			if len(locals) > 10 {
				locals = locals[:10]
			}
			for i := 0; i < len(locals); i++ {
				for j := i + 1; j < len(locals); j++ {
					*outRels = append(*outRels, [4]string{locals[i][0], locals[i][1], locals[j][0], locals[j][1]})
				}
			}
		}
	case []any:
		limit := minInt(100, len(tv))
		for i := 0; i < limit; i++ {
			extractJSONRuntimeValues(tv[i], outVals, outRels, depth+1)
		}
	}
}

func extractEntityIDs(body string, headers map[string]string) []string {
	out := []string{}
	if reJSONStartAny.MatchString(body) {
		var js any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			if m, ok := js.(map[string]any); ok {
				if id, ok := m["id"]; ok {
					if s, ok := toUsefulScalar(id); ok {
						out = append(out, s)
					}
				} else if id, ok := m["Id"]; ok {
					if s, ok := toUsefulScalar(id); ok {
						out = append(out, s)
					}
				}
				if data, ok := m["data"].([]any); ok {
					for _, el := range data {
						if mm, ok := el.(map[string]any); ok {
							if id, ok := mm["id"]; ok {
								if s, ok := toUsefulScalar(id); ok {
									out = append(out, s)
								}
							} else if id, ok := mm["Id"]; ok {
								if s, ok := toUsefulScalar(id); ok {
									out = append(out, s)
								}
							}
						}
					}
				}
			}
		}
	}
	loc := headers["Location"]
	if loc == "" {
		loc = headers["location"]
	}
	if loc != "" {
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		if len(parts) > 0 {
			last := strings.TrimSpace(parts[len(parts)-1])
			if isUsefulValue(last) {
				out = append(out, last)
			}
		}
	}
	return uniqStrings(filterUsefulStrings(out))
}

// enqueueCrashReplay queues n follow-up work items after a unique crash is found.
// It re-renders the crashing template with varying mutation modes to find bug variants.
func (f *Fuzzer) enqueueCrashReplay(item WorkItem, n int) {
	if n <= 0 || f.isTemplateBlocked(item.TemplateID) {
		return
	}
	epKey := endpointKey(item.Method, normalizePath(item.Path))
	if f.cfg.CrashReplayPerEndpoint > 0 {
		remaining := f.cfg.CrashReplayPerEndpoint - f.replayByEndpoint[epKey]
		if remaining <= 0 {
			return
		}
		n = minInt(n, remaining)
	}
	queueMax := maxInt(1, f.cfg.CrashReplayQueueMax)
	added := 0
	modes := []string{"mutate", "havoc", "mutate", "havoc", "havoc"}
	for i := 0; i < n; i++ {
		if len(f.replayQueue) >= queueMax {
			break
		}
		mode := modes[i%len(modes)]
		depth := 1 + (i / len(modes))
		rendered, err := f.renderTemplate(item.TemplateID, mode, depth, -1)
		if err != nil {
			// Fall back to replaying the exact crashing item.
			replay := item
			replay.MutationLabel = fmt.Sprintf("crash_replay_%d", i)
			replay.MutationName = "crash_replay"
			replay.EpochName = "Replay"
			f.replayQueue = append(f.replayQueue, replay)
			added++
			continue
		}
		rendered.MutationLabel = "crash_replay+" + rendered.MutationLabel
		rendered.MutationName = "crash_replay"
		rendered.EpochName = "Replay"
		f.replayQueue = append(f.replayQueue, rendered)
		added++
	}
	if added > 0 {
		f.replayByEndpoint[epKey] += added
	}
}
