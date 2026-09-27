package engine

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
	if item.BodyTree != nil {
		item = f.minimizeBodyTree(item, trySet)
	} else {
		item = f.minimizeFormBody(item, trySet)
		item = f.minimizeJSONBody(item, trySet)
	}
	item = f.minimizePathSegments(item, trySet)

	return item, changed, probes
}

// minimizeBodyTree is minimizeJSONBody's typed-body counterpart (typed
// structural mutation Stage 7): where minimizeJSONBody only ever drops
// TOP-LEVEL keys of a re-parsed map, this recurses into nested objects and
// also shrinks arrays element-by-element, since a typed tree's structure is
// already in hand and doesn't need re-parsing to walk.
//
// Operates on a clone of item.BodyTree, never the original -- res.Item (and
// its BodyTree pointer) is still read elsewhere in the crash-recording path
// (crash.go's recordCrash captures res.Item.Body as a plain string snapshot
// before this ever runs, but pocItem starts as a copy of the SAME res.Item,
// sharing the same *BodyValue pointer until a successful minimization
// replaces it) -- mutating that shared tree in place, even with careful
// revert-on-reject, is an unnecessary aliasing risk this codebase has
// already been burned by twice in Stage 5 (see body_mutate.go's
// opNestingDepthStressAdversarial fix). A clone costs one bounded-depth copy
// and removes the risk entirely.
//
// Each attempted change eagerly re-serializes into candidate.Body (not just
// candidate.BodyTree) before calling trySet -- trySet's no-op guard
// (minimizeCrashCandidate, above) does a plain string-equality check on Body
// BEFORE prepareItemForSend would normally re-derive it from BodyTree at
// send time, so skipping this resync would make every real tree edit look
// like a no-op and minimization would never converge. The exact serialized
// form (JSON) doesn't need to match the real wire content-type here --
// prepareItemForSend re-derives the correct one from BodyTree right before
// every actual probe request goes out -- it only needs to reliably differ
// whenever the tree really changed.
func (f *Fuzzer) minimizeBodyTree(item WorkItem, trySet func(WorkItem) bool) WorkItem {
	if item.BodyTree == nil {
		return item
	}
	root := item.BodyTree.clone()
	attempt := func() bool {
		cand := item
		cand.BodyTree = root
		cand.Body = root.ToJSON()
		if trySet(cand) {
			item.BodyTree = root
			item.Body = cand.Body
			return true
		}
		return false
	}
	minimizeBodyValueNode(root, 0, attempt)
	return item
}

// minimizeBodyValueNode walks node in place, trying to drop each object
// field / shrink each array by one element at a time, keeping the change
// only when attempt() (a probe against the CURRENT root, whatever node is
// nested under it) reports success; otherwise the exact removed element is
// reinserted at its original position before moving on. Recurses into
// whatever remains after this level's own pass. depth is a defense-in-depth
// cap (maxSerializeDepth, body_serialize.go) against a malformed/cyclic tree
// reaching here despite every earlier layer (build/serialize/clone) already
// guarding against that independently.
func minimizeBodyValueNode(node *BodyValue, depth int, attempt func() bool) {
	if node == nil || depth > maxSerializeDepth {
		return
	}
	switch node.Kind {
	case BVObject:
		i := 0
		for i < len(node.Fields) {
			removed := node.Fields[i]
			node.Fields = append(node.Fields[:i:i], node.Fields[i+1:]...)
			if attempt() {
				continue // dropped and accepted -- next field has shifted into position i
			}
			restored := make([]BodyField, 0, len(node.Fields)+1)
			restored = append(restored, node.Fields[:i]...)
			restored = append(restored, removed)
			restored = append(restored, node.Fields[i:]...)
			node.Fields = restored
			i++
		}
		for _, f := range node.Fields {
			minimizeBodyValueNode(f.Value, depth+1, attempt)
		}
	case BVArray:
		i := 0
		for i < len(node.Items) {
			removed := node.Items[i]
			node.Items = append(node.Items[:i:i], node.Items[i+1:]...)
			if attempt() {
				continue
			}
			restored := make([]*BodyValue, 0, len(node.Items)+1)
			restored = append(restored, node.Items[:i]...)
			restored = append(restored, removed)
			restored = append(restored, node.Items[i:]...)
			node.Items = restored
			i++
		}
		for _, it := range node.Items {
			minimizeBodyValueNode(it, depth+1, attempt)
		}
	}
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

// ---------------------------------------------------------------------------
// Whole-chain minimization (Phase 5 #126, docs/ARCHITECTURE_STATEFUL.md §2.7)
// ---------------------------------------------------------------------------
//
// Everything above minimizes the SINGLE crash-triggering request's own
// fields (query/form/JSON/path). minimizeChainCandidate below is the
// complementary piece for a crash reached through a multi-step sequence
// chain: it tries dropping earlier, non-essential STEPS entirely, not just
// shrinking their fields. Deliberately narrow scope, stated honestly: it
// replays each remaining step's own already-rendered, concrete
// Method/Path/Headers/Body verbatim (SequenceStep, populated by
// enqueueSequenceFollowups regardless of whether -resource-graph produced
// the values) -- it does NOT attempt to re-derive dynamic producer->consumer
// bindings for a shrunk chain (dropping a step that produced an id another
// step's stored body already references would just make that later step
// replay with its OWN already-captured value, which may or may not still
// resolve against a shrunk prior chain -- accepted as a known limitation
// rather than built around, since the replayed steps are exact byte-for-byte
// resends of what was actually sent, not a re-planned chain).

// minimizeChainCandidate attempts to shrink the SEQUENCE CHAIN leading up to
// a crash (item.SeqState.History) by dropping non-final steps one at a time,
// greedily keeping a drop only if replaying the resulting shorter chain
// still ends in a >=500 on the final step. No-op (returns nil, false, 0) for
// a crash with no chain at all (item.SeqState == nil) or a single-step
// "chain" -- the overwhelming majority of crashes, already fully covered by
// minimizeCrashCandidate above. Shares f.cfg.MinimizeMaxProbes as its own
// probe budget (a separate concern from the caller's own remaining budget
// for field-level minimization -- see crash.go's call site).
func (f *Fuzzer) minimizeChainCandidate(item WorkItem) ([]SequenceStep, bool, int) {
	if item.SeqState == nil || len(item.SeqState.History) <= 1 {
		return nil, false, 0
	}
	maxProbes := maxInt(0, f.cfg.MinimizeMaxProbes)
	if maxProbes == 0 {
		return item.SeqState.History, false, 0
	}
	history := append([]SequenceStep{}, item.SeqState.History...)
	probes := 0
	changed := false

	// stillCrashes replays steps in order using each one's own stored,
	// already-concrete request -- true iff the LAST step in the candidate
	// chain returns >=500. Intermediate steps are sent but their own status
	// isn't checked (a dropped intermediate step commonly changes an earlier
	// status code, e.g. a 404 instead of the original 200, without changing
	// whether the FINAL step still crashes -- which is the only thing that
	// actually matters for a minimized repro).
	stillCrashes := func(steps []SequenceStep) bool {
		var lastStatus int
		for _, step := range steps {
			if probes >= maxProbes {
				return false
			}
			probes++
			res := f.sendOne(WorkItem{Method: step.Method, Path: step.Path, Headers: step.Headers, Body: step.Body})
			if res.Err != nil {
				return false
			}
			lastStatus = res.Status
		}
		return lastStatus >= 500
	}

	// Walk backward so earlier indices stay valid after a removal (a forward
	// walk would need to re-index after every successful drop).
	for i := len(history) - 2; i >= 0; i-- {
		if probes >= maxProbes {
			break
		}
		candidate := make([]SequenceStep, 0, len(history)-1)
		candidate = append(candidate, history[:i]...)
		candidate = append(candidate, history[i+1:]...)
		if len(candidate) == 0 {
			continue
		}
		if stillCrashes(candidate) {
			history = candidate
			changed = true
		}
	}

	return history, changed, probes
}
