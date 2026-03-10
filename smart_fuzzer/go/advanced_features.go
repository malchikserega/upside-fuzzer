package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	reSourceRoute = regexp.MustCompile(`(?i)(?:Route|HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)\s*\(\s*"([^"]+)"`)
)

type TraceStep struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Mutation string `json:"mutation,omitempty"`
}

type AuthIdentity struct {
	Name    string
	Token   string
	Headers map[string]string
	Weight  float64
}

type CrashFinding struct {
	Signature    string
	TS           string
	ElapsedSec   string
	Method       string
	Path         string
	Status       int
	Identity     string
	Mutation     string
	Payload      string
	Response     string
	Exception    string
	RequestHeads map[string]string
	CurlCommand  string
	Triage       map[string]any
	Repro        map[string]any
	Minimized    map[string]any
	PocFile      string
	Timeline     string
}

func (f *Fuzzer) decorateWorkItem(item WorkItem) WorkItem {
	if strings.TrimSpace(item.Identity) == "" {
		item.Identity = f.pickIdentityForEndpoint(item.Method, item.Path)
	}
	if len(item.Trace) == 0 {
		item.Trace = f.extendTrace(nil, item)
	} else if len(item.Trace) > traceDepthMax {
		item.Trace = item.Trace[len(item.Trace)-traceDepthMax:]
	}
	return item
}

func (f *Fuzzer) extendTrace(prev []TraceStep, item WorkItem) []TraceStep {
	out := make([]TraceStep, 0, traceDepthMax)
	if len(prev) > 0 {
		if len(prev) > traceDepthMax-1 {
			prev = prev[len(prev)-(traceDepthMax-1):]
		}
		out = append(out, prev...)
	}
	step := TraceStep{
		Method:   sanitizeText(item.Method, 16),
		Path:     sanitizeText(normalizePath(item.Path), 192),
		Mutation: sanitizeText(item.MutationName, 48),
	}
	if step.Mutation == "" {
		step.Mutation = sanitizeText(item.MutationLabel, 48)
	}
	out = append(out, step)
	if len(out) > traceDepthMax {
		out = out[len(out)-traceDepthMax:]
	}
	return out
}

func (f *Fuzzer) initAuthIdentities() {
	ids := make([]AuthIdentity, 0, 8)

	parsed := parseAuthIdentitiesJSON(strings.TrimSpace(os.Getenv("AUTH_IDENTITIES_JSON")))
	if f.cfg.MultiIdentity && len(parsed) > 0 {
		ids = append(ids, parsed...)
	}

	if len(ids) == 0 {
		ids = append(ids, AuthIdentity{
			Name:    "default",
			Token:   strings.TrimSpace(f.token),
			Headers: cloneStringMap(f.authHeaders),
			Weight:  1.0,
		})
	} else if f.hasAuthContext() {
		ids = append(ids, AuthIdentity{
			Name:    "default",
			Token:   strings.TrimSpace(f.token),
			Headers: cloneStringMap(f.authHeaders),
			Weight:  1.0,
		})
	}

	hasGuest := false
	for i := range ids {
		ids[i].Name = strings.TrimSpace(ids[i].Name)
		if ids[i].Name == "" {
			ids[i].Name = fmt.Sprintf("id-%d", i+1)
		}
		if ids[i].Weight <= 0 {
			ids[i].Weight = 1.0
		}
		if strings.EqualFold(ids[i].Name, "guest") {
			hasGuest = true
		}
		if ids[i].Headers == nil {
			ids[i].Headers = map[string]string{}
		}
	}
	if f.cfg.MultiIdentity && !hasGuest {
		ids = append(ids, AuthIdentity{Name: "guest", Headers: map[string]string{}, Weight: 0.7})
	}

	byName := map[string]AuthIdentity{}
	order := make([]string, 0, len(ids))
	for _, id := range ids {
		name := sanitizeText(strings.TrimSpace(id.Name), 32)
		if name == "" {
			continue
		}
		if _, exists := byName[name]; exists {
			continue
		}
		byName[name] = id
		order = append(order, name)
	}
	if len(order) == 0 {
		byName["guest"] = AuthIdentity{Name: "guest", Headers: map[string]string{}, Weight: 1.0}
		order = append(order, "guest")
	}
	f.identities = make([]AuthIdentity, 0, len(order))
	for _, n := range order {
		f.identities = append(f.identities, byName[n])
	}
	f.identityOrder = order
}

func parseAuthIdentitiesJSON(raw string) []AuthIdentity {
	if raw == "" {
		return nil
	}
	type identityIn struct {
		Name    string         `json:"name"`
		Token   string         `json:"token"`
		Cookie  string         `json:"cookie"`
		Weight  float64        `json:"weight"`
		Headers map[string]any `json:"headers"`
	}
	out := make([]AuthIdentity, 0, 8)
	tryAdd := func(name, token, cookie string, headers map[string]any, weight float64) {
		h := map[string]string{}
		for k, v := range headers {
			ks := strings.TrimSpace(k)
			vs := strings.TrimSpace(toString(v))
			if ks == "" || vs == "" {
				continue
			}
			h[ks] = vs
		}
		if strings.TrimSpace(cookie) != "" {
			setHeaderCI(h, "Cookie", strings.TrimSpace(cookie))
		}
		if weight <= 0 {
			weight = 1.0
		}
		out = append(out, AuthIdentity{
			Name:    strings.TrimSpace(name),
			Token:   strings.TrimSpace(token),
			Headers: h,
			Weight:  weight,
		})
	}

	var arr []identityIn
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		for i, id := range arr {
			n := id.Name
			if strings.TrimSpace(n) == "" {
				n = fmt.Sprintf("id-%d", i+1)
			}
			tryAdd(n, id.Token, id.Cookie, id.Headers, id.Weight)
		}
		return out
	}

	var obj map[string]identityIn
	if err := json.Unmarshal([]byte(raw), &obj); err == nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			id := obj[k]
			name := k
			if strings.TrimSpace(id.Name) != "" {
				name = id.Name
			}
			tryAdd(name, id.Token, id.Cookie, id.Headers, id.Weight)
		}
	}
	return out
}

func (f *Fuzzer) identityAuth(name string) (map[string]string, string) {
	if strings.TrimSpace(name) == "" {
		return cloneStringMap(f.authHeaders), strings.TrimSpace(f.token)
	}
	for _, id := range f.identities {
		if id.Name == name {
			return cloneStringMap(id.Headers), strings.TrimSpace(id.Token)
		}
	}
	return cloneStringMap(f.authHeaders), strings.TrimSpace(f.token)
}

func (f *Fuzzer) pickIdentityForEndpoint(method, path string) string {
	if len(f.identities) == 0 {
		return ""
	}
	if len(f.identities) == 1 {
		return f.identities[0].Name
	}
	mode := strings.ToLower(strings.TrimSpace(f.cfg.IdentitySampleMode))
	if mode == "rr" || mode == "roundrobin" {
		mode = "round-robin"
	}

	switch mode {
	case "round-robin":
		pick := f.identities[f.identityCursor%len(f.identities)].Name
		f.identityCursor++
		return pick
	case "random":
		return f.identities[rand.Intn(len(f.identities))].Name
	default:
		weights := make([]float64, 0, len(f.identities))
		for _, id := range f.identities {
			w := math.Max(0.01, id.Weight)
			nameLow := strings.ToLower(id.Name)
			pathLow := strings.ToLower(normalizePath(path))
			if strings.Contains(pathLow, "/admin") {
				if strings.Contains(nameLow, "admin") {
					w *= 5.0
				} else if strings.Contains(nameLow, "guest") {
					w *= 0.3
				}
			}
			if strings.Contains(pathLow, "/vendor") {
				if strings.Contains(nameLow, "vendor") {
					w *= 4.0
				}
			}
			if strings.Contains(pathLow, "auth") || strings.Contains(pathLow, "login") || strings.Contains(pathLow, "register") {
				if strings.Contains(nameLow, "guest") || strings.Contains(nameLow, "anon") {
					w *= 3.0
				}
			}
			if isWriteMethod(method) && (strings.Contains(nameLow, "guest") || strings.Contains(nameLow, "anon")) {
				w *= 0.35
			}
			weights = append(weights, w)
		}
		idx := weightedPick(weights)
		if idx < 0 || idx >= len(f.identities) {
			idx = rand.Intn(len(f.identities))
		}
		return f.identities[idx].Name
	}
}

func (f *Fuzzer) templateSourcePriorityWeight(tid int) float64 {
	if w, ok := f.templatePriority[tid]; ok && w > 0 {
		return w
	}
	return 1.0
}

func (f *Fuzzer) loadSourceAwarePriority() int {
	out := map[int]float64{}
	routeScores := map[string]float64{}
	if strings.TrimSpace(f.cfg.SourceDir) != "" {
		routeScores = scanSourceRouteScores(f.cfg.SourceDir)
	}
	boosted := 0
	for _, tid := range f.activeIDs {
		meta, ok := f.meta[tid]
		if !ok {
			continue
		}
		w := 1.0
		w *= sensitivePathScore(meta.Method, meta.Norm)
		if len(routeScores) > 0 {
			rp := normalizeRoutePattern(meta.Norm)
			if s := routeScores[rp]; s > 0 {
				w *= s
			}
		}
		w = clampFloat(w, 0.2, 8.0)
		out[tid] = w
		if w > 1.05 {
			boosted++
		}
	}
	f.templatePriority = out
	return boosted
}

func sensitivePathScore(method, path string) float64 {
	low := strings.ToLower(strings.TrimSpace(normalizePath(path)))
	score := 1.0
	sensitive := []string{
		"/billing", "/payment", "/checkout", "/order", "/cart", "/invoice",
		"/auth", "/token", "/login", "/password", "/account", "/admin", "/role",
		"/tenant", "/customer", "/wishlist", "/discount", "/coupon", "/stock",
	}
	hits := 0
	for _, kw := range sensitive {
		if strings.Contains(low, kw) {
			hits++
		}
	}
	if hits > 0 {
		score *= 1.0 + float64(minInt(4, hits))*0.45
	}
	if isWriteMethod(method) {
		score *= 1.25
	}
	return clampFloat(score, 0.8, 6.0)
}

func scanSourceRouteScores(srcDir string) map[string]float64 {
	scores := map[string]float64{}
	if strings.TrimSpace(srcDir) == "" {
		return scores
	}
	_ = filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if name == "bin" || name == "obj" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".cs") {
			return nil
		}
		buf, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		src := string(buf)
		if len(src) > 1<<20 {
			src = src[:1<<20]
		}
		low := strings.ToLower(src)
		fileWeight := 1.0
		for _, k := range []string{"order", "billing", "payment", "checkout", "auth", "login", "role", "admin", "tenant", "wishlist", "cart"} {
			if strings.Contains(low, k) {
				fileWeight += 0.15
			}
		}
		matches := reSourceRoute.FindAllStringSubmatch(src, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			rp := normalizeRoutePattern(m[1])
			if rp == "" {
				continue
			}
			scores[rp] += fileWeight
		}
		return nil
	})
	for k, v := range scores {
		scores[k] = clampFloat(1.0+math.Log1p(v)*0.55, 1.0, 4.0)
	}
	return scores
}

func normalizeRoutePattern(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	parts := splitPathTokens(p)
	if len(parts) == 0 {
		return "/"
	}
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		s := strings.TrimSpace(seg)
		if _, ok := pathPlaceholderName(s); ok {
			out = append(out, "{param}")
			continue
		}
		if strings.HasPrefix(s, ":") {
			out = append(out, "{param}")
			continue
		}
		if strings.ContainsAny(s, "*?") {
			out = append(out, "{param}")
			continue
		}
		out = append(out, normalizeEndpointSegment(s))
	}
	return "/" + strings.Join(out, "/")
}

func (f *Fuzzer) enqueueRaceBurst(source WorkItem) {
	if !f.cfg.RaceMode {
		return
	}
	if !isWriteMethod(source.Method) {
		return
	}
	if rand.Float64() > clampFloat(f.cfg.RaceProb, 0.0, 1.0) {
		return
	}
	if !isRaceCandidatePath(source.Path) {
		return
	}
	n := clampInt(f.cfg.RaceBurst, 2, 64)
	added := 0
	for i := 0; i < n; i++ {
		it := source
		it.MutationName = "race_conflict"
		it.MutationLabel = sanitizeText(source.MutationLabel+"+race", 256)
		it.Trace = f.extendTrace(source.Trace, it)
		if len(f.raceQueue) >= raceQueueMax {
			f.raceQueue = f.raceQueue[1:]
		}
		f.raceQueue = append(f.raceQueue, it)
		added++
	}
	if added > 0 {
		f.addEvent(fmt.Sprintf("RACE enqueue +%d  %s %s", added, source.Method, truncate(normalizePath(source.Path), 52)))
	}
}

func isRaceCandidatePath(path string) bool {
	low := strings.ToLower(normalizePath(path))
	for _, kw := range []string{"cart", "order", "checkout", "payment", "invoice", "discount", "coupon", "stock", "wishlist", "balance"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func (f *Fuzzer) triageCrash(res SendResult) map[string]any {
	if !f.cfg.CrashTriage {
		return map[string]any{
			"classification": "unclassified",
			"severity_score": 0,
			"dev_mode":       false,
		}
	}

	score := 0.0
	reasons := make([]string, 0, 8)
	bodyLow := strings.ToLower(res.Body)
	pathLow := strings.ToLower(normalizePath(res.Item.Path))
	mutLow := strings.ToLower(res.Item.MutationLabel)

	if res.Status >= 500 {
		score += 4.0
		reasons = append(reasons, "server_error")
	}
	devMode := false
	for _, marker := range []string{
		"developer exception page", "stack trace", "microsoft.aspnetcore",
		" at ", "system.", "exception:", ".cs:",
	} {
		if strings.Contains(bodyLow, marker) {
			devMode = true
			score += 1.5
			reasons = append(reasons, "dev_stack")
			break
		}
	}
	for _, marker := range []string{
		"sql", "deadlock", "timeout", "nullreferenceexception", "invalidoperationexception",
		"object reference not set", "index was out of range", "sequence contains no elements",
	} {
		if strings.Contains(bodyLow, marker) {
			score += 1.6
			reasons = append(reasons, "backend_exception")
			break
		}
	}
	score += (sensitivePathScore(res.Item.Method, res.Item.Path) - 1.0) * 1.1
	if strings.Contains(mutLow, "sequence") || strings.Contains(mutLow, "dep_") || strings.Contains(mutLow, "corr_") {
		score += 0.9
		reasons = append(reasons, "stateful_trigger")
	}
	if strings.Contains(pathLow, "fuzzstring") || strings.Contains(pathLow, "{param}") {
		score -= 1.5
		reasons = append(reasons, "synthetic_path")
	}
	if isFormContentTypeMismatch(res.Status, res.Body) {
		score -= 2.0
		reasons = append(reasons, "content_type_noise")
	}
	if strings.Contains(bodyLow, "an error occurred while processing your request") {
		score += 0.6
	}

	score = clampFloat(score, 0.0, 10.0)
	classification := "noise"
	switch {
	case score >= 8.0:
		classification = "likely_vuln_high"
	case score >= 6.0:
		classification = "likely_vuln"
	case score >= 4.0:
		classification = "needs_review"
	default:
		classification = "noise"
	}
	impact := "stability"
	if strings.Contains(pathLow, "auth") || strings.Contains(pathLow, "login") || strings.Contains(pathLow, "role") || strings.Contains(pathLow, "admin") {
		impact = "authz/authn"
	} else if strings.Contains(pathLow, "cart") || strings.Contains(pathLow, "order") || strings.Contains(pathLow, "payment") || strings.Contains(pathLow, "billing") {
		impact = "business_logic"
	}
	return map[string]any{
		"classification": classification,
		"severity_score": int(math.Round(score)),
		"score":          fmt.Sprintf("%.2f", score),
		"dev_mode":       devMode,
		"impact_hint":    impact,
		"reasons":        dedupStrings(reasons),
	}
}

func (f *Fuzzer) reproCheckCrash(item WorkItem, status int) map[string]any {
	runs := clampInt(f.cfg.ReproRuns, 0, 20)
	if runs <= 0 {
		return map[string]any{}
	}
	// Repro probes must not mutate the shared client timeout while worker goroutines
	// are sending requests concurrently. Use a dedicated probe client instead.
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
		"stability_pct":       fmt.Sprintf("%.1f", pct),
		"target_pct":          fmt.Sprintf("%.1f", f.cfg.ReproTargetPct),
		"stable_reproducible": ok,
		"probe_statuses":      statuses,
		"repro_status_class":  "5xx",
	}
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

func (f *Fuzzer) resolvedCrashHeaders(item WorkItem) map[string]string {
	headers := cloneStringMap(item.Headers)
	idHeaders, idToken := f.identityAuth(item.Identity)
	for k, v := range idHeaders {
		if strings.TrimSpace(headers[k]) == "" {
			headers[k] = v
		}
	}
	if idToken != "" {
		headers["Authorization"] = "Bearer " + idToken
	} else if strings.TrimSpace(f.token) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(f.token)
	}
	if strings.TrimSpace(getHeaderCI(headers, "Content-Type")) == "" && strings.TrimSpace(item.Body) != "" {
		setHeaderCI(headers, "Content-Type", "application/json")
	}
	return headers
}

func crashHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *Fuzzer) buildInlineCurlCommand(item WorkItem, headers map[string]string) string {
	path := item.Path
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method := strings.ToUpper(strings.TrimSpace(item.Method))
	if method == "" {
		method = "GET"
	}

	parts := []string{
		"TARGET_HOST=\"${TARGET_HOST:-" + escapeForDoubleQuotedBash(strings.TrimRight(f.target, "/")) + "}\";",
		"curl -i -sS -X \"" + escapeForDoubleQuotedBash(method) + "\"",
		"\"$TARGET_HOST" + escapeForDoubleQuotedBash(path) + "\"",
	}
	for _, hk := range crashHeaderKeys(headers) {
		parts = append(parts, "-H \""+escapeForDoubleQuotedBash(hk+": "+headers[hk])+"\"")
	}
	if strings.TrimSpace(item.Body) != "" {
		parts = append(parts, "--data-raw \""+escapeForDoubleQuotedBash(item.Body)+"\"")
	} else {
		parts = append(parts, "--data ''")
	}
	return strings.Join(parts, " ")
}

func (f *Fuzzer) writeCrashPoC(sig string, res SendResult, pocItem WorkItem, triage, repro, minimized map[string]any) string {
	if strings.TrimSpace(f.cfg.PocDir) == "" {
		return ""
	}
	if err := os.MkdirAll(f.cfg.PocDir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(f.cfg.PocDir, "poc-"+sig+".sh")
	headers := f.resolvedCrashHeaders(pocItem)
	headerKeys := crashHeaderKeys(headers)

	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n\n")
	b.WriteString("# Auto-generated by SmartFuzzer-Go\n")
	b.WriteString("# signature: " + sig + "\n")
	b.WriteString("# method: " + pocItem.Method + "\n")
	b.WriteString("# path: " + normalizePath(pocItem.Path) + "\n")
	if cls := toString(triage["classification"]); cls != "" {
		b.WriteString("# triage: " + cls + " severity=" + toString(triage["severity_score"]) + " dev_mode=" + toString(triage["dev_mode"]) + "\n")
	}
	if st := toString(repro["stability_pct"]); st != "" {
		b.WriteString("# repro stability: " + st + "%\n")
	}
	if len(pocItem.Trace) > 1 {
		b.WriteString("# sequence trace:\n")
		for i, step := range pocItem.Trace {
			b.WriteString(fmt.Sprintf("#   %d) %s %s\n", i+1, step.Method, step.Path))
		}
	}
	b.WriteString("\nTARGET_HOST=\"${TARGET_HOST:-" + shellQuoteDouble(f.target) + "}\"\n\n")
	b.WriteString("curl -i -sS -X " + shellQuoteDouble(strings.ToUpper(pocItem.Method)) + " \"$TARGET_HOST" + escapeForDoubleQuotedBash(pocItem.Path) + "\" \\\n")
	for _, hk := range headerKeys {
		b.WriteString("  -H \"" + escapeForDoubleQuotedBash(hk+": "+headers[hk]) + "\" \\\n")
	}
	if strings.TrimSpace(pocItem.Body) != "" {
		b.WriteString("  --data-raw \"" + escapeForDoubleQuotedBash(pocItem.Body) + "\"\n")
	} else {
		b.WriteString("  --data ''\n")
	}
	if len(minimized) > 0 {
		_ = minimized
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		return ""
	}
	f.pocCount++
	return path
}

func (f *Fuzzer) writeExploitTimeline(sig string, res SendResult, pocItem WorkItem) string {
	if strings.TrimSpace(f.cfg.TimelineDir) == "" {
		return ""
	}
	if err := os.MkdirAll(f.cfg.TimelineDir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(f.cfg.TimelineDir, "timeline-"+sig+".md")
	trace := pocItem.Trace
	if len(trace) == 0 {
		trace = []TraceStep{{Method: pocItem.Method, Path: normalizePath(pocItem.Path), Mutation: pocItem.MutationName}}
	}
	if len(trace) > traceDepthMax {
		trace = trace[len(trace)-traceDepthMax:]
	}

	var b strings.Builder
	b.WriteString("# Exploit Timeline " + sig + "\n\n")
	b.WriteString("```mermaid\nsequenceDiagram\n")
	b.WriteString("    participant F as Fuzzer\n")
	b.WriteString("    participant API as API\n")
	for i, st := range trace {
		msg := fmt.Sprintf("%d. %s %s", i+1, strings.ToUpper(st.Method), sanitizeText(normalizePath(st.Path), 80))
		b.WriteString("    F->>API: " + mermaidEscape(msg) + "\n")
		if i == len(trace)-1 {
			b.WriteString(fmt.Sprintf("    API-->>F: %d crash\n", res.Status))
		} else {
			b.WriteString("    API-->>F: success/transition\n")
		}
	}
	b.WriteString("```\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return ""
	}
	return path
}

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
		"race_mode_enabled":      f.cfg.RaceMode,
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
			"request": map[string]any{
				"endpoint":             endpoint,
				"method":               fd.Method,
				"path":                 fd.Path,
				"identity":             fd.Identity,
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
		"report_version": "smartfuzzer-go-bug-report-v1",
		"generated_at":   time.Now().Format(time.RFC3339),
		"target_host":    f.target,
		"stats": map[string]any{
			"elapsed_secs":     elapsed,
			"requests_done":    f.totalDone,
			"requests_sent":    f.totalSent,
			"errors":           f.totalErrors,
			"crashes_total":    f.totalCrashes,
			"crashes_unique":   f.uniqueCrashes,
			"coverage_edges":   f.currentEdges,
			"coverage_new":     f.currentEdges - f.startEdges,
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

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneURLValues(in url.Values) url.Values {
	out := url.Values{}
	for k, arr := range in {
		c := make([]string, len(arr))
		copy(c, arr)
		out[k] = c
	}
	return out
}

func shellQuoteDouble(v string) string {
	return strings.ReplaceAll(sanitizeText(v, 2048), "\"", "\\\"")
}

func escapeForDoubleQuotedBash(v string) string {
	s := strings.ToValidUTF8(v, "?")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "$", "\\$")
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
}

func mermaidEscape(v string) string {
	s := sanitizeText(v, 200)
	s = strings.ReplaceAll(s, "\"", "'")
	return s
}

func strconvAtof(v string) (float64, error) {
	s := strings.TrimSpace(strings.TrimSuffix(v, "%"))
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return strconv.ParseFloat(s, 64)
}
