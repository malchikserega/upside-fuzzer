package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// identity.go — Auth identity management, trace decoration, race probing,
// and shared utility functions (cloneStringMap, cloneAnyMap, etc.).
//
// Previously named advanced_features_compat.go. The March 11 refactor left this
// file as a compatibility shim; this rename completes that refactor:
//   - triage.go:  crash triage scoring, source-aware priority, route scoring
//   - poc.go:     PoC shell script and timeline generation
//   - report.go:  final crash report building
//   - minimize.go: crash minimization and repro verification
//   - identity.go: auth identities, race probing, shared utilities (this file)

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
	AuthContext  map[string]any
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

	if f.cfg.MultiIdentity {
		parsed := parseAuthIdentitiesFile(f.cfg.AuthFile)
		if len(parsed) > 0 {
			ids = append(ids, parsed...)
		}
	}

	parsed := parseAuthIdentitiesJSON(strings.TrimSpace(os.Getenv("AUTH_IDENTITIES_JSON")))
	if f.cfg.MultiIdentity && len(parsed) > 0 {
		ids = append(ids, parsed...)
	}

	if len(ids) == 0 {
		f.authMu.RLock()
		ids = append(ids, AuthIdentity{
			Name:    "default",
			Token:   strings.TrimSpace(f.token),
			Headers: cloneStringMap(f.authHeaders),
			Weight:  1.0,
		})
		f.authMu.RUnlock()
	} else if f.hasAuthContext() {
		f.authMu.RLock()
		ids = append(ids, AuthIdentity{
			Name:    "default",
			Token:   strings.TrimSpace(f.token),
			Headers: cloneStringMap(f.authHeaders),
			Weight:  1.0,
		})
		f.authMu.RUnlock()
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
	if f.cfg.MultiIdentity && f.cfg.IdentityIncludeGuest && !hasGuest {
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
	out, _ := parseAuthIdentitiesBytes([]byte(raw))
	return out
}

func parseAuthIdentitiesFile(path string) []AuthIdentity {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to read auth identities file %s: %v\n", p, err)
		return nil
	}
	out, err := parseAuthIdentitiesBytes(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to parse auth identities file %s: %v\n", p, err)
		return nil
	}
	return out
}

func parseAuthIdentitiesBytes(raw []byte) ([]AuthIdentity, error) {
	type identityIn struct {
		Name      string         `json:"name"`
		Token     string         `json:"token"`
		JWT       string         `json:"jwt"`
		APIKey    string         `json:"api_key"`
		APIKeyEnv string         `json:"api_key_env"`
		APIKeyHdr string         `json:"api_key_header"`
		Cookie    string         `json:"cookie"`
		Weight    float64        `json:"weight"`
		Headers   map[string]any `json:"headers"`
	}
	type identityFile struct {
		Version    string       `json:"version,omitempty"`
		Identities []identityIn `json:"identities"`
	}
	out := make([]AuthIdentity, 0, 8)
	tryAdd := func(name string, id identityIn) {
		h := map[string]string{}
		skipReason := ""
		for k, v := range id.Headers {
			ks := strings.TrimSpace(k)
			vs := strings.TrimSpace(toString(v))
			if ks == "" || vs == "" {
				continue
			}
			setHeaderCI(h, ks, vs)
		}
		token := strings.TrimSpace(id.JWT)
		if token == "" {
			token = strings.TrimSpace(id.Token)
		}
		if token != "" && strings.TrimSpace(getHeaderCI(h, "Authorization")) == "" {
			setHeaderCI(h, "Authorization", "Bearer "+stripBearerPrefix(token))
		}
		apiKey := strings.TrimSpace(id.APIKey)
		apiKeyEnv := strings.TrimSpace(id.APIKeyEnv)
		if apiKey == "" && apiKeyEnv != "" {
			apiKey = strings.TrimSpace(os.Getenv(apiKeyEnv))
			if apiKey == "" {
				skipReason = fmt.Sprintf("api_key_env %s is empty", apiKeyEnv)
			}
		}
		apiKeyHeader := strings.TrimSpace(id.APIKeyHdr)
		if apiKeyHeader == "" {
			apiKeyHeader = "X-Api-Key"
		}
		if apiKey != "" && strings.TrimSpace(getHeaderCI(h, apiKeyHeader)) == "" {
			setHeaderCI(h, apiKeyHeader, apiKey)
		}
		if strings.TrimSpace(id.Cookie) != "" {
			setHeaderCI(h, "Cookie", strings.TrimSpace(id.Cookie))
		}
		legacyToken := strings.TrimSpace(id.Token)
		if legacyToken != "" && strings.TrimSpace(id.JWT) != "" {
			legacyToken = ""
		}
		legacyToken = stripBearerPrefix(legacyToken)
		weight := id.Weight
		if weight <= 0 {
			weight = 1.0
		}
		if len(h) == 0 && legacyToken == "" && !strings.EqualFold(strings.TrimSpace(name), "guest") && !strings.Contains(strings.ToLower(strings.TrimSpace(name)), "anon") {
			if skipReason != "" {
				fmt.Fprintf(os.Stderr, "warning: auth identity %q skipped: %s\n", strings.TrimSpace(name), skipReason)
			}
			return
		}
		out = append(out, AuthIdentity{
			Name:    strings.TrimSpace(name),
			Token:   legacyToken,
			Headers: h,
			Weight:  weight,
		})
	}

	var file identityFile
	if err := json.Unmarshal(raw, &file); err == nil && file.Identities != nil {
		for i, id := range file.Identities {
			n := id.Name
			if strings.TrimSpace(n) == "" {
				n = fmt.Sprintf("id-%d", i+1)
			}
			tryAdd(n, id)
		}
		return out, nil
	}

	var arr []identityIn
	if err := json.Unmarshal(raw, &arr); err == nil {
		for i, id := range arr {
			n := id.Name
			if strings.TrimSpace(n) == "" {
				n = fmt.Sprintf("id-%d", i+1)
			}
			tryAdd(n, id)
		}
		return out, nil
	}

	var obj map[string]identityIn
	if err := json.Unmarshal(raw, &obj); err == nil {
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
			tryAdd(name, id)
		}
		return out, nil
	}
	return nil, fmt.Errorf("expected JSON auth identity file, array, or object")
}

func stripBearerPrefix(token string) string {
	t := strings.TrimSpace(token)
	for {
		parts := strings.Fields(t)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			t = strings.TrimSpace(parts[1])
			continue
		}
		return t
	}
}

func (f *Fuzzer) identityAuth(name string) (map[string]string, string, bool) {
	wanted := strings.TrimSpace(name)
	if wanted == "" {
		f.authMu.RLock()
		defer f.authMu.RUnlock()
		return cloneStringMap(f.authHeaders), strings.TrimSpace(f.token), false
	}
	for _, id := range f.identities {
		if id.Name == wanted {
			return cloneStringMap(id.Headers), strings.TrimSpace(id.Token), true
		}
	}
	f.authMu.RLock()
	defer f.authMu.RUnlock()
	return cloneStringMap(f.authHeaders), strings.TrimSpace(f.token), false
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
			if strings.Contains(pathLow, "/vendor") && strings.Contains(nameLow, "vendor") {
				w *= 4.0
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

func (f *Fuzzer) enqueueRaceBurst(source WorkItem) {
	if !f.cfg.RaceMode || !isWriteMethod(source.Method) {
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
			"crash_layer":    "unknown",
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

	// --- Crash layer detection -----------------------------------------------
	// Determine where in the ASP.NET pipeline the crash occurred.
	// Frames that appear BEFORE any user/controller code executes indicate
	// a pre-auth deserialization/model-binding failure. These are legitimate
	// bugs (they can cause DoS) but are NOT security vulnerabilities in the
	// traditional sense and must not be rated as likely_vuln.
	//
	// Frame hierarchy (outermost first, i.e. earliest in the call chain):
	//   deserialization -> model_binding -> filter_pipeline -> controller -> service
	//
	// We scan for the DEEPEST layer where the crash originates by checking
	// which post-deserialization markers are absent.
	crashLayer := "unknown"
	controllerMarkers := []string{
		"controller.", "controllerbase.", "apicontroller",
		"endpoint.", "minimal api",
		"handler.", "commandhandler.", "queryhandler.",
	}
	serviceMarkers := []string{
		"service.", "repository.", "manager.", "logic.",
		"dbcontext.", "entityframework", "sqlexception",
	}
	modelBindingMarkers := []string{
		"modelbinder", "bodybinder", "bodymodeibinder",
		"inputformatter", "newtonsoftjsoninputformatter",
		"parameterbinder",
	}
	deserializationMarkers := []string{
		"jsonserializerinternalreader", "jsonserializerinternalwriter",
		"jsonserializer.deserialize", "jsonconvert.deserializeobject",
		"newtonsoft.json.serialization",
	}

	hasService := false
	hasController := false
	hasModelBinding := false
	hasDeserialization := false
	for _, m := range serviceMarkers {
		if strings.Contains(bodyLow, m) {
			hasService = true
			break
		}
	}
	for _, m := range controllerMarkers {
		if strings.Contains(bodyLow, m) {
			hasController = true
			break
		}
	}
	for _, m := range modelBindingMarkers {
		if strings.Contains(bodyLow, m) {
			hasModelBinding = true
			break
		}
	}
	for _, m := range deserializationMarkers {
		if strings.Contains(bodyLow, m) {
			hasDeserialization = true
			break
		}
	}

	switch {
	case hasService:
		// Crash happened in (or after) a service/repository — deepest layer, post-auth.
		crashLayer = "service"
		score += 0.8
		reasons = append(reasons, "post_auth_execution")
	case hasController:
		// Crash in a controller action — post-auth business logic.
		crashLayer = "controller"
		score += 0.8
		reasons = append(reasons, "post_auth_execution")
	case hasModelBinding && !hasController && !hasService:
		// Crash in model binding but no controller frame — pre-auth infrastructure.
		// The request was deserialized/bound but application code never ran.
		crashLayer = "model_binding"
		score -= 1.5
		reasons = append(reasons, "pre_auth_model_binding")
	case hasDeserialization && !hasModelBinding && !hasController && !hasService:
		// Crash purely in the JSON deserializer — the earliest possible failure point.
		// No user code ever ran; this is a framework-level input handling bug.
		crashLayer = "deserialization"
		score -= 1.5
		reasons = append(reasons, "pre_auth_deserialization")
	default:
		crashLayer = "unknown"
	}
	// -------------------------------------------------------------------------

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

	// Pre-auth crashes (deserialization/model_binding) are capped at needs_review:
	// they prove the app is unstable but do NOT demonstrate unauthorized access to
	// business logic. Elevating them to likely_vuln would inflate risk ratings.
	preAuth := crashLayer == "deserialization" || crashLayer == "model_binding"

	classification := "noise"
	switch {
	case score >= 8.0 && !preAuth:
		classification = "likely_vuln_high"
	case score >= 6.0 && !preAuth:
		classification = "likely_vuln"
	case score >= 4.0:
		classification = "needs_review"
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
		"crash_layer":    crashLayer,
		"reasons":        dedupStrings(reasons),
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
