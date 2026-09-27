package engine

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

// TraceStep is one step of a WorkItem's own execution history
// (decorateWorkItem/extendTrace), attached to every built item (not just
// crash-adjacent ones) and consulted by poc.go's PoC-script/timeline
// generation for the chain leading up to a crash. Deliberately does NOT carry
// full request/response headers or bodies -- this is built for every single
// item the engine sends, so a per-step full-body/header snapshot would be a
// real memory/throughput cost on the hot path; CrashFinding (identity.go)
// already carries that full detail for the one request that actually crashed.
// Status and Identity close the two most valuable gaps for chain
// readability without that cost: Status is unknown at build time (extendTrace
// runs before the request is sent) and is patched in once known
// (handleResult, worker.go); Identity is known at build time and set directly
// in extendTrace.
type TraceStep struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Mutation string `json:"mutation,omitempty"`
	Identity string `json:"identity,omitempty"`
	Status   int    `json:"status,omitempty"`
}

type AuthIdentity struct {
	Name    string
	Token   string
	Headers map[string]string
	Weight  float64
}

type CrashFinding struct {
	Signature    string
	ClusterKey   string
	ClusterLabel string
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
	// SequenceID/ChainTrace (Phase 5 #127, manifest.go/report.go/sarif.go) carry
	// the full multi-step chain a sequence-originated crash was reached
	// through, for report/SARIF output -- distinct from Trace (WorkItem, every
	// item) and from Minimized's chain_* summary counters (minimize.go): this
	// is the actual step-by-step SequenceStep list itself. Reflects
	// pocItem.SeqState.History AFTER whole-chain minimization has run, so a
	// shrunk chain is what gets reported, not the original. Empty for any
	// non-sequence crash (SeqState == nil).
	SequenceID string
	ChainTrace []SequenceStep
	// Bindings (Phase 5 #127/#128) is this finding's own slice of
	// f.producerConsumerBindings (sequence.go), filtered to SequenceID --
	// "which of this chain's IDs genuinely came from a producer response, and
	// from where" as a directly reportable fact, not something a reader has
	// to cross-reference ChainTrace's raw request/response pairs to infer.
	Bindings []ProducerConsumerBinding
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
		Identity: sanitizeText(item.Identity, 64),
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

// patchTraceStatus records item's own step's now-known Status into the last
// entry of item.Trace (a no-op if the trace is empty) -- Status is unavailable
// at trace-build time (extendTrace runs before the request is sent), so
// handleResult (worker.go) calls this as soon as the response is known.
// Mutates in place: item.Trace's backing array is shared with any follow-up
// item later built via extendTrace(item.Trace, ...), so this must run before
// any of those run. A standalone function (not a Fuzzer method) since it
// touches nothing but its arguments -- kept easy to unit-test without
// constructing a full Fuzzer.
func patchTraceStatus(item WorkItem, status int) {
	if n := len(item.Trace); n > 0 {
		item.Trace[n-1].Status = status
	}
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
		// Reuse f.idWeightsBuf across calls (the same buffer-reuse pattern worker.go's
		// weightsBuf/tidsBuf already use for template selection) instead of allocating a
		// fresh slice every request -- this function runs on the single work-item-
		// building goroutine (buildWorkItem -> decorateWorkItem), never concurrently,
		// so reuse here is safe.
		weights := f.idWeightsBuf[:0]
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
		f.idWeightsBuf = weights // capture growth so a later call can reuse the larger backing array
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
	// Phase 4 #119: tag every item in this burst with a shared BurstID so
	// their results can be correlated back into "how many of these N
	// concurrent identical requests succeeded" once they've all completed
	// (recordRaceBurstResult, race.go) -- the concurrency-pattern oracle
	// (double-spend/concurrent-approve/etc.), distinct from this burst
	// mechanism's pre-existing role of just surfacing generic crashes.
	burstID := fmt.Sprintf("race-%d-%d", f.totalDone, rand.Int63())
	burstAction := deriveTransitionActionForTemplate(f.meta[source.TemplateID], source.Method, source.Path)
	added := 0
	for i := 0; i < n; i++ {
		it := source
		it.MutationName = "race_conflict"
		it.MutationLabel = sanitizeText(source.MutationLabel+"+race", 256)
		it.Trace = f.extendTrace(source.Trace, it)
		it.BurstID = burstID
		it.BurstSize = n
		it.BurstAction = burstAction
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
	for _, kw := range []string{
		"cart", "order", "checkout", "payment", "invoice", "discount", "coupon", "stock", "wishlist", "balance",
		// Phase 4 #119: action-shaped keywords for the concurrent
		// approve/cancel/redeem/withdraw/transfer family, not just the
		// original commerce-cart keyword set -- these are exactly the
		// endpoints where "two concurrent identical requests both succeeded"
		// is a meaningful business-logic race, not just a generic 500.
		"approve", "cancel", "redeem", "withdraw", "transfer", "refund", "reject", "accept", "confirm",
	} {
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

	// Target misconfiguration: a DI/service-resolution failure means the endpoint
	// 500s because of how the *instrumented image was built* (e.g. Secrets Manager
	// services not registered), not because of a bug in the application logic.
	// These must be excluded from the vulnerability count entirely.
	misconfig := false
	for _, m := range []string{
		"unable to resolve service for type", "no service for type",
		"unable to activate type", "cannot instantiate implementation type",
		"unable to resolve service",
	} {
		if strings.Contains(bodyLow, m) {
			misconfig = true
			break
		}
	}
	if misconfig {
		reasons = append(reasons, "target_misconfiguration")
	}

	// Benign input-validation 500s: the app threw while PARSING a malformed
	// route/body value (bad GUID, bad base64, etc.) before any business logic ran.
	// These are low-value robustness bugs and dominate raw crash counts; cap them
	// so they never masquerade as confirmed unhandled exceptions in real code.
	benignParse := false
	for _, m := range []string{
		"unrecognized guid format", "guid should contain 32 digits",
		"byte array for guid must be", "illegal base64url string",
		"illegal base64 string", "the input is not a valid base-64 string",
		"could not be parsed", "was not recognized as a valid",
		"input string was not in a correct format",
	} {
		if strings.Contains(bodyLow, m) {
			benignParse = true
			break
		}
	}
	if benignParse {
		score -= 2.5
		reasons = append(reasons, "benign_input_validation")
	}

	// Exploitation signals: concrete evidence that a payload actually did something
	// dangerous — not merely that the server threw a 500. Only these justify a
	// "likely_vuln" rating. A bare unhandled exception is a robustness bug.
	exploitReasons := exploitationSignals(res)
	hasExploitSignal := len(exploitReasons) > 0
	reasons = append(reasons, exploitReasons...)
	if hasExploitSignal {
		score += 3.0
	}
	score = clampFloat(score, 0.0, 10.0)

	// Pre-auth crashes (deserialization/model_binding) prove instability but do NOT
	// demonstrate unauthorized access to business logic.
	preAuth := crashLayer == "deserialization" || crashLayer == "model_binding"

	// Classification honesty:
	//   likely_vuln*                -> requires a real exploitation signal.
	//   confirmed_unhandled_exception -> reproducible 500 with a backend stack trace,
	//                                    i.e. a robustness/DoS bug, NOT a proven vuln.
	//   needs_review                -> a 500 we could not attribute.
	//   target_misconfiguration     -> build/config artifact, excluded from vuln count.
	//   noise                       -> filtered (content-type, synthetic paths, etc.).
	classification := "noise"
	switch {
	case misconfig && !hasExploitSignal:
		classification = "target_misconfiguration"
	case hasExploitSignal && score >= 8.0 && !preAuth:
		classification = "likely_vuln_high"
	case hasExploitSignal && score >= 6.0 && !preAuth:
		classification = "likely_vuln"
	case benignParse && !hasExploitSignal:
		// Malformed-input parse exception: cap at needs_review regardless of score.
		if score >= 4.0 {
			classification = "needs_review"
		}
	case score >= 6.0 && !preAuth:
		classification = "confirmed_unhandled_exception"
	case score >= 4.0:
		classification = "needs_review"
	}
	impact := "stability"
	if hasExploitSignal {
		impact = "exploitable"
	} else if misconfig {
		impact = "target_config"
	} else if strings.Contains(pathLow, "auth") || strings.Contains(pathLow, "login") || strings.Contains(pathLow, "role") || strings.Contains(pathLow, "admin") {
		impact = "authz/authn"
	} else if strings.Contains(pathLow, "cart") || strings.Contains(pathLow, "order") || strings.Contains(pathLow, "payment") || strings.Contains(pathLow, "billing") {
		impact = "business_logic"
	}
	return map[string]any{
		"classification": classification,
		// Floor (not round) so severity_score never crosses a classification band it
		// didn't earn — e.g. score 3.8 stays severity 3 alongside a "noise" label
		// instead of showing a contradictory severity 4.
		"severity_score":       int(math.Floor(score)),
		"score":                fmt.Sprintf("%.2f", score),
		"dev_mode":             devMode,
		"impact_hint":          impact,
		"crash_layer":          crashLayer,
		"reasons":              dedupStrings(reasons),
		"exploitation_signals": exploitReasons,
	}
}

// exploitationSignals looks for concrete evidence that an injected payload
// actually executed or exfiltrated data — the difference between "the server
// erred" and "the server is vulnerable". Returns reason tags (empty = none).
func exploitationSignals(res SendResult) []string {
	out := []string{}
	body := res.Body
	bodyLow := strings.ToLower(body)
	sentLow := strings.ToLower(res.Item.Body + " " + res.Item.Path)

	// SQL injection: database engine error strings surfacing in the response.
	for _, m := range []string{
		"you have an error in your sql syntax", "unclosed quotation mark",
		"quoted string not properly terminated", "syntax error at or near",
		"sqlite3.operationalerror", "npgsql.postgresexception",
		"microsoft.data.sqlclient.sqlexception", "system.data.sqlclient.sqlexception",
		"ora-00933", "ora-01756", "conversion failed when converting",
	} {
		if strings.Contains(bodyLow, m) {
			out = append(out, "sqli_error_reflected")
			break
		}
	}

	// Path traversal / LFI: contents of a well-known system file in the response.
	if strings.Contains(body, "root:x:0:0:") || strings.Contains(body, "root:*:0:0:") ||
		strings.Contains(bodyLow, "[boot loader]") || strings.Contains(bodyLow, "; for 16-bit app support") {
		out = append(out, "file_read_success")
	}

	// SSRF: cloud metadata contents echoed back (only counts if we actually asked for it) --
	// AND only if the match isn't just our own payload being echoed back verbatim. A field
	// that stores-then-returns whatever string it was given (a very common "update X,
	// respond with the updated X" REST pattern) trivially satisfies a naive substring check:
	// two of the markers this used to check for ("iam/security-credentials",
	// "computemetadata") are themselves literal substrings of the SSRF payloads below, so
	// they could never distinguish "the target fetched this URL and got real metadata back"
	// from "the target just handed my own string back to me". Found as a real false positive
	// on Bitwarden's PUT /settings/domains, which stores an arbitrary user-submitted domain
	// list and returns it unchanged -- no outbound fetch anywhere in that code path.
	// bodyWithoutEcho strips every literal occurrence of a known SSRF payload from the body
	// before matching, so a marker overlapping a payload substring (now or in the future)
	// can't be satisfied by pure echo, only by content the target itself generated.
	if strings.Contains(sentLow, "169.254.169.254") || strings.Contains(sentLow, "metadata.google") ||
		strings.Contains(sentLow, "100.100.100.200") {
		bodyWithoutEcho := bodyLow
		for _, payload := range ssrfMetadataPayloads {
			bodyWithoutEcho = strings.ReplaceAll(bodyWithoutEcho, strings.ToLower(payload), "")
		}
		for _, m := range []string{
			"ami-id", "instance-identity", "accesskeyid", "secretaccesskey", "sessiontoken",
			"service-accounts/", "numeric-project-id", "hostname\nid\n",
		} {
			if strings.Contains(bodyWithoutEcho, m) {
				out = append(out, "ssrf_metadata_reflected")
				break
			}
		}
	}

	// Reflected XSS: the exact script payload comes back unescaped in an HTML response.
	ct := strings.ToLower(res.Headers["Content-Type"] + res.Headers["content-type"])
	if strings.Contains(ct, "text/html") {
		for _, p := range []string{"<script>alert(1)</script>", "<svg/onload=alert(1)>", "onerror=alert(document.domain)"} {
			if strings.Contains(sentLow, strings.ToLower(p)) && strings.Contains(body, p) {
				out = append(out, "xss_reflected_unescaped")
				break
			}
		}
	}

	// Open redirect: Location header points at an attacker-controlled host we injected.
	loc := strings.ToLower(res.Headers["Location"] + res.Headers["location"])
	if loc != "" && strings.Contains(sentLow, "evil.com") && strings.Contains(loc, "evil.com") {
		out = append(out, "open_redirect")
	}

	// SSTI: a distinctive arithmetic marker was EVALUATED (product present in the
	// response) rather than merely reflected (expression text absent). The rare
	// products keep this low-false-positive.
	for expr, product := range map[string]string{"1337*1337": "1787569", "2340*2375": "5557500"} {
		if strings.Contains(res.Item.Body+res.Item.Path, expr) {
			if strings.Contains(body, product) && !strings.Contains(body, expr) {
				out = append(out, "ssti_evaluated")
				break
			}
		}
	}

	return dedupStrings(out)
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

// cloneChainTrace returns a defensive copy of seqState's History (nil for a
// nil seqState, i.e. any non-sequence crash) -- CrashFinding.ChainTrace must
// not alias the live SequenceState's backing slice, which later sequence
// steps continue to append to / whose backing array minimizeChainCandidate's
// caller (crash.go) may have just replaced.
func cloneChainTrace(seqState *SequenceState) []SequenceStep {
	if seqState == nil || len(seqState.History) == 0 {
		return nil
	}
	out := make([]SequenceStep, len(seqState.History))
	copy(out, seqState.History)
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
