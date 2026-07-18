package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// oracle.go — Access-control oracles (BOLA/IDOR + broken authentication).
//
// The rest of the engine treats "HTTP 500" as the only bug signal, which finds
// robustness bugs but not access-control vulnerabilities — the #1 class of real
// API bugs. These oracles reuse the multi-identity machinery: when identity A
// successfully reaches a resource-scoped endpoint, we *replay the identical
// request* under (a) every other configured identity and (b) no credentials at
// all. If a different principal — or an anonymous caller — also gets a 2xx with
// a real body, that is a candidate Broken Object-Level Authorization (BOLA) or
// broken-authentication finding, and unlike a 500 it is a genuine vulnerability.

const (
	oracleKindBOLA       = "bola"
	oracleKindAuthBypass = "authbypass"
	oracleKindMassAssign = "massassign"
	unauthIdentity       = "__unauth__"
)

// privilegeFields are the security-sensitive properties a mass-assignment probe
// over-posts into a write body. Values are raw JSON, chosen to be UNlikely to be
// an object's natural state (e.g. accessLevel=99, permissions=["*"]) so that
// seeing one reflected back is a strong signal the field was accepted rather than
// a coincidental default. Fields like isActive/emailConfirmed are deliberately
// excluded — their common values (true) would produce false positives.
var privilegeFields = []struct{ Field, Value string }{
	{"isAdmin", "true"}, {"isSuperAdmin", "true"}, {"isSystemAdmin", "true"},
	{"isRoot", "true"}, {"isStaff", "true"}, {"admin", "true"},
	{"role", `"SuperAdmin"`}, {"roles", `["SuperAdmin"]`},
	{"accessLevel", "99999"}, {"permissions", `["*"]`}, {"privilegeLevel", "99999"},
}

// authHeaderNames are the request headers we strip from a replayed probe so the
// shadow identity's credentials (or none) fully determine authorization.
var authHeaderNames = []string{"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "Api-Key"}

// maybeEnqueueAccessProbes fires cross-identity / no-auth replays after a
// successful, resource-scoped request under an authenticated identity.
func (f *Fuzzer) maybeEnqueueAccessProbes(res SendResult) {
	if !f.cfg.AccessProbe || res.Item.OracleKind != "" {
		return
	}
	if !f.cfg.ProbeBOLA && !f.cfg.ProbeAuthBypass {
		return
	}
	if res.Status < 200 || res.Status >= 300 {
		return
	}
	switch res.Item.Method {
	case "GET", "PUT", "PATCH", "DELETE", "POST":
	default:
		return
	}
	// Only meaningful for requests that name a specific resource, and only when
	// the ORIGIN caller was actually authenticated (else there is nothing to bypass).
	if !pathHasConcreteResourceID(res.Item.Path) {
		return
	}
	if !f.identityIsAuthed(res.Item.Identity) {
		return
	}
	// Nothing to steal from an empty/default response — this is the dominant BOLA
	// false-positive source between two fresh accounts, so skip trivial bodies.
	if isTrivialBody(res.Body) {
		return
	}
	// Bound the volume: per-endpoint cap + probability gate.
	epKey := endpointKey(res.Item.Method, normalizeEndpointPath(res.Item.Path))
	if f.accessProbeCount[epKey] >= f.cfg.AccessProbeMaxPerEndpoint {
		return
	}
	if rand.Float64() > clampFloat(f.cfg.AccessProbeProb, 0.0, 1.0) {
		return
	}

	originFP := stableResponseFingerprint(res.Body)
	originLen := len(strings.TrimSpace(res.Body))
	enqueued := 0

	mkProbe := func(kind, shadow string, noAuth bool) WorkItem {
		p := res.Item
		p.OracleKind = kind
		p.NoAuth = noAuth
		p.Identity = shadow
		p.OracleOriginIdentity = res.Item.Identity
		p.OracleOriginStatus = res.Status
		p.OracleOriginFP = originFP
		p.OracleOriginBodyLen = originLen
		p.SeedIdx = -1
		p.Trace = nil
		p.Headers = stripAuthHeaders(p.Headers)
		p.MutationName = "acl_" + kind
		p.MutationLabel = "acl_probe(" + kind + ")"
		return p
	}

	// BOLA: replay under every *distinct* other identity.
	if f.cfg.ProbeBOLA {
		for _, id := range f.identities {
			if enqueued >= f.cfg.AccessProbeMaxPerEndpoint {
				break
			}
			if id.Name == res.Item.Identity {
				continue
			}
			if f.sameCredentials(id.Name, res.Item.Identity) {
				continue
			}
			f.oracleEnqueue(mkProbe(oracleKindBOLA, id.Name, false))
			enqueued++
		}
	}
	// Broken authentication: replay with no credentials — but ONLY on endpoints we
	// have already seen reject unauthenticated access (401/403). This removes the
	// public-endpoint false positive: a truly public endpoint never reaches here.
	if f.cfg.ProbeAuthBypass && f.authRequiredEndpoints[epKey] >= 1 {
		f.oracleEnqueue(mkProbe(oracleKindAuthBypass, unauthIdentity, true))
		enqueued++
	}

	if enqueued > 0 {
		f.accessProbeCount[epKey] += enqueued
	}
}

// markAuthRequired records that an endpoint enforces authentication, based on a
// 401/403 response. `strong` means the rejected request carried no effective
// credentials (guest/unauth) — the most direct evidence that unauthenticated
// access is denied there.
func (f *Fuzzer) markAuthRequired(method, path string, strong bool) {
	k := endpointKey(method, normalizeEndpointPath(path))
	v := 1
	if strong {
		v = 2
	}
	if v > f.authRequiredEndpoints[k] {
		f.authRequiredEndpoints[k] = v
	}
}

// maybeEnqueueMassAssignProbe fires after a successful write with a JSON object
// body: it re-sends the same request with privileged fields over-posted into the
// body, then checks whether the server accepted and reflected them back.
func (f *Fuzzer) maybeEnqueueMassAssignProbe(res SendResult) {
	if !f.cfg.AccessProbe || !f.cfg.ProbeMassAssign || res.Item.OracleKind != "" {
		return
	}
	if res.Status < 200 || res.Status >= 300 {
		return
	}
	switch res.Item.Method {
	case "POST", "PUT", "PATCH":
	default:
		return
	}
	if !f.identityIsAuthed(res.Item.Identity) {
		return
	}
	newBody, injected, ok := mergePrivilegeFieldsJSON(res.Item.Body)
	if !ok || len(injected) == 0 {
		return
	}
	epKey := endpointKey(res.Item.Method, normalizeEndpointPath(res.Item.Path)) + "|ma"
	if f.accessProbeCount[epKey] >= f.cfg.AccessProbeMaxPerEndpoint {
		return
	}
	if rand.Float64() > clampFloat(f.cfg.AccessProbeProb, 0.0, 1.0) {
		return
	}
	p := res.Item
	p.OracleKind = oracleKindMassAssign
	p.Body = newBody
	p.SeedIdx = -1
	p.Trace = nil
	p.OracleOriginIdentity = res.Item.Identity
	p.OracleOriginStatus = res.Status
	p.MutationName = "acl_massassign"
	p.MutationLabel = "acl_probe(massassign)"
	f.oracleEnqueue(p)
	f.accessProbeCount[epKey]++
}

// mergePrivilegeFieldsJSON over-posts privileged fields into a JSON object body,
// skipping any key already present. Returns the new body, the injected field
// names, and whether the body was a mergeable JSON object.
func mergePrivilegeFieldsJSON(body string) (string, []string, bool) {
	s := strings.TrimSpace(body)
	if !strings.HasPrefix(s, "{") {
		return "", nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &obj); err != nil || obj == nil {
		return "", nil, false
	}
	injected := []string{}
	for _, pf := range privilegeFields {
		exists := false
		for k := range obj {
			if strings.EqualFold(k, pf.Field) {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		obj[pf.Field] = json.RawMessage(pf.Value)
		injected = append(injected, pf.Field)
	}
	if len(injected) == 0 {
		return "", nil, false
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return "", nil, false
	}
	return string(out), injected, true
}

// reflectedPrivilegeField reports the first injected privileged field that the
// response echoes back with its injected value (evidence of over-posting).
func reflectedPrivilegeField(body string) string {
	norm := strings.ToLower(strings.Join(strings.Fields(body), ""))
	for _, pf := range privilegeFields {
		needle := `"` + strings.ToLower(pf.Field) + `":` + strings.ToLower(pf.Value)
		if strings.Contains(norm, needle) {
			return pf.Field
		}
	}
	return ""
}

func (f *Fuzzer) oracleEnqueue(item WorkItem) {
	if len(f.oracleQueue) >= f.cfg.AccessProbeQueueMax {
		f.oracleQueue = f.oracleQueue[1:]
	}
	f.oracleQueue = append(f.oracleQueue, item)
}

// handleOracleResult evaluates a returned access-control probe.
func (f *Fuzzer) handleOracleResult(res SendResult) {
	if res.Err != nil {
		return
	}
	// A probe only matters if the shadow principal was *granted* access.
	if res.Status < 200 || res.Status >= 300 {
		return
	}
	body := strings.TrimSpace(res.Body)
	if len(body) == 0 || looksLikeErrorBody(res.Status, body) || isTrivialBody(body) {
		return
	}

	shadowFP := stableResponseFingerprint(res.Body)
	identical := shadowFP != "" && shadowFP == res.Item.OracleOriginFP

	kind := res.Item.OracleKind
	var class string
	var severity int
	reasons := []string{}

	switch kind {
	case oracleKindMassAssign:
		// The write with over-posted privileged fields succeeded. If the response
		// echoes an injected field with its injected value, the server accepted it.
		field := reflectedPrivilegeField(res.Body)
		if field == "" {
			return
		}
		class = "likely_vuln"
		severity = 8
		reasons = append(reasons, "mass_assignment_privileged_field_accepted:"+field, "needs_manual_verification")
		f.recordAccessControlFinding(res, kind, class, severity, reasons, false)
		return
	case oracleKindAuthBypass:
		// A resource that one identity had to authenticate for is now reachable
		// with zero credentials. Confidence depends on how strongly we know the
		// endpoint enforces auth: strength 2 = we saw it reject an unauthenticated
		// request (401/403), strength 1 = it rejected someone.
		strength := f.authRequiredEndpoints[endpointKey(res.Item.Method, normalizeEndpointPath(res.Item.Path))]
		if strength >= 2 {
			class = "likely_vuln_high"
			severity = 9
			reasons = append(reasons, "auth_bypass_unauthenticated_access", "endpoint_rejected_unauth_401_403")
		} else {
			class = "likely_vuln"
			severity = 7
			reasons = append(reasons, "auth_bypass_unauthenticated_access", "needs_manual_verification")
		}
		if identical {
			reasons = append(reasons, "identical_response_to_authenticated")
		}
	case oracleKindBOLA:
		if identical {
			class = "likely_vuln_high"
			severity = 9
			reasons = append(reasons, "bola_identical_cross_identity_response")
		} else {
			// 2xx with a *different* substantial body — could be the shadow
			// identity's own data (shared endpoint) rather than A's object, so
			// flag lower and mark for manual confirmation.
			class = "likely_vuln"
			severity = 7
			reasons = append(reasons, "bola_suspected_cross_identity_access", "needs_manual_verification")
		}
	default:
		return
	}
	f.recordAccessControlFinding(res, kind, class, severity, reasons, identical)
}

// recordAccessControlFinding logs a de-duplicated access-control finding.
func (f *Fuzzer) recordAccessControlFinding(res SendResult, kind, class string, severity int, reasons []string, identical bool) {
	normPath := normalizeEndpointPath(res.Item.Path)
	dedupKey := "acl|" + kind + "|" + res.Item.Method + "|" + normPath + "|" + res.Item.OracleOriginIdentity + "->" + res.Item.Identity
	if _, ok := f.aclSeen[dedupKey]; ok {
		return
	}
	f.aclSeen[dedupKey] = struct{}{}
	f.accessFindings++

	shadowLabel := res.Item.Identity
	if kind == oracleKindAuthBypass {
		shadowLabel = "<no-auth>"
	}
	sig := hashWithFNV(dedupKey)
	triage := map[string]any{
		"classification":  class,
		"severity_score":  severity,
		"impact_hint":     "access_control",
		"crash_layer":     "authorization",
		"oracle":          kind,
		"origin_identity": res.Item.OracleOriginIdentity,
		"shadow_identity": shadowLabel,
		"origin_status":   res.Item.OracleOriginStatus,
		"shadow_status":   res.Status,
		"identical_body":  identical,
		"reasons":         dedupStrings(reasons),
	}
	f.addEvent(fmt.Sprintf("ACL %s  %s %s  %s -> %s  (%d)", strings.ToUpper(kind),
		res.Item.Method, truncate(normalizePath(res.Item.Path), 48),
		res.Item.OracleOriginIdentity, shadowLabel, res.Status))

	uniq := map[string]any{
		"signature":       sig,
		"ts":              time.Now().Format(time.RFC3339),
		"elapsed_secs":    fmt.Sprintf("%.3f", time.Since(f.startTime).Seconds()),
		"status_code":     res.Status,
		"method":          res.Item.Method,
		"path":            sanitizeText(res.Item.Path, 1024),
		"identity":        shadowLabel,
		"mutation":        "acl_" + kind,
		"payload":         truncate(sanitizeText(res.Item.Body, 4000), 4000),
		"response_body":   truncate(sanitizeText(res.Body, 4000), 4000),
		"exception_type":  "",
		"triage":          triage,
		"access_control":  true,
		"origin_identity": res.Item.OracleOriginIdentity,
	}
	_ = f.uniqueWriter.Write(uniq)

	f.findings = append(f.findings, CrashFinding{
		Signature:  sig,
		ClusterKey: sig,
		TS:         time.Now().Format(time.RFC3339),
		ElapsedSec: fmt.Sprintf("%.3f", time.Since(f.startTime).Seconds()),
		Method:     res.Item.Method,
		Path:       strings.ToValidUTF8(res.Item.Path, "?"),
		Status:     res.Status,
		Identity:   shadowLabel,
		Mutation:   "acl_" + kind,
		Payload:    strings.ToValidUTF8(res.Item.Body, "?"),
		Response:   strings.ToValidUTF8(res.Body, "?"),
		Triage:     triage,
	})
}

// checkInjectionOracle runs positive injection detection on NON-crash responses
// (2xx/3xx/4xx). 5xx exploit signals are already handled by crash triage; here
// we catch the vulns that succeed silently: reflected XSS, evaluated SSTI, and
// time-based SQLi.
func (f *Fuzzer) checkInjectionOracle(res SendResult) {
	if !f.cfg.InjectionOracle || res.Item.OracleKind != "" || res.Err != nil {
		return
	}
	if res.Status >= 500 {
		return
	}
	// Cheap gate: only inspect responses where a security-category payload was
	// actually applied (labels are "...mcat_<category>..."). Avoids scanning every
	// benign response and keeps the hot path fast.
	if !strings.Contains(res.Item.MutationLabel, "mcat_") {
		return
	}
	sigs := exploitationSignals(res)
	if f.isTimeBasedSQLiHit(res) {
		sigs = append(sigs, "sqli_time_based")
	}
	sigs = dedupStrings(sigs)
	if len(sigs) == 0 {
		return
	}
	f.recordInjectionFinding(res, sigs)
}

// isTimeBasedSQLiHit reports a sleep/benchmark SQLi payload whose response
// latency is far above the running baseline — evidence the injection executed.
func (f *Fuzzer) isTimeBasedSQLiHit(res SendResult) bool {
	probe := strings.ToLower(res.Item.MutationLabel + " " + res.Item.Body + " " + res.Item.Path)
	sleepy := strings.Contains(probe, "sleep(") || strings.Contains(probe, "waitfor delay") ||
		strings.Contains(probe, "pg_sleep(") || strings.Contains(probe, "benchmark(")
	if !sleepy {
		return false
	}
	latMS := float64(res.Latency.Milliseconds())
	if latMS < f.cfg.SQLiTimeThresholdSec*1000.0 {
		return false
	}
	// Require a clear multiple of the observed baseline to reject slow-but-normal endpoints.
	return f.baselineLatMS <= 0 || latMS >= f.baselineLatMS*3.0
}

func (f *Fuzzer) recordInjectionFinding(res SendResult, sigs []string) {
	normPath := normalizeEndpointPath(res.Item.Path)
	primary := sigs[0]
	dedupKey := "inj|" + primary + "|" + res.Item.Method + "|" + normPath
	if _, ok := f.aclSeen[dedupKey]; ok {
		return
	}
	f.aclSeen[dedupKey] = struct{}{}
	f.accessFindings++ // counted alongside access-control findings as "confirmed exploit" findings

	// Severity: code execution / data exfiltration are high; reflection is medium.
	class, severity := "likely_vuln", 7
	for _, s := range sigs {
		switch s {
		case "sqli_time_based", "sqli_error_reflected", "ssti_evaluated", "file_read_success", "ssrf_metadata_reflected":
			class, severity = "likely_vuln_high", 9
		}
	}
	sig := hashWithFNV(dedupKey)
	triage := map[string]any{
		"classification":       class,
		"severity_score":       severity,
		"impact_hint":          "exploitable",
		"crash_layer":          "application",
		"oracle":               "injection",
		"exploitation_signals": dedupStrings(sigs),
		"reasons":              dedupStrings(sigs),
	}
	f.addEvent(fmt.Sprintf("INJECT %s  %s %s  (%d)", primary,
		res.Item.Method, truncate(normalizePath(res.Item.Path), 48), res.Status))

	uniq := map[string]any{
		"signature":      sig,
		"ts":             time.Now().Format(time.RFC3339),
		"elapsed_secs":   fmt.Sprintf("%.3f", time.Since(f.startTime).Seconds()),
		"status_code":    res.Status,
		"method":         res.Item.Method,
		"path":           sanitizeText(res.Item.Path, 1024),
		"identity":       sanitizeText(res.Item.Identity, 64),
		"mutation":       sanitizeText(res.Item.MutationLabel, 512),
		"payload":        truncate(sanitizeText(res.Item.Body, 4000), 4000),
		"response_body":  truncate(sanitizeText(res.Body, 4000), 4000),
		"exception_type": "",
		"triage":         triage,
		"injection":      true,
	}
	_ = f.uniqueWriter.Write(uniq)

	f.findings = append(f.findings, CrashFinding{
		Signature:  sig,
		ClusterKey: sig,
		TS:         time.Now().Format(time.RFC3339),
		ElapsedSec: fmt.Sprintf("%.3f", time.Since(f.startTime).Seconds()),
		Method:     res.Item.Method,
		Path:       strings.ToValidUTF8(res.Item.Path, "?"),
		Status:     res.Status,
		Identity:   strings.ToValidUTF8(res.Item.Identity, "?"),
		Mutation:   strings.ToValidUTF8(res.Item.MutationLabel, "?"),
		Payload:    strings.ToValidUTF8(res.Item.Body, "?"),
		Response:   strings.ToValidUTF8(res.Body, "?"),
		Triage:     triage,
	})
}

// --- helpers ---------------------------------------------------------------

func (f *Fuzzer) identityIsAuthed(name string) bool {
	headers, token, _ := f.identityAuth(name)
	if strings.TrimSpace(token) != "" {
		return true
	}
	for _, h := range authHeaderNames {
		if strings.TrimSpace(getHeaderCI(headers, h)) != "" {
			return true
		}
	}
	return false
}

func (f *Fuzzer) sameCredentials(a, b string) bool {
	ha, ta, _ := f.identityAuth(a)
	hb, tb, _ := f.identityAuth(b)
	if strings.TrimSpace(ta) != strings.TrimSpace(tb) {
		return false
	}
	return strings.TrimSpace(getHeaderCI(ha, "Authorization")) == strings.TrimSpace(getHeaderCI(hb, "Authorization")) &&
		strings.TrimSpace(getHeaderCI(ha, "Cookie")) == strings.TrimSpace(getHeaderCI(hb, "Cookie"))
}

func stripAuthHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		skip := false
		for _, name := range authHeaderNames {
			if strings.EqualFold(k, name) {
				skip = true
				break
			}
		}
		if !skip {
			out[k] = v
		}
	}
	return out
}

// pathHasConcreteResourceID reports whether the path names a specific resource
// via a real object handle — a UUID, a numeric id, a long hex id, or a dashed
// token that CONTAINS A DIGIT (e.g. usr-1234). It deliberately does NOT treat a
// hyphenated dictionary word (is-country-supported, key-rotation-data,
// device-verification-settings) as an id: those are static route segments, and
// mistaking them for resource ids produced false-positive BOLA findings on
// non-object "self" endpoints.
func pathHasConcreteResourceID(path string) bool {
	for _, seg := range splitPathTokens(normalizePath(path)) {
		s := strings.TrimSpace(seg)
		if s == "" {
			continue
		}
		if reUUIDLike.MatchString(s) || reAllDigits.MatchString(s) || reHexLong.MatchString(s) {
			return true
		}
		// A dashed/underscored token only counts as an id if it carries a digit —
		// this admits usr-1234 / obj-0007 while rejecting plain hyphenated words.
		if strings.ContainsAny(s, "-_") && hasASCIIDigit(s) && len(s) >= 6 {
			return true
		}
	}
	return false
}

// isTrivialBody reports whether a response body is empty or an empty-collection
// shape. Two fresh accounts return identical trivial bodies almost everywhere,
// which is the dominant BOLA false-positive source — there is nothing to steal
// from an empty response, so such comparisons must not be flagged.
func isTrivialBody(body string) bool {
	s := strings.TrimSpace(body)
	if len(s) < 8 {
		return true
	}
	switch s {
	case "[]", "{}", "null", `""`, "[ ]", "{ }":
		return true
	}
	compact := strings.ToLower(strings.Join(strings.Fields(s), ""))
	if len(compact) < 60 {
		for _, e := range []string{`"data":[]`, `"data":null`, `"items":[]`, `"results":[]`, `"value":[]`, `"count":0`, `"total":0`} {
			if strings.Contains(compact, e) {
				return true
			}
		}
	}
	return false
}

// looksLikeErrorBody detects an error-shaped 2xx body (some frameworks return
// 200 with an error envelope) so we don't raise a false access-control finding.
func looksLikeErrorBody(status int, body string) bool {
	low := strings.ToLower(body)
	for _, m := range []string{
		`"error"`, `"errors"`, "access denied", "not authorized", "unauthorized",
		"forbidden", "\"status\":401", "\"status\":403", "\"status\":404",
	} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}
