package engine

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// cluster.go — Root-cause clustering.
//
// The per-crash Signature (crash.go) is intentionally fine-grained: it folds in
// the request path and the mutation label, so the same underlying bug triggered
// from many endpoints or many payloads produces many distinct signatures. That
// is useful for forensic dedup of individual repro variants, but it massively
// over-counts *distinct bugs* in reports (e.g. one "Unrecognized Guid format"
// model-binding bug reached from 60 routes = 60 signatures = 1 real bug).
//
// A ClusterKey groups crashes by their ROOT CAUSE instead: the normalized
// backend exception message plus the first application stack frame. When no
// exception detail is available (production mode, no dev stack), it falls back
// to (method + status + path template) so those still cluster per-endpoint
// rather than exploding per-payload.

// ClusterInfo aggregates all crash variants that share a single root cause.
type ClusterInfo struct {
	Key          string `json:"key"`
	Label        string `json:"label"`
	Variants     int    `json:"variant_signatures"`
	CrashesTotal int    `json:"crashes_total"`
	MaxSeverity  int    `json:"max_severity_score"`
	Class        string `json:"classification"`
	RepSignature string `json:"representative_signature"`
	RepMethod    string `json:"representative_method"`
	RepPath      string `json:"representative_path"`
	RepException string `json:"representative_exception,omitempty"`
	Status       int    `json:"status_code"`
	HasException bool   `json:"has_exception_detail"`
}

var (
	// reExcMsgField pulls the exceptionMessage from ASP.NET's JSON error envelope.
	reExcMsgField = regexp.MustCompile(`(?i)"exceptionMessage"\s*:\s*"((?:[^"\\]|\\.){0,300})"`)
	// reFirstDotNetException matches a leading ".NET exception class: message" line.
	reFirstDotNetException = regexp.MustCompile(`((?:[A-Za-z0-9_]+\.)+[A-Za-z0-9_]*Exception)\s*:\s*([^\r\n]{0,300})`)
	// reAppStackFrame matches a stack frame "... at Namespace.Class.Method(...)".
	// ASP.NET serializes stack traces inside a JSON string with escaped "\r\n"
	// (literal backslashes, not real newlines), so we anchor on the space-delimited
	// " at " token rather than on line starts.
	reAppStackFrame = regexp.MustCompile(`(?:^|\s)at\s+((?:[A-Za-z0-9_]+\.)+[A-Za-z0-9_<>` + "`" + `]+)`)
	// Noise strippers so payload-specific tokens don't split a cluster.
	reQuotedIdent = regexp.MustCompile(`'[^']*'`)
	reDblQuoted   = regexp.MustCompile(`"[^"]*"`)
	reGuidAny     = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reAnyNumber   = regexp.MustCompile(`\b\d+\b`)
	reBase64ish   = regexp.MustCompile(`\b[A-Za-z0-9+/_-]{16,}={0,2}\b`)
	reWs          = regexp.MustCompile(`\s+`)
)

// frameworkFramePrefixes are stack-frame namespaces that are NOT application code.
// We skip them when picking the "top app frame" so the cluster fingerprints the
// bug's location in the target, not in the runtime.
var frameworkFramePrefixes = []string{
	"system.", "microsoft.", "newtonsoft.", "swashbuckle.",
	"mediatr.", "automapper.", "serilog.", "polly.", "fluentvalidation.",
}

// extractExceptionMessage returns the most specific exception message available.
// A message from the X-Exception-Message header (reliable in production mode) is
// preferred over anything parsed from the body.
func extractExceptionMessage(body, exceptionType, exceptionMsg string) string {
	if m := strings.TrimSpace(exceptionMsg); m != "" {
		return m
	}
	s := strings.TrimSpace(body)
	if s != "" {
		if len(s) > 8192 {
			s = s[:8192]
		}
		// Preferred: ASP.NET JSON error envelope.
		if m := reExcMsgField.FindStringSubmatch(s); len(m) > 1 {
			if v := decodeJSONFragment(m[1]); strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		// Fallback: "Some.Namespace.FooException: message" in a raw dev-mode dump.
		if m := reFirstDotNetException.FindStringSubmatch(s); len(m) > 2 {
			return strings.TrimSpace(m[1]) + ": " + strings.TrimSpace(m[2])
		}
	}
	// Last resort: the exception class from the response header.
	return strings.TrimSpace(exceptionType)
}

// decodeJSONFragment un-escapes a captured JSON string fragment.
func decodeJSONFragment(raw string) string {
	var out string
	if err := json.Unmarshal([]byte(`"`+raw+`"`), &out); err == nil {
		return out
	}
	return raw
}

// normalizeExceptionMessage strips payload-specific tokens so that the same bug
// with different injected values collapses to one key.
func normalizeExceptionMessage(msg string) string {
	m := strings.ToLower(strings.TrimSpace(msg))
	if m == "" {
		return ""
	}
	m = reQuotedIdent.ReplaceAllString(m, "'x'")
	m = reDblQuoted.ReplaceAllString(m, `"x"`)
	m = reGuidAny.ReplaceAllString(m, "<guid>")
	m = reBase64ish.ReplaceAllString(m, "<tok>")
	m = reAnyNumber.ReplaceAllString(m, "<n>")
	m = reWs.ReplaceAllString(m, " ")
	m = strings.TrimSpace(m)
	if len(m) > 160 {
		m = m[:160]
	}
	return m
}

// extractTopAppFrame returns the first stack frame belonging to application code.
func extractTopAppFrame(body string) string {
	s := body
	if len(s) > 8192 {
		s = s[:8192]
	}
	for _, m := range reAppStackFrame.FindAllStringSubmatch(s, 40) {
		if len(m) < 2 {
			continue
		}
		frame := strings.TrimSpace(m[1])
		low := strings.ToLower(frame)
		isFramework := false
		for _, p := range frameworkFramePrefixes {
			if strings.HasPrefix(low, p) {
				isFramework = true
				break
			}
		}
		if !isFramework {
			// Trim to Namespace.Class.Method (drop generic/anonymous tails).
			return frame
		}
	}
	return ""
}

// rootCauseClusterKey computes a stable cluster key + human label for a crash.
// The boolean reports whether real exception detail was available.
func rootCauseClusterKey(method string, status int, exceptionType, exceptionMsg, body, normPath string) (key, label string, hasException bool) {
	msg := extractExceptionMessage(body, exceptionType, exceptionMsg)
	normMsg := normalizeExceptionMessage(msg)
	frame := extractTopAppFrame(body)

	if normMsg != "" {
		parts := []string{"ex", normMsg}
		if frame != "" {
			parts = append(parts, "@"+strings.ToLower(frame))
		}
		key = hashWithFNV(strings.Join(parts, "|"))
		label = msg
		if frame != "" {
			label = msg + "  @ " + frame
		}
		if len(label) > 200 {
			label = label[:200]
		}
		return key, label, true
	}

	// No exception detail — cluster by endpoint template so we still collapse
	// per-payload noise into one row per (method, status, route). Coarsen the
	// typed placeholders ({uuid}/{id}/{int}/{hex}/{long}) to a single {param}:
	// the SAME route fragments into several templates otherwise, depending on
	// which value type the fuzzer happened to inject into each segment.
	tmpl := coarsenPathParams(normPath)
	key = hashWithFNV("ep|" + strings.ToUpper(method) + "|" + strconv.Itoa(status) + "|" + tmpl)
	label = strings.ToUpper(method) + " " + tmpl + " -> " + strconv.Itoa(status) + " (no exception detail)"
	return key, label, false
}

// coarsenPathParams collapses all typed path-placeholder tokens to a single
// {param} so one logical route maps to one cluster regardless of the injected
// value type.
func coarsenPathParams(normPath string) string {
	replacer := strings.NewReplacer(
		"{uuid}", "{param}",
		"{id}", "{param}",
		"{int}", "{param}",
		"{hex}", "{param}",
		"{long}", "{param}",
	)
	return replacer.Replace(normPath)
}

// recordCluster folds a crash into its root-cause cluster, updating the
// representative to the highest-severity variant seen.
func (f *Fuzzer) recordCluster(key, label, exception, class string, severity, status int, signature, method, path string, hasException bool) {
	if f.clusters == nil {
		f.clusters = map[string]*ClusterInfo{}
	}
	ci := f.clusters[key]
	if ci == nil {
		ci = &ClusterInfo{
			Key:          key,
			Label:        label,
			Class:        class,
			MaxSeverity:  severity,
			RepSignature: signature,
			RepMethod:    method,
			RepPath:      path,
			RepException: exception,
			Status:       status,
			HasException: hasException,
		}
		f.clusters[key] = ci
	}
	ci.Variants++ // counts unique variant signatures folded in
	if severity > ci.MaxSeverity {
		ci.MaxSeverity = severity
		ci.Class = class
		ci.RepSignature = signature
		ci.RepMethod = method
		ci.RepPath = path
		ci.RepException = exception
	}
}
