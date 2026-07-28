package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// utils.go — Generic utilities: string helpers, path normalization,
// value filtering, file I/O helpers, endpoint key derivation, regexps.

const (
	maxRuntimeValuesPerKey   = 200
	maxRuntimeRelationsPerKV = 500
	sequenceQueueMax         = 400
	raceQueueMax             = 512
	traceDepthMax            = 4
	minSHMBitmapSize         = 65536
	defaultSHMBitmapSize     = 262144
	// drainRemainderCap bounds the best-effort HTTP response-body drain in
	// worker.go::sendOneWithClient (reads to EOF, up to this cap, so the
	// Transport can reuse the connection) against a pathological/adversarial
	// target streaming an unbounded body.
	drainRemainderCap = 8 << 20 // 8MB
)

var (
	reNonAlnum       = regexp.MustCompile(`[^a-z0-9]+`)
	rePathParam      = regexp.MustCompile(`\{[^/{}]+\}`)
	reWordID         = regexp.MustCompile(`([a-z][a-z0-9]{1,40})id`)
	reJSONStartObj   = regexp.MustCompile(`^\s*\{`)
	reJSONStartAny   = regexp.MustCompile(`^\s*[\[{]`)
	reAPIVersion     = regexp.MustCompile(`^/v[0-9]+/`)
	reUUIDLike       = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reHexLong        = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reBizIDLike      = regexp.MustCompile(`(?i)^[a-z]{2,12}[-_][a-z0-9]{1,12}(?:[-_][a-z0-9]{1,12}){0,3}$`)
	reDashIDToken    = regexp.MustCompile(`(?i)^[a-z0-9]{1,20}(?:[-_][a-z0-9]{1,20}){1,6}$`)
	reAllDigits      = regexp.MustCompile(`^[0-9]{1,20}$`)
	reHTMLInputTag   = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reHTMLAttrKV     = regexp.MustCompile(`(?i)([a-z_:][a-z0-9_:\\.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	reTraceIDField   = regexp.MustCompile(`(?i)"traceid"\s*:\s*"[^"]+"`)
	reRequestIDField = regexp.MustCompile(`(?i)"requestid"\s*:\s*"[^"]+"`)
	reUUIDBody       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	reHexLongBody    = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	reNumLongBody    = regexp.MustCompile(`\b[0-9]{6,}\b`)
)

// --- generic helpers ---

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func parseAuthHeadersJSON(raw string) map[string]string {
	out := map[string]string{}
	s := strings.TrimSpace(raw)
	if s == "" {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return out
	}
	for k, v := range m {
		ks := strings.TrimSpace(k)
		vs := strings.TrimSpace(toString(v))
		if ks == "" || vs == "" {
			continue
		}
		out[ks] = vs
	}
	return out
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func deriveReportPathFromSummary(summaryPath string) string {
	sumAbs := absPath(summaryPath)
	if strings.TrimSpace(sumAbs) == "" {
		return absPath(filepath.Join("./summaries", "report.json"))
	}

	dir := filepath.Dir(sumAbs)
	base := filepath.Base(sumAbs)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if ext == "" {
		ext = ".json"
	}

	var reportName string
	switch {
	case strings.EqualFold(stem, "summary"):
		reportName = "report" + ext
	case strings.HasPrefix(stem, "summary-"):
		reportName = "report-" + strings.TrimPrefix(stem, "summary-") + ext
	default:
		reportName = stem + "-report" + ext
	}
	return filepath.Join(dir, reportName)
}

func ensureFileExists(path string, initialContent []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty output path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("output path is a directory: %s", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(initialContent) == 0 {
		initialContent = []byte{}
	}
	return os.WriteFile(path, initialContent, 0o644)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}

func normalizePath(path string) string {
	if i := strings.Index(path, "?"); i >= 0 {
		return path[:i]
	}
	return path
}

func splitPathTokens(path string) []string {
	p := strings.TrimSpace(normalizePath(path))
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	out := strings.Split(p, "/")
	return out
}

func pathPlaceholderName(segment string) (string, bool) {
	s := strings.TrimSpace(segment)
	if len(s) < 3 || !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}"))
	if name == "" {
		return "", false
	}
	if i := strings.IndexAny(name, ":?"); i >= 0 {
		name = strings.TrimSpace(name[:i])
	}
	if name == "" {
		return "", false
	}
	return name, true
}

func isPathPlaceholderValue(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return true
	}
	switch s {
	case "fuzzstring", "fuzzint", "fuzzbool", "fuzzuuid4", "fuzzuuid", "fuzzdate", "fuzzdatetime":
		return true
	}
	if strings.HasPrefix(s, "fuzz") || strings.HasPrefix(s, "custom_payload") {
		return true
	}
	return false
}

func normalizePathParamValue(v, fallback string) string {
	s := strings.TrimSpace(v)
	s = strings.Trim(s, "\"'")
	if s == "" {
		return fallback
	}
	// Reject any injection or special-char payloads from URL paths.
	// These produce garbage endpoint keys and confuse routing/coverage attribution.
	if strings.ContainsAny(s, "{}$%\r\n;@()*<>|`^~") {
		return fallback
	}
	// Also reject payloads that look like SQL, SSTI, or path traversal
	if strings.Contains(s, "..") || strings.Contains(s, "OR ") || strings.Contains(s, "SELECT") {
		return fallback
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return fallback
	}
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "?", "-")
	s = strings.ReplaceAll(s, "#", "-")
	s = strings.ReplaceAll(s, "&", "-")
	s = strings.Trim(s, ".")
	if s == "" {
		return fallback
	}
	if len(s) > 96 {
		s = s[:96]
	}
	return s
}

func compactPayloadForUI(body string, maxLen int) string {
	b := strings.TrimSpace(body)
	if b == "" {
		return ""
	}
	if reJSONStartAny.MatchString(b) {
		return truncate(sanitizeText(strings.ReplaceAll(b, "\n", ""), maxLen*2), maxLen)
	}
	if strings.Contains(b, "=") {
		if vals, err := url.ParseQuery(b); err == nil && len(vals) > 0 {
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, 4)
			for _, k := range keys {
				arr := vals[k]
				if len(arr) == 0 {
					continue
				}
				v := sanitizeText(arr[0], 28)
				if len(v) > 24 {
					v = v[:24]
				}
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				if len(parts) >= 3 {
					break
				}
			}
			if len(parts) > 0 {
				return truncate(strings.Join(parts, "&"), maxLen)
			}
		}
	}
	return truncate(sanitizeText(strings.ReplaceAll(b, "\n", ""), maxLen*2), maxLen)
}

func normalizeEndpointSegment(seg string) string {
	s := strings.TrimSpace(seg)
	if s == "" {
		return s
	}
	if len(s) > 64 {
		return "{long}"
	}
	if _, ok := pathPlaceholderName(s); ok {
		return "{param}"
	}
	low := strings.ToLower(s)
	if isPathPlaceholderValue(low) {
		return "{param}"
	}
	if strings.ContainsAny(s, "'\"<>$") {
		return "{param}"
	}
	if reUUIDLike.MatchString(s) {
		return "{uuid}"
	}
	if reAllDigits.MatchString(s) {
		return "{int}"
	}
	if reHexLong.MatchString(s) {
		return "{hex}"
	}
	if reBizIDLike.MatchString(s) {
		return "{id}"
	}
	if reDashIDToken.MatchString(s) && hasASCIIDigit(s) {
		return "{id}"
	}
	if len(s) >= 24 && strings.ContainsAny(s, "-_") {
		return "{id}"
	}
	return s
}

func hasASCIIDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func normalizeEndpointPath(path string) string {
	norm := strings.TrimSpace(normalizePath(path))
	if norm == "" || norm == "/" {
		return "/"
	}
	parts := splitPathTokens(norm)
	if len(parts) == 0 {
		return "/"
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, normalizeEndpointSegment(p))
	}
	return "/" + strings.Join(out, "/")
}

func endpointKey(method, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + normalizeEndpointPath(path)
}

func isWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func isAPILikePath(path string) bool {
	p := strings.ToLower(strings.TrimSpace(normalizePath(path)))
	if strings.HasPrefix(p, "/api/") {
		return true
	}
	if reAPIVersion.MatchString(p) {
		return true
	}
	return false
}

func getHeaderCI(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func isFormLikeContentType(ct string) bool {
	low := strings.ToLower(strings.TrimSpace(ct))
	return strings.Contains(low, "application/x-www-form-urlencoded") || strings.Contains(low, "multipart/form-data")
}

func upsertFormField(body, key, value string) (string, bool) {
	if strings.TrimSpace(key) == "" {
		return body, false
	}
	vals, err := url.ParseQuery(strings.TrimSpace(body))
	if err != nil {
		vals = url.Values{}
	}
	old := vals.Get(key)
	if strings.TrimSpace(old) == strings.TrimSpace(value) && old != "" {
		return body, false
	}
	vals.Set(key, value)
	enc := vals.Encode()
	if enc == "" {
		return body, false
	}
	return enc, true
}

func antiForgeryHarvestPaths(path string) []string {
	norm := strings.TrimSpace(normalizePath(path))
	if norm == "" {
		return nil
	}
	if !strings.HasPrefix(norm, "/") {
		norm = "/" + norm
	}
	parts := splitPathTokens(norm)
	cands := []string{norm}
	if len(parts) >= 2 {
		cands = append(cands, "/"+strings.Join(parts[:len(parts)-1], "/"))
	}
	if len(parts) >= 3 {
		cands = append(cands, "/"+strings.Join(parts[:len(parts)-2], "/"))
	}
	if len(parts) >= 1 {
		cands = append(cands, "/"+parts[0])
	}
	out := make([]string, 0, len(cands))
	seen := map[string]struct{}{}
	for _, c := range cands {
		cc := strings.TrimSpace(normalizePath(c))
		if cc == "" {
			continue
		}
		if !strings.HasPrefix(cc, "/") {
			cc = "/" + cc
		}
		if _, ok := seen[cc]; ok {
			continue
		}
		seen[cc] = struct{}{}
		out = append(out, cc)
	}
	return out
}

func isAntiForgeryFailure(body string) bool {
	low := strings.ToLower(strings.TrimSpace(body))
	if low == "" {
		return false
	}
	if strings.Contains(low, "antiforgery") {
		return true
	}
	if strings.Contains(low, "__requestverificationtoken") || strings.Contains(low, "requestverificationtoken") {
		return true
	}
	if strings.Contains(low, "csrf") {
		return true
	}
	return false
}

func extractAntiForgeryTokens(body string, fieldName string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	target := strings.ToLower(strings.TrimSpace(fieldName))
	if target == "" {
		target = "__requestverificationtoken"
	}
	out := make([]string, 0, 8)
	tags := reHTMLInputTag.FindAllString(body, -1)
	for _, tag := range tags {
		if !strings.Contains(strings.ToLower(tag), "requestverificationtoken") {
			continue
		}
		attrs := reHTMLAttrKV.FindAllStringSubmatch(tag, -1)
		if len(attrs) == 0 {
			continue
		}
		name := ""
		value := ""
		for _, m := range attrs {
			if len(m) < 4 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(m[1]))
			vraw := strings.TrimSpace(m[2])
			if vraw == "" {
				vraw = strings.TrimSpace(m[3])
			}
			v := html.UnescapeString(vraw)
			switch k {
			case "name":
				name = strings.ToLower(v)
			case "value":
				value = v
			}
		}
		if name == target || name == "requestverificationtoken" || name == "__requestverificationtoken" {
			value = normalizeValue(value)
			if isUsefulValue(value) {
				out = append(out, value)
			}
		}
	}
	return uniqStrings(out)
}

func canonicalContentType(headers map[string]string) string {
	return strings.ToLower(strings.TrimSpace(getHeaderCI(headers, "Content-Type")))
}

func setHeaderCI(headers map[string]string, name, value string) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
	headers[name] = value
}

func deleteHeaderCI(headers map[string]string, name string) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
}

func adaptJSONRequestToForm(headers map[string]string, body string) (map[string]string, string, bool) {
	ct := canonicalContentType(headers)
	if strings.Contains(ct, "application/x-www-form-urlencoded") || strings.Contains(ct, "multipart/form-data") {
		return headers, body, false
	}
	if ct != "" && !strings.Contains(ct, "application/json") {
		return headers, body, false
	}

	formBody, ok := jsonToFormBody(body)
	if !ok {
		return headers, body, false
	}
	setHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded")
	deleteHeaderCI(headers, "Content-Length")
	return headers, formBody, true
}

func isFormContentTypeMismatch(status int, body string) bool {
	if status < 500 {
		return false
	}
	low := strings.ToLower(body)
	if strings.Contains(low, "formvaluerequiredattribute") {
		return true
	}
	if strings.Contains(low, "formfeature.readform") {
		return true
	}
	if strings.Contains(low, "forms are available from requests with bodies like posts") {
		return true
	}
	if strings.Contains(low, "a form content-type of either application/x-www-form-urlencoded or multipart/form-data") {
		return true
	}
	return false
}

func jsonToFormBody(body string) (string, bool) {
	src := strings.TrimSpace(body)
	if src == "" {
		return "fuzz=false", true
	}
	var obj any
	if err := json.Unmarshal([]byte(src), &obj); err != nil {
		return "", false
	}
	vals := url.Values{}
	switch tv := obj.(type) {
	case map[string]any:
		if len(tv) == 0 {
			vals.Set("fuzz", "false")
		} else {
			addFormValue("", tv, vals, 0)
		}
	case []any:
		js, _ := json.Marshal(tv)
		vals.Set("value", string(js))
	default:
		vals.Set("value", toString(tv))
	}
	enc := vals.Encode()
	if enc == "" {
		enc = "fuzz=false"
	}
	return enc, true
}

func addFormValue(prefix string, v any, vals url.Values, depth int) {
	if depth > 2 {
		js, _ := json.Marshal(v)
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, string(js))
		return
	}
	switch tv := v.(type) {
	case map[string]any:
		for k, sub := range tv {
			nk := k
			if prefix != "" {
				nk = prefix + "." + k
			}
			addFormValue(nk, sub, vals, depth+1)
		}
	case []any:
		js, _ := json.Marshal(tv)
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, string(js))
	case nil:
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, "")
	default:
		key := strings.Trim(prefix, ".")
		if key == "" {
			key = "value"
		}
		vals.Add(key, toString(tv))
	}
}

func canonicalKey(v string) string {
	return reNonAlnum.ReplaceAllString(strings.ToLower(strings.TrimSpace(v)), "")
}

func normalizeValue(v string) string {
	return strings.TrimSpace(v)
}

func isUsefulValue(v string) bool {
	if v == "" {
		return false
	}
	s := strings.TrimSpace(v)
	if s == "" || s == "null" || s == "None" || s == "{}" || s == "[]" {
		return false
	}
	return len(s) <= 256
}

func isIDLikeKey(k string) bool {
	ck := canonicalKey(k)
	return ck == "id" || strings.HasSuffix(ck, "id")
}

func anySliceToStrings(arr []any) []string {
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		out = append(out, toString(v))
	}
	return out
}

func toString(v any) string {
	switch tv := v.(type) {
	case nil:
		return ""
	case string:
		return tv
	case bool:
		if tv {
			return "true"
		}
		return "false"
	case json.Number:
		return tv.String()
	case float64:
		if math.Trunc(tv) == tv {
			return strconv.FormatInt(int64(tv), 10)
		}
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case float32:
		f := float64(tv)
		if math.Trunc(f) == f {
			return strconv.FormatInt(int64(f), 10)
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	case int:
		return strconv.Itoa(tv)
	case int64:
		return strconv.FormatInt(tv, 10)
	case uint64:
		return strconv.FormatUint(tv, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toInt(v any) int {
	switch tv := v.(type) {
	case int:
		return tv
	case int64:
		return int(tv)
	case float64:
		return int(tv)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(tv))
		return i
	default:
		return 0
	}
}

func toUsefulScalar(v any) (string, bool) {
	s := toString(v)
	s = normalizeValue(s)
	if !isUsefulValue(s) {
		return "", false
	}
	return s, true
}

func uniqStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// dedupStrings removes duplicate strings; equivalent to uniqStrings.
// Kept for backward compatibility with callers in advanced_features.go.
func dedupStrings(in []string) []string { return uniqStrings(in) }

func filterUsefulStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		vv := normalizeValue(v)
		if !isUsefulValue(vv) {
			continue
		}
		if strings.HasPrefix(vv, "CUSTOM_PAYLOAD") {
			continue
		}
		out = append(out, vv)
	}
	return out
}

func splitNonAlnum(s string) []string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return parts
}

func singularize(t string) string {
	t = strings.TrimSpace(strings.ToLower(t))
	if len(t) <= 3 {
		return t
	}
	if strings.HasSuffix(t, "ies") && len(t) > 4 {
		return t[:len(t)-3] + "y"
	}
	if strings.HasSuffix(t, "ses") && len(t) > 4 {
		return t[:len(t)-2]
	}
	if strings.HasSuffix(t, "s") && !strings.HasSuffix(t, "ss") {
		return t[:len(t)-1]
	}
	return t
}

func setFromSlice(in []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		out[s] = struct{}{}
	}
	return out
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func appendUniqueInt(arr []int, v int) []int {
	for _, x := range arr {
		if x == v {
			return arr
		}
	}
	return append(arr, v)
}

func mapKeysAny(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func weightedPick(weights []float64) int {
	if len(weights) == 0 {
		return -1
	}
	total := 0.0
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}
	if total <= 0 {
		return rand.Intn(len(weights))
	}
	r := rand.Float64() * total
	acc := 0.0
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		acc += w
		if r <= acc {
			return i
		}
	}
	return len(weights) - 1
}

func sanitizeText(v string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 1024
	}
	// Fast path: skip ToValidUTF8 allocation when input is already valid (common case).
	if utf8.ValidString(v) {
		if len(v) > maxLen {
			return v[:maxLen]
		}
		return v
	}
	s := strings.ToValidUTF8(v, "?")
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 2 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func shuffleInts(a []int) {
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func filterIDLikePairs(in [][2]string) [][2]string {
	out := make([][2]string, 0, len(in))
	for _, kv := range in {
		if isIDLikeKey(kv[0]) {
			out = append(out, kv)
		}
	}
	return out
}
