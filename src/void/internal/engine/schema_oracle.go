package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// schema_oracle.go — Response-schema conformance oracle (Top-20+ #23).
//
// grammarc/oas.py already parses and resolves each operation's declared 2xx response
// schemas; emit_templates.py flattens them into templates.export.json's
// response_schemas field (status -> {dotted field name: declared type}). Nothing
// validated live response bodies against that data until now -- a whole class of
// findings was invisible: fields present in real responses but never declared in the
// OpenAPI schema (the priority case -- a client can read/interact with something the
// spec never documented, which is worth flagging distinctly from a field that's
// merely typed differently than declared), plus lower-confidence declared-vs-observed
// type drift.
//
// Deliberately conservative: silent (no finding) on any endpoint whose grammar
// declares no response schema at all -- there's no ground truth to compare against,
// and inventing a finding from nothing would repeat this session's own SSRF
// false-positive lesson (see docs/ARCHITECTURE_REVIEW.md's Recorded Inconsistencies #11).

const (
	schemaCheckMaxKeys  = 200
	schemaCheckMaxDepth = 4
)

// sensitiveFieldNameMarkers are case-insensitive substrings of a field's own (last
// dotted-path segment) name that make an *undeclared* field worth flagging at
// likely_vuln rather than needs_review -- a field the spec never documented AND whose
// name suggests it's carrying something sensitive is the sharpest version of this
// finding class.
var sensitiveFieldNameMarkers = []string{
	"password", "secret", "token", "apikey", "api_key", "hash", "ssn",
	"creditcard", "cardnumber", "cvv", "privatekey", "connectionstring", "accesskey",
}

func isSensitiveFieldName(name string) bool {
	low := strings.ToLower(name)
	for _, m := range sensitiveFieldNameMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// checkSchemaConformance runs on every organic (non-probe) 2xx response. It compares
// the live JSON body against the endpoint's declared response schema for the observed
// status, if the grammar carries one, and flags fields present in the body but absent
// from the schema (undeclared -- the priority finding) and fields whose observed JSON
// type is incompatible with what the schema declares (type drift, lower confidence).
func (f *Fuzzer) checkSchemaConformance(res SendResult) {
	if !f.cfg.SchemaConformance || res.Item.OracleKind != "" {
		return
	}

	epKey := f.tmplEPKey[res.Item.TemplateID]
	schemas := f.responseSchemas[epKey]
	if len(schemas) == 0 {
		return
	}

	var declared map[string]string
	if m, ok := schemas[strconv.Itoa(res.Status)]; ok {
		declared = m
	} else if len(schemas) == 1 {
		// Common case: the spec only documents one 2xx status (usually 200) but the
		// server also returns an undocumented sibling (201/204/...) for the same
		// operation -- close enough to still be worth checking against.
		for _, m := range schemas {
			declared = m
		}
	}
	if len(declared) == 0 {
		return
	}

	var root any
	if err := json.Unmarshal([]byte(res.Body), &root); err != nil {
		return
	}
	if arr, ok := root.([]any); ok {
		// List endpoints: check the shape of the first element only.
		if len(arr) == 0 {
			return
		}
		root = arr[0]
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return
	}

	observed := map[string]any{}
	remaining := schemaCheckMaxKeys
	flattenJSONForSchemaCheck(obj, "", 0, &remaining, observed)

	var reasons []string
	class := ""
	severity := 0
	bump := func(reason, c string, s int) {
		reasons = append(reasons, reason)
		if s > severity {
			severity = s
		}
		// "Worst reason wins": likely_vuln always dominates needs_review for the
		// finding's overall classification, regardless of matched order.
		if c == "likely_vuln" {
			class = "likely_vuln"
		} else if class == "" {
			class = c
		}
	}

	for key, val := range observed {
		declaredType, ok := declared[key]
		if !ok {
			name := key
			if i := strings.LastIndexByte(key, '.'); i >= 0 {
				name = key[i+1:]
			}
			if isSensitiveFieldName(name) {
				bump("schema_undeclared_sensitive_field:"+key, "likely_vuln", 7)
			} else {
				bump("schema_undeclared_field:"+key, "needs_review", 3)
			}
			continue
		}
		if !jsonValueMatchesDeclaredType(val, declaredType) {
			bump("schema_type_mismatch:"+key, "needs_review", 2)
		}
	}

	if len(reasons) == 0 {
		return
	}
	f.recordSchemaFinding(res, reasons, class, severity)
}

// flattenJSONForSchemaCheck flattens a decoded JSON object into dotted-path entries,
// mirroring grammarc/oas.py::_collect_schema_fields's exact shape so keys compare 1:1
// against the schema-side flattening in emit_templates.py:
//   - An object gets an entry for itself (the map value) *and* is recursed into with
//     the same prefix for its children.
//   - An array shares its own dotted prefix with its item schema (no "[]"/index
//     component) -- only the first element is inspected, matching the schema side's
//     "one items schema for the whole array" semantics.
//   - Scalars (including null) are stored as leaves.
func flattenJSONForSchemaCheck(v any, prefix string, depth int, remaining *int, out map[string]any) {
	if *remaining <= 0 || depth > schemaCheckMaxDepth {
		return
	}
	switch tv := v.(type) {
	case map[string]any:
		if prefix != "" {
			out[prefix] = tv
			*remaining--
		}
		for k, val := range tv {
			if *remaining <= 0 {
				return
			}
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			flattenJSONForSchemaCheck(val, path, depth+1, remaining, out)
		}
	case []any:
		if len(tv) == 0 {
			if prefix != "" {
				out[prefix] = tv
				*remaining--
			}
			return
		}
		// Recurse into the first element under the SAME prefix as the array itself
		// (matches _collect_schema_fields: array items never get an index segment).
		flattenJSONForSchemaCheck(tv[0], prefix, depth+1, remaining, out)
	default:
		if prefix != "" {
			out[prefix] = tv
			*remaining--
		}
	}
}

// jsonValueMatchesDeclaredType reports whether v (a value decoded by encoding/json,
// so one of string/float64/bool/[]any/map[string]any/nil) is compatible with a
// declared OpenAPI type name. JSON null is always accepted regardless of declared
// type -- nullable-by-convention is extremely common in real APIs, and flagging it
// would produce a predictable, low-value false-positive flood. An unrecognized
// declared type name (a custom format string, etc.) is also never flagged -- this
// oracle only asserts what it can confidently classify.
func jsonValueMatchesDeclaredType(v any, declared string) bool {
	if v == nil {
		return true
	}
	switch declared {
	case "integer", "number":
		_, ok := v.(float64)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	default:
		return true
	}
}

// recordSchemaFinding logs a de-duplicated response-schema-conformance finding,
// mirroring recordInjectionFinding's shape (oracle.go) almost exactly.
func (f *Fuzzer) recordSchemaFinding(res SendResult, reasons []string, class string, severity int) {
	epKey := f.tmplEPKey[res.Item.TemplateID]
	sortedReasons := append([]string{}, reasons...)
	sort.Strings(sortedReasons)
	dedupKey := "schema|" + epKey + "|" + strings.Join(sortedReasons, ",")
	if _, ok := f.aclSeen[dedupKey]; ok {
		return
	}
	f.aclSeen[dedupKey] = struct{}{}
	f.accessFindings++

	sig := hashWithFNV(dedupKey)
	triage := map[string]any{
		"classification": class,
		"severity_score": severity,
		"impact_hint":    "schema_drift",
		"crash_layer":    "contract",
		"oracle":         "schema",
		"reasons":        dedupStrings(reasons),
	}
	f.addEvent(fmt.Sprintf("SCHEMA %s  %s %s  (%d)", class,
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
		"schema_drift":   true,
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
