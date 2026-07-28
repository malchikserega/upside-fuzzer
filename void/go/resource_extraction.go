package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// resource_extraction.go — generalized entity/reference extraction, replacing
// extractEntityIDs' fixed id/Id/data[].id/Location-last-segment name list
// (sequence.go) with a layered pipeline that finds candidates by response
// *structure* (HAL, JSON:API, headers, route templates) and by value *shape*
// (UUID/hex/slug/opaque), not primarily by field name. See
// docs/resource-state-graph-plan.md §8.2 for the full design.
//
// Every candidate carries provenance (Strategy, JSONPath/HeaderName/LinkRelation)
// and a Confidence score -- nothing here is "silently believed to be an id."

// Confidence tiers. Deliberately explicit constants (not inline magic numbers) so
// the scoring policy is visible and easy to tune/audit in one place.
const (
	confHALExplicit       = 0.90 // HAL _links relation with an href
	confJSONAPIExplicit   = 0.90 // JSON:API {type,id} or relationship
	confHeaderLocation    = 0.85 // Location/Content-Location header, route-template matched
	confHeaderLink        = 0.80 // Link header with an explicit rel
	confRouteTemplateOnly = 0.60 // URI matched a known route template, no explicit type
	confShapeWithNameHint = 0.70 // value shape (uuid/hex/slug) corroborated by key name
	confShapeUUIDBare     = 0.45 // uuid/hex shape, no name corroboration
	confShapeDigitsHinted = 0.55 // plain integer, but key name corroborates (e.g. "orderId")
	confShapeDigitsBare   = 0.20 // plain integer, no name corroboration -- very weak, lots of
	// false positives (counts, quantities, page sizes); kept low on purpose.
	confOpaqueToken = 0.35 // long alnum/mixed-case token, no other corroboration
)

// ExtractedCandidate is one candidate resource reference found in a response,
// with full provenance for debugging/auditing (Phase 5 of the design task).
type ExtractedCandidate struct {
	RawValue        string
	NormalizedValue string
	ValueType       string // "scalar" | "uri" | "composite" | "opaque" -- becomes IdentityKind
	ResourceType    string // best-effort; "" if genuinely unknown (caller may fall back)
	SourceOperation string // "METHOD NORM_PATH" of the response this came from
	JSONPath        string
	HeaderName      string
	LinkRelation    string
	Strategy        string // "structural" | "header" | "hal" | "jsonapi" | "route_template"
	Confidence      float64
}

func (c ExtractedCandidate) toIdentity() ResourceIdentity {
	rt := c.ResourceType
	if rt == "" {
		rt = "GenericResource"
	}
	return ResourceIdentity{
		ResourceType:    rt,
		IdentityKind:    c.ValueType,
		NormalizedValue: normalizeResourceValue(rt, c.ValueType, c.RawValue),
		RawValue:        c.RawValue,
		SourcePath:      firstNonEmpty(c.JSONPath, c.HeaderName, c.LinkRelation),
		Confidence:      c.Confidence,
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// classifyValueShape reports whether s looks like an identifier by *shape*
// alone, its identity kind, and a base confidence -- independent of whatever
// field name it was found under. This is the mechanism that makes `reference`,
// `resourceRef`, or any domain-specific field name extractable at all: it reuses
// the shape-detection regexes this codebase already has for BOLA/minimize
// purposes (utils.go), applied here to a new purpose.
// identityKindOf maps classifyValueShape's fine-grained shape name (used only
// to differentiate confidence -- uuid/hex/int/slug are scored differently)
// down to the fixed ResourceIdentity.IdentityKind taxonomy ("scalar" | "uri" |
// "composite" | "opaque"). This is the mapping that keeps graph identity keys
// consistent: a value shaped as a UUID and one shaped as a plain int must both
// resolve to IdentityKind "scalar" so recordInstance's graphKey (ResourceType +
// NormalizedValue, which embeds IdentityKind) isn't fragmented by an
// implementation-detail shape label that was never meant to be part of a
// resource's identity.
func identityKindOf(shapeKind string) string {
	if shapeKind == "opaque" {
		return "opaque"
	}
	return "scalar"
}

func classifyValueShape(s string) (kind string, base float64, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return "", 0, false
	}
	switch {
	case reUUIDLike.MatchString(s):
		return "uuid", confShapeUUIDBare, true
	case reHexLong.MatchString(s):
		return "hex", confShapeUUIDBare, true
	case reAllDigits.MatchString(s):
		return "int", confShapeDigitsBare, true
	case reBizIDLike.MatchString(s), reDashIDToken.MatchString(s) && hasASCIIDigit(s):
		return "slug", confShapeWithNameHint, true
	case isSlugShaped(s):
		return "slug", confShapeWithNameHint - 0.1, true
	case isOpaqueTokenShaped(s):
		return "opaque", confOpaqueToken, true
	default:
		return "", 0, false
	}
}

var reSlugShaped = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+){1,6}$`)

// isSlugShaped catches plain lowercase-dash-separated slugs ("demo-app",
// "my-project") that reDashIDToken/reBizIDLike miss because they require a
// digit or a short first segment -- a real gap the old id-name-only pipeline
// had no way to fill regardless, since slugs usually live under keys like
// "slug"/"code"/"name", not "id".
func isSlugShaped(s string) bool {
	return reSlugShaped.MatchString(s) && len(s) <= 64
}

// isOpaqueTokenShaped is a conservative last-resort heuristic for bearer-token-
// or handle-shaped strings: long, alphanumeric, mixed case or containing both
// letters and digits, no whitespace, not a common English word shape. Kept
// deliberately narrow (long + mixed alnum) to avoid flagging ordinary free-text
// values as resource references.
func isOpaqueTokenShaped(s string) bool {
	if len(s) < 20 || len(s) > 128 {
		return false
	}
	hasDigit, hasAlpha, hasSpace := false, false, false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasAlpha = true
		case r == ' ' || r == '\t' || r == '\n':
			hasSpace = true
		case r != '-' && r != '_' && r != '.':
			return false // punctuation/unicode outside a plausible token alphabet
		}
	}
	return hasDigit && hasAlpha && !hasSpace
}

// resourceTypeFromKeyName derives a best-effort resource type from a JSON field
// name -- "customerId" -> "customer", "orderRef" -> "order", "userKey" ->
// "user", a bare "id"/"Id" -> "" (caller must supply a fallback, e.g. the
// enclosing object's own field name or the endpoint's resource family).
// Deliberately a *fallback* signal, not the primary mechanism -- HAL/JSON:API's
// own declared type, and route-template matches, both take priority over this
// wherever they're available (see extractResourceCandidates).
func resourceTypeFromKeyName(key string) string {
	ck := canonicalKey(key)
	for _, suffix := range []string{"id", "ref", "reference", "key", "code", "slug"} {
		if ck == suffix {
			return ""
		}
		if strings.HasSuffix(ck, suffix) && len(ck) > len(suffix) {
			base := ck[:len(ck)-len(suffix)]
			if base != "" {
				return singularize(base)
			}
		}
	}
	return ""
}

// extractStructuralCandidates walks a parsed JSON body recursively, producing a
// candidate for every scalar value that *looks* like an identifier by shape
// (classifyValueShape), regardless of its key name -- corroborated (higher
// confidence) when the key name also hints at a reference. depth is bounded the
// same way extractJSONRuntimeValues already bounds it (sequence.go), and arrays
// are capped at 100 elements for the same reason.
func extractStructuralCandidates(node any, jsonPath, sourceOp string, depth int, out *[]ExtractedCandidate) {
	if depth > 6 {
		return
	}
	switch tv := node.(type) {
	case map[string]any:
		for k, v := range tv {
			childPath := jsonPath + "." + k
			if s, ok := v.(string); ok {
				kind, base, shaped := classifyValueShape(s)
				if shaped {
					rt := resourceTypeFromKeyName(k)
					conf := base
					if rt != "" && (kind == "uuid" || kind == "hex") {
						conf = confShapeWithNameHint
					} else if rt != "" && kind == "int" {
						conf = confShapeDigitsHinted
					}
					if rt == "" {
						// A bare "id"/"Id" (or any other field whose name gives
						// no type hint) almost always refers to the endpoint's
						// OWN resource family, not to a type named after the
						// field itself -- e.g. POST /orders returning
						// {"id": "9001"} means an order, not a resource of
						// type "id".
						rt = resourceTypeFromSourceOp(sourceOp)
					}
					*out = append(*out, ExtractedCandidate{
						RawValue: s, NormalizedValue: s, ValueType: identityKindOf(kind),
						ResourceType: rt, SourceOperation: sourceOp,
						JSONPath: childPath, Strategy: "structural", Confidence: conf,
					})
				}
			} else if n, ok := toUsefulScalar(v); ok {
				if kind, base, shaped := classifyValueShape(n); shaped {
					rt := resourceTypeFromKeyName(k)
					conf := base
					if rt != "" {
						conf = confShapeDigitsHinted
					}
					if rt == "" {
						rt = resourceTypeFromSourceOp(sourceOp)
					}
					*out = append(*out, ExtractedCandidate{
						RawValue: n, NormalizedValue: n, ValueType: identityKindOf(kind),
						ResourceType: rt, SourceOperation: sourceOp,
						JSONPath: childPath, Strategy: "structural", Confidence: conf,
					})
				}
			}
			extractStructuralCandidates(v, childPath, sourceOp, depth+1, out)
		}
	case []any:
		limit := minInt(100, len(tv))
		for i := 0; i < limit; i++ {
			extractStructuralCandidates(tv[i], jsonPath+"[]", sourceOp, depth+1, out)
		}
	}
}

// reLinkHeaderEntry parses one RFC 8288 Link header entry: <uri>; rel="name".
var reLinkHeaderEntry = regexp.MustCompile(`<([^>]*)>\s*;\s*rel="?([\w-]+)"?`)

// extractHeaderCandidates handles Location, Content-Location, and Link headers
// structurally (real URI parsing, not naive string splitting on "/").
// route-template matching (matchRouteTemplateCandidates) is applied by the
// caller (extractResourceCandidates) once a URI is found here, since that needs
// the Fuzzer receiver's known templates.
func extractHeaderCandidates(headers map[string]string) (uris []struct {
	URI, HeaderName, Relation string
	Confidence                float64
}) {
	get := func(name string) string {
		if v, ok := headers[name]; ok {
			return v
		}
		return headers[strings.ToLower(name)]
	}
	if loc := strings.TrimSpace(get("Location")); loc != "" {
		uris = append(uris, struct {
			URI, HeaderName, Relation string
			Confidence                float64
		}{loc, "Location", "self", confHeaderLocation})
	}
	if loc := strings.TrimSpace(get("Content-Location")); loc != "" {
		uris = append(uris, struct {
			URI, HeaderName, Relation string
			Confidence                float64
		}{loc, "Content-Location", "self", confHeaderLocation})
	}
	if link := strings.TrimSpace(get("Link")); link != "" {
		for _, m := range reLinkHeaderEntry.FindAllStringSubmatch(link, -1) {
			if len(m) == 3 && m[1] != "" {
				uris = append(uris, struct {
					URI, HeaderName, Relation string
					Confidence                float64
				}{m[1], "Link", m[2], confHeaderLink})
			}
		}
	}
	return uris
}

// extractHALCandidates finds HAL-style `_links` structures (both single-object
// `{"href": "..."}` and array-of-link forms) at any depth up to a shallow
// bound (HAL links are conventionally top-level or one level down), returning
// one candidate per relation with the relation name as both the resource-type
// hint and the provenance.
func extractHALCandidates(node any, sourceOp string, depth int) []struct {
	URI, Relation string
} {
	if depth > 3 {
		return nil
	}
	var out []struct{ URI, Relation string }
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	if links, ok := m["_links"].(map[string]any); ok {
		for rel, v := range links {
			switch lv := v.(type) {
			case map[string]any:
				if href, ok := lv["href"].(string); ok && href != "" {
					out = append(out, struct{ URI, Relation string }{href, rel})
				}
			case []any:
				for _, e := range lv {
					if em, ok := e.(map[string]any); ok {
						if href, ok := em["href"].(string); ok && href != "" {
							out = append(out, struct{ URI, Relation string }{href, rel})
						}
					}
				}
			}
		}
	}
	for _, v := range m {
		out = append(out, extractHALCandidates(v, sourceOp, depth+1)...)
	}
	return out
}

// extractJSONAPICandidates finds JSON:API {"data": {"type":"orders","id":"123"}}
// and nested {"relationships": {"<rel>": {"data": {"type":...,"id":...}}}}
// structures, at either the top level or nested under a field. Also handles
// "data" being an array of resource objects.
func extractJSONAPICandidates(node any, sourceOp string, depth int, out *[]ExtractedCandidate) {
	if depth > 6 {
		return
	}
	m, ok := node.(map[string]any)
	if !ok {
		if arr, ok := node.([]any); ok {
			limit := minInt(50, len(arr))
			for i := 0; i < limit; i++ {
				extractJSONAPICandidates(arr[i], sourceOp, depth+1, out)
			}
		}
		return
	}
	if data, ok := m["data"]; ok {
		emitJSONAPIResourceObject(data, sourceOp, out)
	}
	for k, v := range m {
		if k == "data" {
			continue
		}
		extractJSONAPICandidates(v, sourceOp, depth+1, out)
	}
}

func emitJSONAPIResourceObject(data any, sourceOp string, out *[]ExtractedCandidate) {
	switch dv := data.(type) {
	case map[string]any:
		typ, _ := dv["type"].(string)
		id, hasID := toUsefulScalar(dv["id"])
		if typ != "" && hasID {
			*out = append(*out, ExtractedCandidate{
				RawValue: id, NormalizedValue: id, ValueType: "scalar",
				ResourceType: singularize(canonicalKey(typ)), SourceOperation: sourceOp,
				JSONPath: "data.id", Strategy: "jsonapi", Confidence: confJSONAPIExplicit,
			})
		}
		if rels, ok := dv["relationships"].(map[string]any); ok {
			for rel, rv := range rels {
				rm, ok := rv.(map[string]any)
				if !ok {
					continue
				}
				rd, ok := rm["data"]
				if !ok {
					continue
				}
				switch rdv := rd.(type) {
				case map[string]any:
					rtyp, _ := rdv["type"].(string)
					rid, hasRID := toUsefulScalar(rdv["id"])
					if hasRID {
						resourceType := rel
						if rtyp != "" {
							resourceType = rtyp
						}
						*out = append(*out, ExtractedCandidate{
							RawValue: rid, NormalizedValue: rid, ValueType: "scalar",
							ResourceType: singularize(canonicalKey(resourceType)), SourceOperation: sourceOp,
							JSONPath: "data.relationships." + rel, LinkRelation: rel,
							Strategy: "jsonapi", Confidence: confJSONAPIExplicit,
						})
					}
				case []any:
					for _, e := range rdv {
						em, ok := e.(map[string]any)
						if !ok {
							continue
						}
						rtyp, _ := em["type"].(string)
						rid, hasRID := toUsefulScalar(em["id"])
						if !hasRID {
							continue
						}
						resourceType := rel
						if rtyp != "" {
							resourceType = rtyp
						}
						*out = append(*out, ExtractedCandidate{
							RawValue: rid, NormalizedValue: rid, ValueType: "scalar",
							ResourceType: singularize(canonicalKey(resourceType)), SourceOperation: sourceOp,
							JSONPath: "data.relationships." + rel + "[]", LinkRelation: rel,
							Strategy: "jsonapi", Confidence: confJSONAPIExplicit,
						})
					}
				}
			}
		}
	case []any:
		limit := minInt(50, len(dv))
		for i := 0; i < limit; i++ {
			emitJSONAPIResourceObject(dv[i], sourceOp, out)
		}
	}
}

// matchRouteTemplateCandidates matches rawURI's path against every known
// template's normalized route (f.meta[tid].Norm, already shape-normalized by
// normalizeEndpointPath: numeric/UUID/hex/id-like segments already collapse to
// {int}/{uuid}/{hex}/{id}/{param}) and, for each placeholder position, emits a
// typed candidate whose resource type comes from the *preceding static
// segment* -- not just the URI's final segment. This is what lets
// "/organizations/{orgId}/projects/{projectSlug}" yield two distinct typed
// candidates (organization, project) instead of one.
func (f *Fuzzer) matchRouteTemplateCandidates(rawURI, sourceOp, headerOrRel string, baseConfidence float64) []ExtractedCandidate {
	u, err := url.Parse(strings.TrimSpace(rawURI))
	rawPath := rawURI
	if err == nil && u.Path != "" {
		rawPath = u.Path
	}
	rawSegs := splitPathTokensRaw(rawPath)
	if len(rawSegs) == 0 {
		return nil
	}

	var out []ExtractedCandidate
	seen := map[string]struct{}{}
	for _, tid := range f.activeIDs {
		norm := f.meta[tid].Norm
		normSegs := splitPathTokensRaw(norm)
		if len(normSegs) != len(rawSegs) {
			continue
		}
		for i, ns := range normSegs {
			if !isRouteTemplatePlaceholder(ns) {
				if !strings.EqualFold(ns, rawSegs[i]) {
					goto nextTemplate
				}
				continue
			}
			resourceType := ""
			if i > 0 {
				resourceType = singularize(strings.ToLower(normSegs[i-1]))
			}
			// {param}/{id}/{long} mean "normalizeEndpointSegment didn't classify
			// this segment into a more specific shape bucket" -- NOT "this looks
			// like an opaque bearer token." It's still an ordinary single-value
			// identifier (a slug, a username, anything not uuid/int/hex-shaped),
			// so it maps to IdentityKind "scalar" like the classified shapes do,
			// not to the specific low-confidence "opaque" heuristic category.
			kind := "scalar"
			switch ns {
			case "{uuid}":
				kind = "uuid"
			case "{hex}":
				kind = "hex"
			}
			dedupKey := resourceType + "|" + rawSegs[i]
			if _, dup := seen[dedupKey]; dup {
				continue
			}
			seen[dedupKey] = struct{}{}
			out = append(out, ExtractedCandidate{
				RawValue: rawSegs[i], NormalizedValue: rawSegs[i], ValueType: identityKindOf(kind),
				ResourceType: resourceType, SourceOperation: sourceOp,
				JSONPath: headerOrRel, Strategy: "route_template", Confidence: baseConfidence,
			})
		}
	nextTemplate:
	}
	return out
}

func isRouteTemplatePlaceholder(seg string) bool {
	switch seg {
	case "{param}", "{uuid}", "{int}", "{hex}", "{id}", "{long}":
		return true
	}
	return false
}

// splitPathTokensRaw splits a URI path into non-empty segments without the
// noise-filtering extractPathTokens applies -- route-template matching needs
// positional correspondence with the *unfiltered* segment list.
func splitPathTokensRaw(path string) []string {
	var out []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// extractResourceCandidates is the pipeline entry point: runs HAL, JSON:API,
// header (+ route-template matching on any URI found), and structural
// extraction over one response, returning every candidate found across all
// four strategies. sourceOp is "METHOD NORM_PATH" of the response's own
// request, for provenance.
func (f *Fuzzer) extractResourceCandidates(body string, headers map[string]string, sourceOp string) []ExtractedCandidate {
	var out []ExtractedCandidate

	for _, h := range extractHeaderCandidates(headers) {
		matched := f.matchRouteTemplateCandidates(h.URI, sourceOp, h.HeaderName, h.Confidence)
		if len(matched) > 0 {
			out = append(out, matched...)
			continue
		}
		// No known template matched this URI -- fall back to "last segment is the
		// identity, relation name is the resource-type hint" the same way the old
		// extractEntityIDs did for Location, so we never regress below its coverage.
		segs := splitPathTokensRaw(h.URI)
		if len(segs) == 0 {
			continue
		}
		last := segs[len(segs)-1]
		if !isUsefulValue(last) {
			continue
		}
		rt := h.Relation
		if rt == "self" || rt == "" {
			if len(segs) >= 2 {
				rt = singularize(strings.ToLower(segs[len(segs)-2]))
			}
		}
		kind, _, shaped := classifyValueShape(last)
		if !shaped {
			kind = "scalar"
		}
		out = append(out, ExtractedCandidate{
			RawValue: last, NormalizedValue: last, ValueType: identityKindOf(kind),
			ResourceType: rt, SourceOperation: sourceOp,
			JSONPath: h.HeaderName, LinkRelation: h.Relation,
			Strategy: "header", Confidence: h.Confidence * 0.8, // unmatched-template discount
		})
	}

	if !reJSONStartAny.MatchString(body) {
		return out
	}
	var js any
	if err := json.Unmarshal([]byte(body), &js); err != nil {
		return out
	}

	for _, hl := range extractHALCandidates(js, sourceOp, 0) {
		matched := f.matchRouteTemplateCandidates(hl.URI, sourceOp, hl.Relation, confHALExplicit)
		if len(matched) > 0 {
			out = append(out, matched...)
			continue
		}
		segs := splitPathTokensRaw(hl.URI)
		if len(segs) == 0 {
			continue
		}
		last := segs[len(segs)-1]
		if !isUsefulValue(last) {
			continue
		}
		rt := hl.Relation
		if rt == "self" && len(segs) >= 2 {
			rt = singularize(strings.ToLower(segs[len(segs)-2]))
		}
		kind, _, shaped := classifyValueShape(last)
		if !shaped {
			kind = "scalar"
		}
		out = append(out, ExtractedCandidate{
			RawValue: last, NormalizedValue: last, ValueType: identityKindOf(kind),
			ResourceType: singularize(canonicalKey(rt)), SourceOperation: sourceOp,
			JSONPath: "_links." + hl.Relation + ".href", LinkRelation: hl.Relation,
			Strategy: "hal", Confidence: confHALExplicit * 0.85,
		})
	}

	extractJSONAPICandidates(js, sourceOp, 0, &out)
	extractStructuralCandidates(js, "$", sourceOp, 0, &out)

	return out
}

// resourceTypeFromSourceOp derives a fallback resource type from a "METHOD
// /path" SourceOperation string (extractResourceCandidates' own provenance
// format), for candidates whose field name gives no type hint at all (a bare
// "id"/"Id"). See resourceTypeFromEndpointPath for the underlying technique.
func resourceTypeFromSourceOp(sourceOp string) string {
	parts := strings.SplitN(strings.TrimSpace(sourceOp), " ", 2)
	if len(parts) != 2 {
		return ""
	}
	return resourceTypeFromEndpointPath(parts[1])
}

// resourceTypeFromEndpointPath derives a resource-type name from an endpoint's
// own normalized path family -- the same core technique
// inferResourceIDKeyFromPath already uses (singularize the last static
// segment), extracted here as a reusable, general helper (not limited to
// "the id key for a POST/PUT producer") so it can supply a fallback resource
// type for candidates that have no better signal (no HAL/JSON:API type, no
// name hint). Mirrors resourcePathNoise filtering.
func resourceTypeFromEndpointPath(path string) string {
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
	return singularize(tokens[len(tokens)-1])
}
