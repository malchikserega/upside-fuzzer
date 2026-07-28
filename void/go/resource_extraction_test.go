package main

import (
	"strings"
	"testing"
)

func TestClassifyValueShape(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		wantKind string
		wantOK   bool
	}{
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "uuid", true},
		{"plain digits", "12345", "int", true},
		{"long hex", "5f4dcc3b5aa765d61d8327deb882cf99", "hex", true},
		{"dashed slug with digit", "user-42", "slug", true},
		{"plain lowercase slug", "demo-app", "slug", true},
		{"opaque bearer-shaped token", "aZ9k3mQ7xR2vL8nP1cT6wY4bH0dF5gJ", "opaque", true},
		{"free text sentence", "this is not an identifier at all", "", false},
		{"empty", "", "", false},
		{"single word", "hello", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, _, ok := classifyValueShape(tc.value)
			if ok != tc.wantOK {
				t.Fatalf("classifyValueShape(%q) ok = %v, want %v", tc.value, ok, tc.wantOK)
			}
			if ok && kind != tc.wantKind {
				t.Fatalf("classifyValueShape(%q) kind = %q, want %q", tc.value, kind, tc.wantKind)
			}
		})
	}
}

func TestResourceTypeFromKeyName(t *testing.T) {
	cases := map[string]string{
		"customerId":  "customer",
		"orderRef":    "order",
		"userKey":     "user",
		"productCode": "product",
		"id":          "",
		"Id":          "",
		"name":        "",
	}
	for key, want := range cases {
		if got := resourceTypeFromKeyName(key); got != want {
			t.Errorf("resourceTypeFromKeyName(%q) = %q, want %q", key, got, want)
		}
	}
}

// --- Regression tests: the OLD extractEntityIDs pipeline is proven to find
// nothing for each of these inputs first, then the NEW pipeline is proven to
// find the reference anyway. This is the concrete "chains now work when
// identifiers are returned as guid/slug/reference/..." proof the design task
// requires.

func newTestFuzzerForExtraction() *Fuzzer {
	f := &Fuzzer{
		meta:      map[int]TemplateMeta{},
		activeIDs: []int{},
	}
	return f
}

func TestRegression_GUIDIdentifier_OldPipelineBlindNewPipelineFinds(t *testing.T) {
	body := `{"reference": "550e8400-e29b-41d4-a716-446655440000", "status": "confirmed"}`
	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected the OLD id-name-centric pipeline to find nothing for a GUID under 'reference', got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /reservations/1")
	found := false
	for _, c := range candidates {
		if c.RawValue == "550e8400-e29b-41d4-a716-446655440000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the NEW extraction pipeline to find the GUID under 'reference', got %+v", candidates)
	}
}

func TestRegression_SlugIdentifier_OldPipelineBlindNewPipelineFinds(t *testing.T) {
	body := `{"slug": "my-cool-project", "visibility": "public"}`
	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected the OLD pipeline to find nothing for a slug field, got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /projects/1")
	found := false
	for _, c := range candidates {
		if c.RawValue == "my-cool-project" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the NEW pipeline to find the slug value, got %+v", candidates)
	}
}

func TestRegression_DomainSpecificFieldNameNoIDSubstring(t *testing.T) {
	// "resourceRef" contains no "id" substring anywhere -- isIDLikeKey would
	// reject it outright (canonicalKey ends in "ref", not "id").
	body := `{"resourceRef": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}`
	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected OLD pipeline to find nothing for resourceRef (no id/Id/data[].id shape), got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /things/1")
	found := false
	for _, c := range candidates {
		if c.RawValue == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" && c.ResourceType == "resource" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NEW pipeline to find resourceRef's hex-shaped value with resource type 'resource', got %+v", candidates)
	}
}

func TestRegression_LocationHeader_BothPipelinesFindIt(t *testing.T) {
	// The old pipeline already handled Location (last path segment) -- prove
	// the new pipeline does not regress this baseline case.
	headers := map[string]string{"Location": "/orders/789"}
	old := extractEntityIDs("", headers)
	if len(old) == 0 || old[0] != "789" {
		t.Fatalf("expected OLD pipeline to extract '789' from Location header, got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates("", headers, "POST /orders")
	found := false
	for _, c := range candidates {
		if c.RawValue == "789" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NEW pipeline to also extract '789' from Location header, got %+v", candidates)
	}
}

func TestRegression_HALSelfLink(t *testing.T) {
	body := `{
		"_links": {
			"self": {"href": "/orders/123"},
			"customer": {"href": "/customers/456"}
		},
		"total": 42.50
	}`
	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected OLD pipeline to find nothing in a pure-HAL body with no id/Id field, got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /orders/123")
	var gotOrder, gotCustomer bool
	for _, c := range candidates {
		if c.RawValue == "123" && c.Strategy == "hal" {
			gotOrder = true
		}
		if c.RawValue == "456" && c.Strategy == "hal" {
			gotCustomer = true
		}
	}
	if !gotOrder || !gotCustomer {
		t.Fatalf("expected NEW pipeline to extract both HAL relations (self=123, customer=456), got %+v", candidates)
	}
}

func TestRegression_HALLinkArray(t *testing.T) {
	body := `{"_links": {"items": [{"href": "/items/1"}, {"href": "/items/2"}]}}`
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /orders/1")
	seen := map[string]bool{}
	for _, c := range candidates {
		if c.Strategy == "hal" {
			seen[c.RawValue] = true
		}
	}
	if !seen["1"] || !seen["2"] {
		t.Fatalf("expected both array-form HAL links to be extracted, got %+v", candidates)
	}
}

func TestRegression_JSONAPIResourceAndRelationship(t *testing.T) {
	body := `{
		"data": {
			"type": "orders",
			"id": "123",
			"relationships": {
				"customer": {"data": {"type": "customers", "id": "456"}}
			}
		}
	}`
	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected OLD pipeline to find nothing for a JSON:API body (no bare id/Id top-level field), got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /orders/123")
	var gotOrder, gotCustomer bool
	for _, c := range candidates {
		if c.Strategy != "jsonapi" {
			continue
		}
		if c.RawValue == "123" && c.ResourceType == "order" {
			gotOrder = true
		}
		if c.RawValue == "456" && c.ResourceType == "customer" {
			gotCustomer = true
		}
	}
	if !gotOrder {
		t.Fatalf("expected NEW pipeline to extract the JSON:API primary resource (orders/123 -> order), got %+v", candidates)
	}
	if !gotCustomer {
		t.Fatalf("expected NEW pipeline to extract the JSON:API relationship (customer/456), got %+v", candidates)
	}
}

func TestRegression_JSONAPIRelationshipArray(t *testing.T) {
	body := `{"data": {"type": "orders", "id": "1", "relationships": {
		"items": {"data": [{"type": "items", "id": "10"}, {"type": "items", "id": "11"}]}
	}}}`
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /orders/1")
	seen := map[string]bool{}
	for _, c := range candidates {
		if c.Strategy == "jsonapi" && c.ResourceType == "item" {
			seen[c.RawValue] = true
		}
	}
	if !seen["10"] || !seen["11"] {
		t.Fatalf("expected both JSON:API relationship-array items to be extracted, got %+v", candidates)
	}
}

func TestRegression_NestedCompositeKeyField(t *testing.T) {
	// A nested object under a domain-specific key, containing its own id-shaped
	// field -- the old extractJSONRuntimeValues handles ONE level of this
	// (m["id"]/m["Id"] inside a nested map), but extractEntityIDs (what
	// sequence.go's chain-building actually calls) does not look inside nested
	// objects at all.
	body := `{"assignedTo": {"employeeId": "E-9981", "name": "Alex"}}`
	if old := extractEntityIDs(body, nil); len(old) != 0 {
		t.Fatalf("expected OLD extractEntityIDs to find nothing for a nested composite object, got %v", old)
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /tasks/1")
	found := false
	for _, c := range candidates {
		if c.RawValue == "E-9981" && c.ResourceType == "employee" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NEW pipeline to find the nested employeeId value, got %+v", candidates)
	}
}

func TestRouteTemplateMatching_MultiSegmentTypedExtraction(t *testing.T) {
	f := newTestFuzzerForExtraction()
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{
		Method: "GET",
		Norm:   "/organizations/{param}/projects/{param}",
	}
	candidates := f.matchRouteTemplateCandidates("/organizations/acme/projects/demo-app", "POST /organizations/acme/projects", "Location", confHeaderLocation)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 typed candidates (org + project) from a 2-placeholder route template, got %d: %+v", len(candidates), candidates)
	}
	var gotOrg, gotProject bool
	for _, c := range candidates {
		if c.RawValue == "acme" && c.ResourceType == "organization" {
			gotOrg = true
		}
		if c.RawValue == "demo-app" && c.ResourceType == "project" {
			gotProject = true
		}
	}
	if !gotOrg {
		t.Fatalf("expected candidate {orgId=acme, type=organization}, got %+v", candidates)
	}
	if !gotProject {
		t.Fatalf("expected candidate {projectSlug=demo-app, type=project}, got %+v", candidates)
	}
}

func TestRouteTemplateMatching_NoMatchWhenSegmentCountDiffers(t *testing.T) {
	f := newTestFuzzerForExtraction()
	f.activeIDs = []int{1}
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/users/{param}"}
	candidates := f.matchRouteTemplateCandidates("/organizations/acme/projects/demo-app", "op", "Location", confHeaderLocation)
	if len(candidates) != 0 {
		t.Fatalf("expected no match when segment counts differ, got %+v", candidates)
	}
}

func TestRouteTemplateMatching_StaticSegmentMismatchRejectsTemplate(t *testing.T) {
	f := newTestFuzzerForExtraction()
	f.activeIDs = []int{1, 2}
	// Same shape (1 static + 1 placeholder) but different static segment --
	// must not be confused with each other.
	f.meta[1] = TemplateMeta{Method: "GET", Norm: "/users/{param}"}
	f.meta[2] = TemplateMeta{Method: "GET", Norm: "/orders/{param}"}
	candidates := f.matchRouteTemplateCandidates("/users/42", "op", "Location", confHeaderLocation)
	for _, c := range candidates {
		if c.ResourceType == "order" {
			t.Fatalf("a /users/42 URI must never match the /orders/{param} template, got %+v", candidates)
		}
	}
	found := false
	for _, c := range candidates {
		if c.ResourceType == "user" && c.RawValue == "42" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /users/42 to match the /users/{param} template, got %+v", candidates)
	}
}

func TestHeaderExtraction_LinkHeaderWithRelation(t *testing.T) {
	headers := map[string]string{
		"Link": `</customers/456>; rel="customer", </orders/123>; rel="self"`,
	}
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates("", headers, "GET /orders/123")
	var gotCustomer bool
	for _, c := range candidates {
		if c.RawValue == "456" && c.LinkRelation == "customer" {
			gotCustomer = true
		}
	}
	if !gotCustomer {
		t.Fatalf("expected the Link header's 'customer' relation to be extracted, got %+v", candidates)
	}
}

func TestExtractionConfidence_StructuralWithNameHintOutranksBare(t *testing.T) {
	withHint := `{"customerId": "550e8400-e29b-41d4-a716-446655440000"}`
	bare := `{"randomField": "550e8400-e29b-41d4-a716-446655440000"}`
	f := newTestFuzzerForExtraction()

	var hinted, unhinted ExtractedCandidate
	for _, c := range f.extractResourceCandidates(withHint, nil, "op") {
		if c.Strategy == "structural" {
			hinted = c
		}
	}
	for _, c := range f.extractResourceCandidates(bare, nil, "op") {
		if c.Strategy == "structural" {
			unhinted = c
		}
	}
	if hinted.Confidence <= unhinted.Confidence {
		t.Fatalf("expected a name-corroborated UUID (customerId) to score higher confidence (%v) than a bare one (%v)",
			hinted.Confidence, unhinted.Confidence)
	}
}

func TestExtractionProvenance_EveryCandidateCarriesStrategyAndSource(t *testing.T) {
	body := `{"data": {"type": "orders", "id": "1"}}`
	f := newTestFuzzerForExtraction()
	candidates := f.extractResourceCandidates(body, nil, "GET /orders/1")
	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate")
	}
	for _, c := range candidates {
		if c.Strategy == "" {
			t.Errorf("candidate %+v has no Strategy -- provenance is required for every candidate", c)
		}
		if c.SourceOperation == "" {
			t.Errorf("candidate %+v has no SourceOperation", c)
		}
		if c.Confidence <= 0 || c.Confidence > 1 {
			t.Errorf("candidate %+v has an out-of-range confidence %v", c, c.Confidence)
		}
	}
}

func TestOpaqueTokenShape_RejectsPlainWords(t *testing.T) {
	for _, s := range []string{"password", "description", "hello world", "12"} {
		if isOpaqueTokenShaped(s) {
			t.Errorf("isOpaqueTokenShaped(%q) = true, want false", s)
		}
	}
}

func TestOpaqueTokenShape_AcceptsBearerLikeToken(t *testing.T) {
	if !isOpaqueTokenShaped("aZ9k3mQ7xR2vL8nP1cT6wY4bH0dF5gJ") {
		t.Error("expected a long mixed alnum token to be classified as opaque-shaped")
	}
}

func TestResourceTypeFromEndpointPath(t *testing.T) {
	cases := map[string]string{
		"/users/{param}": "user",
		"/organizations/{param}/projects/{param}": "project",
		"/health": "health",
	}
	for path, want := range cases {
		if got := resourceTypeFromEndpointPath(path); got != want {
			t.Errorf("resourceTypeFromEndpointPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// sanity: ensure the reJSONStartAny guard means non-JSON bodies never panic
// json.Unmarshal inside the pipeline.
func TestExtractResourceCandidates_NonJSONBodyDoesNotPanic(t *testing.T) {
	f := newTestFuzzerForExtraction()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("extractResourceCandidates panicked on non-JSON body: %v", r)
		}
	}()
	_ = f.extractResourceCandidates("not json at all <><>", nil, "op")
	_ = f.extractResourceCandidates(strings.Repeat("a", 5), map[string]string{"Location": ""}, "op")
}
