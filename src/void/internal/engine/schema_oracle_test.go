package engine

import (
	"path/filepath"
	"testing"
	"void/internal/config"
)

// TestFlattenJSONForSchemaCheckMirrorsGrammarcShape verifies the Go-side JSON
// flattener produces the same dotted-path key shape as grammarc/oas.py's
// _collect_schema_fields (see grammarc/test_response_schemas.py's
// test_nested_object_fields_use_dotted_paths): an intermediate object gets an entry
// for itself *and* is recursed into, and an array shares its own prefix with its
// item schema (no index component).
func TestFlattenJSONForSchemaCheckMirrorsGrammarcShape(t *testing.T) {
	body := map[string]any{
		"id": float64(1),
		"shipping": map[string]any{
			"city": "Berlin",
		},
		"items": []any{
			map[string]any{"sku": "ABC"},
		},
	}
	out := map[string]any{}
	remaining := schemaCheckMaxKeys
	flattenJSONForSchemaCheck(body, "", 0, &remaining, out)

	for _, key := range []string{"id", "shipping", "shipping.city", "items", "items.sku"} {
		if _, ok := out[key]; !ok {
			t.Errorf("expected flattened key %q, got keys: %v", key, keysOf(out))
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestFlattenJSONForSchemaCheckRespectsCap verifies the key-count cap actually
// bounds work on a wide object, so a huge response body can't blow up cost.
func TestFlattenJSONForSchemaCheckRespectsCap(t *testing.T) {
	body := map[string]any{}
	for i := 0; i < 50; i++ {
		body["field"+itoa(i)] = "v"
	}
	out := map[string]any{}
	remaining := 10
	flattenJSONForSchemaCheck(body, "", 0, &remaining, out)
	if len(out) > 10 {
		t.Errorf("expected flattening to stop at the cap (10), got %d keys", len(out))
	}
}

func TestJSONValueMatchesDeclaredType(t *testing.T) {
	cases := []struct {
		v        any
		declared string
		want     bool
	}{
		{nil, "string", true}, // null always accepted regardless of declared type
		{"x", "string", true},
		{float64(5), "string", false},
		{float64(5), "integer", true},
		{float64(5), "number", true},
		{true, "boolean", true},
		{"x", "boolean", false},
		{[]any{}, "array", true},
		{map[string]any{}, "object", true},
		{"x", "date-time", true}, // unrecognized declared type -> never flagged
	}
	for _, c := range cases {
		if got := jsonValueMatchesDeclaredType(c.v, c.declared); got != c.want {
			t.Errorf("jsonValueMatchesDeclaredType(%#v, %q) = %v, want %v", c.v, c.declared, got, c.want)
		}
	}
}

func TestIsSensitiveFieldName(t *testing.T) {
	for _, name := range []string{"passwordHash", "internalApiKey", "SSN", "accessKey"} {
		if !isSensitiveFieldName(name) {
			t.Errorf("expected %q to be classified sensitive", name)
		}
	}
	for _, name := range []string{"createdAt", "displayName", "quantity"} {
		if isSensitiveFieldName(name) {
			t.Errorf("expected %q to NOT be classified sensitive", name)
		}
	}
}

func newSchemaTestFuzzer(t *testing.T, schemaConformance bool) *Fuzzer {
	t.Helper()
	w, err := NewJSONLWriter(filepath.Join(t.TempDir(), "unique.jsonl"))
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	return &Fuzzer{
		cfg:             config.Config{SchemaConformance: schemaConformance},
		tmplEPKey:       map[int]string{},
		responseSchemas: map[string]map[string]map[string]string{},
		aclSeen:         map[string]struct{}{},
		uniqueWriter:    w,
	}
}

// TestCheckSchemaConformanceNoFindingWhenBodyMatchesSchema verifies a response whose
// body exactly matches the declared schema produces no finding at all.
func TestCheckSchemaConformanceNoFindingWhenBodyMatchesSchema(t *testing.T) {
	f := newSchemaTestFuzzer(t, true)
	f.tmplEPKey[1] = "GET|/items/{id}"
	f.responseSchemas["GET|/items/{id}"] = map[string]map[string]string{
		"200": {"id": "integer", "name": "string"},
	}
	res := SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "GET", Path: "/items/1"},
		Status: 200,
		Body:   `{"id":1,"name":"widget"}`,
	}
	f.checkSchemaConformance(res)
	if len(f.findings) != 0 {
		t.Errorf("expected no findings for a schema-conforming body, got %d", len(f.findings))
	}
}

// TestCheckSchemaConformanceGates verifies the oracle stays silent when disabled,
// on probe replays, and on endpoints with no declared response schema.
func TestCheckSchemaConformanceGates(t *testing.T) {
	body := `{"id":1,"extraUndeclaredField":"x"}`

	t.Run("disabled by config", func(t *testing.T) {
		f := newSchemaTestFuzzer(t, false)
		f.tmplEPKey[1] = "GET|/items/{id}"
		f.responseSchemas["GET|/items/{id}"] = map[string]map[string]string{"200": {"id": "integer"}}
		f.checkSchemaConformance(SendResult{Item: WorkItem{TemplateID: 1, Method: "GET", Path: "/items/1"}, Status: 200, Body: body})
		if len(f.findings) != 0 {
			t.Errorf("expected no findings when SchemaConformance is disabled, got %d", len(f.findings))
		}
	})

	t.Run("probe replay skipped", func(t *testing.T) {
		f := newSchemaTestFuzzer(t, true)
		f.tmplEPKey[1] = "GET|/items/{id}"
		f.responseSchemas["GET|/items/{id}"] = map[string]map[string]string{"200": {"id": "integer"}}
		f.checkSchemaConformance(SendResult{Item: WorkItem{TemplateID: 1, Method: "GET", Path: "/items/1", OracleKind: oracleKindBOLA}, Status: 200, Body: body})
		if len(f.findings) != 0 {
			t.Errorf("expected no findings on an oracle-probe replay, got %d", len(f.findings))
		}
	})

	t.Run("no declared schema for endpoint", func(t *testing.T) {
		f := newSchemaTestFuzzer(t, true)
		f.tmplEPKey[1] = "GET|/items/{id}"
		f.checkSchemaConformance(SendResult{Item: WorkItem{TemplateID: 1, Method: "GET", Path: "/items/1"}, Status: 200, Body: body})
		if len(f.findings) != 0 {
			t.Errorf("expected no findings when the grammar declares no response schema, got %d", len(f.findings))
		}
	})
}

// TestCheckSchemaConformanceClassifiesUndeclaredAndTypeDrift verifies the three
// distinct reason tags (undeclared-sensitive, undeclared-plain, type-mismatch) are
// each produced for the right field, with the overall finding's classification
// following "worst reason wins" (a sensitive undeclared field present anywhere in
// the response pulls the whole finding up to likely_vuln).
func TestCheckSchemaConformanceClassifiesUndeclaredAndTypeDrift(t *testing.T) {
	f := newSchemaTestFuzzer(t, true)
	f.tmplEPKey[1] = "GET|/users/{id}"
	f.responseSchemas["GET|/users/{id}"] = map[string]map[string]string{
		"200": {"id": "integer", "age": "integer"},
	}
	res := SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "GET", Path: "/users/1"},
		Status: 200,
		// id: declared, matches. age: declared "integer" but observed a string (type
		// drift). debugFlag: undeclared, plain name. internalPasswordHash: undeclared,
		// sensitive name.
		Body: `{"id":1,"age":"thirty","debugFlag":true,"internalPasswordHash":"deadbeef"}`,
	}
	f.checkSchemaConformance(res)
	if len(f.findings) != 1 {
		t.Fatalf("expected exactly 1 aggregated finding, got %d", len(f.findings))
	}
	fd := f.findings[0]
	reasons, _ := fd.Triage["reasons"].([]string)
	joined := ""
	for _, r := range reasons {
		joined += r + " "
	}
	for _, want := range []string{"schema_type_mismatch:age", "schema_undeclared_field:debugFlag", "schema_undeclared_sensitive_field:internalPasswordHash"} {
		found := false
		for _, r := range reasons {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected reasons to include %q, got %v", want, reasons)
		}
	}
	if fd.Triage["classification"] != "likely_vuln" {
		t.Errorf("expected overall classification likely_vuln (sensitive undeclared field present), got %v", fd.Triage["classification"])
	}
	if sev, _ := fd.Triage["severity_score"].(int); sev != 7 {
		t.Errorf("expected overall severity 7 (max across matched reasons), got %v", fd.Triage["severity_score"])
	}
}

// TestCheckSchemaConformanceDedupsRepeatedHits verifies the same finding (same
// endpoint + same matched fields) is only recorded once across repeated identical
// responses, mirroring recordAccessControlFinding/recordInjectionFinding's existing
// dedup convention.
func TestCheckSchemaConformanceDedupsRepeatedHits(t *testing.T) {
	f := newSchemaTestFuzzer(t, true)
	f.tmplEPKey[1] = "GET|/items/{id}"
	f.responseSchemas["GET|/items/{id}"] = map[string]map[string]string{"200": {"id": "integer"}}
	res := SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "GET", Path: "/items/1"},
		Status: 200,
		Body:   `{"id":1,"undeclaredField":"x"}`,
	}
	f.checkSchemaConformance(res)
	f.checkSchemaConformance(res)
	f.checkSchemaConformance(res)
	if len(f.findings) != 1 {
		t.Errorf("expected repeated identical responses to dedup into 1 finding, got %d", len(f.findings))
	}
}

// TestCheckSchemaConformanceFallsBackToSoleDeclaredStatus verifies that when the
// observed status has no exact schema match but exactly one 2xx schema is declared
// overall, that schema is still used (the common "spec only documents 200" case).
func TestCheckSchemaConformanceFallsBackToSoleDeclaredStatus(t *testing.T) {
	f := newSchemaTestFuzzer(t, true)
	f.tmplEPKey[1] = "POST|/items"
	f.responseSchemas["POST|/items"] = map[string]map[string]string{"200": {"id": "integer"}}
	res := SendResult{
		Item:   WorkItem{TemplateID: 1, Method: "POST", Path: "/items"},
		Status: 201, // undocumented sibling of the declared 200
		Body:   `{"id":1,"undeclaredField":"x"}`,
	}
	f.checkSchemaConformance(res)
	if len(f.findings) != 1 {
		t.Errorf("expected the sole declared 2xx schema to be used as a fallback, got %d findings", len(f.findings))
	}
}
