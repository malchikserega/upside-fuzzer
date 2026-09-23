package engine

import "testing"

// TestMineClientErrorFieldsModelStateShape covers ASP.NET's standard
// ValidationProblemDetails/ModelState 400 body: {"errors": {"Field": ["msg", ...]}}.
func TestMineClientErrorFieldsModelStateShape(t *testing.T) {
	body := `{
		"type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
		"title": "One or more validation errors occurred.",
		"status": 400,
		"errors": {
			"Status": ["The value 'Bogus' is not valid. Must be one of [Pending, Paid, Shipped]."],
			"Name": ["The Name field is required."]
		}
	}`
	got := mineClientErrorFields(body)

	want := map[string]bool{"Pending": true, "Paid": true, "Shipped": true}
	if len(got["Status"]) == 0 {
		t.Fatalf("expected mined values for field 'Status', got none: %v", got)
	}
	for _, v := range got["Status"] {
		if !want[v] {
			t.Errorf("unexpected mined value %q for field Status (want one of %v)", v, want)
		}
	}
	if _, ok := got["Name"]; ok && len(got["Name"]) > 0 {
		t.Errorf("field 'Name' has no enum-hint phrasing, expected no mined values, got %v", got["Name"])
	}
}

// TestMineClientErrorFieldsFlatShape covers the flatter {"Field": ["msg"]} shape some
// minimal-API validators emit directly, without a top-level "errors" wrapper.
func TestMineClientErrorFieldsFlatShape(t *testing.T) {
	body := `{"CurrencyCode": ["Valid values: USD, EUR, GBP"]}`
	got := mineClientErrorFields(body)
	if len(got["CurrencyCode"]) != 3 {
		t.Fatalf("expected 3 mined values for CurrencyCode, got %v", got["CurrencyCode"])
	}
}

// TestMineClientErrorFieldsIgnoresUnrelatedJSON ensures an arbitrary JSON 400 body that
// doesn't look like a field->messages map yields nothing (no spurious mining).
func TestMineClientErrorFieldsIgnoresUnrelatedJSON(t *testing.T) {
	for _, body := range []string{
		`{"count": 5, "nested": {"a": 1}}`,
		`not json at all`,
		``,
		`[1,2,3]`,
	} {
		got := mineClientErrorFields(body)
		if len(got) != 0 {
			t.Errorf("expected no mined fields for %q, got %v", body, got)
		}
	}
}

// TestRecordClientErrorSampleFeedsRuntimeStore verifies the integration point: calling
// recordClientErrorSample with a ModelState body makes the mined value available via
// RuntimeStore, the same pool pickCustomPayloadValue draws from.
func TestRecordClientErrorSampleFeedsRuntimeStore(t *testing.T) {
	f := &Fuzzer{
		clientSamples: map[string][]string{},
		runtime:       newRuntimeStore(),
	}
	body := `{"errors": {"Status": ["must be one of [Active, Inactive]"]}}`
	f.recordClientErrorSample("POST", "/api/things", 400, body)

	cands := f.runtime.valuesForKey("status")
	found := false
	for _, v := range cands {
		if v == "Active" || v == "Inactive" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mined value Active/Inactive to reach RuntimeStore, got %v", cands)
	}
}
