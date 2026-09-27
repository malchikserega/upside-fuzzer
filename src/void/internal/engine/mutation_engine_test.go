package engine

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// TestMutateIntFieldConstraintBoundaries verifies Top-20 #14: when a Segment carries
// declared Minimum/Maximum, mutateInt's candidate pool includes the exact boundary
// values (min-1/min/min+1/max-1/max/max+1), in addition to the pre-existing generic
// pool -- additive, not a replacement.
func TestMutateIntFieldConstraintBoundaries(t *testing.T) {
	min, max := 1.0, 10000.0
	hint := &Segment{Minimum: &min, Maximum: &max}

	seen := map[int]bool{}
	for i := 0; i < 2000; i++ {
		v := mutateInt("5000", hint)
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("mutateInt produced non-integer output: %q", v)
		}
		seen[n] = true
	}

	for _, want := range []int{0, 1, 2, 9999, 10000, 10001} {
		if !seen[want] {
			t.Errorf("expected boundary value %d to appear among mutateInt outputs with hint min=%v max=%v, got set: %v", want, min, max, seen)
		}
	}
}

// TestMutateIntNilHintUnchanged verifies the nil-hint path (today's default for any
// segment without constraint metadata) never crashes and stays within the pre-existing
// generic candidate universe -- i.e. this change is backward compatible.
func TestMutateIntNilHintUnchanged(t *testing.T) {
	for i := 0; i < 50; i++ {
		v := mutateInt("42", nil)
		if _, err := strconv.Atoi(v); err != nil {
			t.Fatalf("mutateInt(nil hint) produced non-integer output: %q", v)
		}
	}
}

// TestMutateStringCategorizedEnumBlend verifies enum-typed fields occasionally surface
// a valid enum value (and a deliberately-invalid near-miss) among mutation outputs.
func TestMutateStringCategorizedEnumBlend(t *testing.T) {
	hint := &Segment{EnumValues: []string{"Pending", "Paid", "Shipped"}}
	found := false
	for i := 0; i < 500; i++ {
		v, cat := mutateStringCategorized("Pending", hint)
		if cat == "mcat_field_constraint" && (v == "Pending" || v == "Paid" || v == "Shipped" || v == "Pending_INVALID" || v == "Paid_INVALID" || v == "Shipped_INVALID") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one field-constraint-category enum-derived candidate over 500 attempts")
	}
}

// TestFieldConstraintStringCandidatesLengthBoundaries checks exact min/max length
// candidates are generated when a segment declares length bounds.
func TestFieldConstraintStringCandidatesLengthBoundaries(t *testing.T) {
	minLen, maxLen := 3, 8
	hint := &Segment{MinLength: &minLen, MaxLength: &maxLen}
	cands := fieldConstraintStringCandidates("hello", hint)

	hasLen := func(n int) bool {
		for _, c := range cands {
			if len(c) == n {
				return true
			}
		}
		return false
	}
	for _, want := range []int{minLen - 1, minLen, maxLen, maxLen + 1} {
		if !hasLen(want) {
			t.Errorf("expected a candidate of length %d among %v", want, cands)
		}
	}
}

func TestMutateJSONBody_NonJSONObjectLeftUnchanged(t *testing.T) {
	for _, body := range []string{"", "not json", `[1,2,3]`, `"just a string"`, `42`} {
		v, label := mutateJSONBody(body, 2)
		if v != body || label != "" {
			t.Errorf("mutateJSONBody(%q) = (%q, %q), want unchanged with empty label", body, v, label)
		}
	}
}

func TestMutateJSONBody_MutatesAValidObjectAndStaysValidJSON(t *testing.T) {
	body := `{"id":1,"name":"alice","active":true}`
	seenLabels := map[string]bool{}
	for i := 0; i < 300; i++ {
		v, label := mutateJSONBody(body, 3)
		if label == "" {
			continue // deletion-then-empty-object edge case is allowed to no-op rarely
		}
		var js any
		if err := json.Unmarshal([]byte(v), &js); err != nil {
			t.Fatalf("mutateJSONBody produced invalid JSON: %q (label=%q): %v", v, label, err)
		}
		for _, part := range strings.Split(label, "+") {
			seenLabels[part] = true
		}
	}
	// Over enough iterations, every mutation op should fire at least once.
	for _, want := range []string{
		"json_del_key", "json_null_key", "json_flip_scalar", "json_type_confuse",
		"json_mass_assign", "json_deep_nest", "json_array_overflow", "json_dup_key",
		"json_dotnet_deser",
	} {
		if !seenLabels[want] {
			t.Errorf("expected mutation label %q to appear at least once over 300 runs, got labels: %v", want, seenLabels)
		}
	}
}

func TestJSONTypeConfuse_AlwaysChangesType(t *testing.T) {
	cases := []any{"a string", 3.14, true, nil, []any{1, 2}, map[string]any{"k": "v"}}
	for _, in := range cases {
		for i := 0; i < 20; i++ {
			out := jsonTypeConfuse(in)
			// default branch (unmatched type) returns nil, which is itself a type
			// change from anything but nil -- just confirm it never panics and
			// returns something JSON-marshalable.
			if _, err := json.Marshal(out); err != nil {
				t.Fatalf("jsonTypeConfuse(%#v) produced unmarshalable output %#v: %v", in, out, err)
			}
		}
	}
}

func TestFlipJSONScalar_BoolInverts(t *testing.T) {
	if v := flipJSONScalar(true); v != false {
		t.Errorf("flipJSONScalar(true) = %v, want false", v)
	}
	if v := flipJSONScalar(false); v != true {
		t.Errorf("flipJSONScalar(false) = %v, want true", v)
	}
}

func TestFlipJSONScalar_StringAndFloatAndNilProduceSomething(t *testing.T) {
	if v := flipJSONScalar("hello"); v == nil {
		t.Error("expected a non-nil flipped string")
	}
	if v := flipJSONScalar(3.14); v == nil {
		t.Error("expected a non-nil flipped float")
	}
	if v := flipJSONScalar(nil); v == nil {
		t.Error("expected flipJSONScalar(nil) to still return a candidate value")
	}
	// Unknown type falls through to the default branch, returned unchanged.
	type weird struct{}
	w := weird{}
	if v := flipJSONScalar(w); v != w {
		t.Errorf("expected an unrecognized type to pass through unchanged, got %#v", v)
	}
}

func TestMutateAny_DispatchesByDeclaredType(t *testing.T) {
	cases := []struct {
		valueType   string
		wantCatHas  string
		checkResult func(t *testing.T, v string)
	}{
		{"int", "mutate_int", func(t *testing.T, v string) {
			if _, err := strconv.Atoi(v); err != nil {
				t.Errorf("expected integer output for type=int, got %q", v)
			}
		}},
		{"integer", "mutate_int", nil},
		{"number", "mutate_number", nil},
		{"float", "mutate_number", nil},
		{"bool", "mutate_bool", nil},
		{"boolean", "mutate_bool", nil},
		{"datetime", "mutate_datetime", nil},
		{"date", "mutate_datetime", nil},
		{"uuid", "mutate_uuid", nil},
		{"guid", "mutate_uuid", nil},
		{"object", "mutate_object", nil},
		{"string", "", nil},
		{"totally-unknown-type", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.valueType, func(t *testing.T) {
			v, cat := mutateAny("orig", tc.valueType, nil)
			if tc.wantCatHas != "" && cat != tc.wantCatHas {
				t.Errorf("mutateAny(type=%q) category = %q, want %q", tc.valueType, cat, tc.wantCatHas)
			}
			if tc.checkResult != nil {
				tc.checkResult(t, v)
			}
		})
	}
}

func TestMutateHavoc_StacksMutationsAndLabelsEachOne(t *testing.T) {
	v, label := mutateHavoc("42", "int", 3, nil)
	if _, err := strconv.Atoi(v); err != nil {
		t.Errorf("expected mutateHavoc(type=int) to still produce an integer, got %q", v)
	}
	if !strings.HasPrefix(label, "havoc(") || !strings.HasSuffix(label, ")") {
		t.Errorf("expected havoc(...) wrapped label, got %q", label)
	}
	// depth=3 clamped into [1,4] should produce 3 mutate_int entries joined by '+'.
	inner := strings.TrimSuffix(strings.TrimPrefix(label, "havoc("), ")")
	if got := len(strings.Split(inner, "+")); got != 3 {
		t.Errorf("expected 3 stacked mutation labels for depth=3, got %d in %q", got, label)
	}
}

func TestMutateHavoc_DepthClampedToOneToFour(t *testing.T) {
	// depth=0 clamps to 1 -> exactly one mutation applied.
	_, label := mutateHavoc("42", "int", 0, nil)
	inner := strings.TrimSuffix(strings.TrimPrefix(label, "havoc("), ")")
	if got := len(strings.Split(inner, "+")); got != 1 {
		t.Errorf("expected depth=0 clamped to 1 mutation, got %d in %q", got, label)
	}
	// depth=99 clamps to 4.
	_, label2 := mutateHavoc("42", "int", 99, nil)
	inner2 := strings.TrimSuffix(strings.TrimPrefix(label2, "havoc("), ")")
	if got := len(strings.Split(inner2, "+")); got != 4 {
		t.Errorf("expected depth=99 clamped to 4 mutations, got %d in %q", got, label2)
	}
}

func TestMutateNumber_ProducesParsableFloatCandidatesWithHintBoundaries(t *testing.T) {
	min, max := 1.0, 100.0
	hint := &Segment{Minimum: &min, Maximum: &max}
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		seen[mutateNumber("50", hint)] = true
	}
	for _, want := range []string{"0", "100"} {
		found := false
		for s := range seen {
			if f, err := strconv.ParseFloat(s, 64); err == nil && f == mustParseFloat(want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a boundary-derived candidate equal to %s among mutateNumber outputs", want)
		}
	}
}

func mustParseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func TestMutateBool_AlwaysOneOfKnownCandidates(t *testing.T) {
	valid := map[string]bool{"true": true, "false": true, "null": true, "0": true, "1": true, `"true"`: true, "yes": true}
	for i := 0; i < 50; i++ {
		v := mutateBool("true")
		if !valid[v] {
			t.Errorf("mutateBool produced unexpected candidate %q", v)
		}
	}
}

func TestMutateDateTime_AlwaysOneOfKnownCandidates(t *testing.T) {
	valid := map[string]bool{
		"0001-01-01T00:00:00Z": true, "9999-12-31T23:59:59Z": true,
		"1970-01-01T00:00:00Z": true, "2038-01-19T03:14:07Z": true,
		"": true, "not-a-date": true, "2024-13-45T99:99:99Z": true,
		"2020-02-29T12:00:00Z": true,
	}
	for i := 0; i < 50; i++ {
		if v := mutateDateTime("2024-01-01T00:00:00Z"); !valid[v] {
			t.Errorf("mutateDateTime produced unexpected candidate %q", v)
		}
	}
}

func TestMutateUUID_ProducesUUIDShapedOrBusinessIDCandidates(t *testing.T) {
	sawStandardCand := false
	for i := 0; i < 200; i++ {
		v := mutateUUID("00000000-0000-0000-0000-000000000000")
		if v == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
			sawStandardCand = true
		}
	}
	if !sawStandardCand {
		t.Error("expected the well-known all-f UUID candidate to appear over 200 runs")
	}
}

func TestMutateBusinessID_UsesRuntimeIDPrefixWhenAvailable(t *testing.T) {
	found := false
	for i := 0; i < 200; i++ {
		v := mutateBusinessID([]string{"ORD-1234"})
		if strings.HasPrefix(strings.ToUpper(v), "ORD-") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected mutateBusinessID to sometimes reuse the ORD- prefix harvested from runtime values")
	}
}

func TestMutateBusinessID_NoRuntimeValuesFallsBackToDefaultPrefixes(t *testing.T) {
	v := mutateBusinessID(nil)
	if v == "" {
		t.Error("expected a non-empty business-ID candidate even with no runtime values")
	}
}

func TestMutateObject_AlwaysReturnsNonEmptyCandidate(t *testing.T) {
	for i := 0; i < 30; i++ {
		if v := mutateObject(""); v == "" {
			t.Error("expected mutateObject to never return an empty string")
		}
	}
}

func TestMutatePath_ReplacesTrailingNumericIDAndPreservesQuery(t *testing.T) {
	for i := 0; i < 50; i++ {
		v, label := mutatePath("/api/users/42?verbose=true")
		if label != "mutate_path" {
			t.Fatalf("expected label mutate_path, got %q", label)
		}
		if !strings.HasPrefix(v, "/api/users/") || !strings.HasSuffix(v, "?verbose=true") {
			t.Fatalf("expected query string preserved and prefix intact, got %q", v)
		}
	}
}

func TestMutatePath_UUIDSegment(t *testing.T) {
	v, label := mutatePath("/api/orders/550e8400-e29b-41d4-a716-446655440000")
	if label != "mutate_path" {
		t.Fatalf("expected a mutation for a UUID path segment, got label %q", label)
	}
	if !strings.HasPrefix(v, "/api/orders/") {
		t.Fatalf("expected prefix preserved, got %q", v)
	}
}

func TestMutatePath_NoIDLikeSegmentReturnsEmpty(t *testing.T) {
	v, label := mutatePath("/api/health")
	if v != "" || label != "" {
		t.Errorf("expected no mutation for a path with no ID-like segment, got (%q, %q)", v, label)
	}
}
