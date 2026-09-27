package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustDecodeNode(t *testing.T, raw string) *BodyNode {
	t.Helper()
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("failed to decode fixture BodyNode: %v", err)
	}
	return &n
}

func TestBuildBodyValue_ScalarDefaults(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"string"}`)
	v := buildBodyValue(node, nil, nil)
	if v.Kind != BVString || v.Str != "fuzzstring" {
		t.Errorf("expected default string fuzzstring, got kind=%v str=%q", v.Kind, v.Str)
	}

	node = mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"integer"}`)
	v = buildBodyValue(node, nil, nil)
	if v.Kind != BVNumber || v.Str != "1" {
		t.Errorf("expected default integer 1, got kind=%v str=%q", v.Kind, v.Str)
	}

	node = mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"boolean"}`)
	v = buildBodyValue(node, nil, nil)
	if v.Kind != BVBool || !v.Bool {
		t.Errorf("expected default bool true, got kind=%v bool=%v", v.Kind, v.Bool)
	}
}

func TestBuildBodyValue_EnumPrefersFirstValue(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"string","enum_values":["Todo","Done"]}`)
	v := buildBodyValue(node, nil, nil)
	if v.Str != "Todo" {
		t.Errorf("expected first enum value Todo, got %q", v.Str)
	}
}

func TestBuildBodyValue_NumericRespectsMinimumBound(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"integer","minimum":50}`)
	v := buildBodyValue(node, nil, nil)
	if v.Str != "50" {
		t.Errorf("expected default clamped up to minimum 50, got %q", v.Str)
	}
}

func TestBuildBodyValue_StringRespectsMinLength(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"string","min_length":20}`)
	v := buildBodyValue(node, nil, nil)
	if len(v.Str) < 20 {
		t.Errorf("expected string padded to at least min_length 20, got %q (len=%d)", v.Str, len(v.Str))
	}
}

func TestBuildBodyValue_UUIDFormatIsV4Shaped(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"scalar","scalar_type":"string","format":"uuid"}`)
	v := buildBodyValue(node, nil, nil)
	parts := strings.Split(v.Str, "-")
	if len(parts) != 5 || parts[2][0] != '4' {
		t.Errorf("expected a v4-shaped UUID, got %q", v.Str)
	}
}

func TestBuildBodyValue_ObjectPopulatesAllPropertiesInOrder(t *testing.T) {
	node := mustDecodeNode(t, `{
		"node_type":"object",
		"properties":{"title":{"node_type":"scalar","scalar_type":"string"},"count":{"node_type":"scalar","scalar_type":"integer"}},
		"property_order":["title","count"]
	}`)
	v := buildBodyValue(node, nil, nil)
	if v.Kind != BVObject || len(v.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %+v", v.Fields)
	}
	if v.Fields[0].Key != "title" || v.Fields[1].Key != "count" {
		t.Errorf("expected property_order preserved, got %q, %q", v.Fields[0].Key, v.Fields[1].Key)
	}
}

func TestBuildBodyValue_NestedObject(t *testing.T) {
	node := mustDecodeNode(t, `{
		"node_type":"object","property_order":["owner"],
		"properties":{"owner":{"node_type":"object","property_order":["city"],
			"properties":{"city":{"node_type":"scalar","scalar_type":"string"}}}}
	}`)
	v := buildBodyValue(node, nil, nil)
	owner := v.Fields[0].Value
	if owner.Kind != BVObject || owner.Fields[0].Key != "city" {
		t.Fatalf("expected nested owner.city, got %+v", owner)
	}
}

func TestBuildBodyValue_ArrayUsesMinItemsCappedAtMax(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"array","items":{"node_type":"scalar","scalar_type":"string"},"min_items":2}`)
	v := buildBodyValue(node, nil, nil)
	if len(v.Items) != 2 {
		t.Errorf("expected 2 items from min_items, got %d", len(v.Items))
	}

	node = mustDecodeNode(t, `{"node_type":"array","items":{"node_type":"scalar","scalar_type":"string"},"min_items":50}`)
	v = buildBodyValue(node, nil, nil)
	if len(v.Items) != maxDefaultArrayLen {
		t.Errorf("expected item count capped at %d, got %d", maxDefaultArrayLen, len(v.Items))
	}
}

func TestBuildBodyValue_ArrayWithNoItemsSchemaIsEmpty(t *testing.T) {
	node := mustDecodeNode(t, `{"node_type":"array"}`)
	v := buildBodyValue(node, nil, nil)
	if len(v.Items) != 0 {
		t.Errorf("expected empty array with no items schema, got %d items", len(v.Items))
	}
}

func TestBuildBodyValue_OneOfPicksVariantAndSetsDiscriminator(t *testing.T) {
	node := mustDecodeNode(t, `{
		"node_type":"oneOf",
		"variants":[
			{"node_type":"object","property_order":["cardNumber"],"properties":{"cardNumber":{"node_type":"scalar","scalar_type":"string"}}},
			{"node_type":"object","property_order":["walletId"],"properties":{"walletId":{"node_type":"scalar","scalar_type":"string"}}}
		],
		"discriminator":{"property_name":"type","mapping":{"card":0,"wallet":1}}
	}`)
	v := buildBodyValue(node, nil, func(n int) int { return 1 })
	if len(v.Fields) != 2 {
		t.Fatalf("expected walletId + injected discriminator field, got %+v", v.Fields)
	}
	found := false
	for _, f := range v.Fields {
		if f.Key == "type" {
			found = true
			if f.Value.Str != "wallet" {
				t.Errorf("expected discriminator tag 'wallet' for variant 1, got %q", f.Value.Str)
			}
		}
	}
	if !found {
		t.Errorf("expected discriminator property 'type' to be injected, got %+v", v.Fields)
	}
}

func TestBuildBodyValue_OneOfDefaultsToFirstVariantWithNilPicker(t *testing.T) {
	node := mustDecodeNode(t, `{
		"node_type":"oneOf",
		"variants":[
			{"node_type":"scalar","scalar_type":"string"},
			{"node_type":"scalar","scalar_type":"integer"}
		]
	}`)
	v := buildBodyValue(node, nil, nil)
	if v.Kind != BVString {
		t.Errorf("expected first variant (string) picked by default, got kind=%v", v.Kind)
	}
}

func TestToJSON_SimpleObject(t *testing.T) {
	obj := newObjectValue(nil, "")
	obj.Fields = []BodyField{
		{Key: "name", Value: newStringValue(nil, "", "widget")},
		{Key: "qty", Value: newNumberValue(nil, "", "3")},
		{Key: "active", Value: newBoolValue(nil, "", true)},
	}
	got := obj.ToJSON()
	want := `{"name":"widget","qty":3,"active":true}`
	if got != want {
		t.Errorf("ToJSON() = %q, want %q", got, want)
	}
}

func TestToJSON_NestedObjectAndArray(t *testing.T) {
	inner := newObjectValue(nil, "")
	inner.Fields = []BodyField{{Key: "city", Value: newStringValue(nil, "", "NYC")}}
	arr := newArrayValue(nil, "")
	arr.Items = []*BodyValue{newNumberValue(nil, "", "1"), newNumberValue(nil, "", "2")}
	root := newObjectValue(nil, "")
	root.Fields = []BodyField{{Key: "owner", Value: inner}, {Key: "nums", Value: arr}}

	got := root.ToJSON()
	want := `{"owner":{"city":"NYC"},"nums":[1,2]}`
	if got != want {
		t.Errorf("ToJSON() = %q, want %q", got, want)
	}
}

func TestToJSON_EscapesQuotesAndControlChars(t *testing.T) {
	v := newStringValue(nil, "", "he said \"hi\"\nline2\ttab")
	got := v.ToJSON()
	want := `"he said \"hi\"\nline2\ttab"`
	if got != want {
		t.Errorf("ToJSON() = %q, want %q", got, want)
	}
}

func TestToJSON_DoesNotHTMLEscape(t *testing.T) {
	v := newStringValue(nil, "", "<script>alert(1)&x</script>")
	got := v.ToJSON()
	want := `"<script>alert(1)&x</script>"`
	if got != want {
		t.Errorf("ToJSON() = %q, want %q -- injection payload bytes must survive verbatim", got, want)
	}
}

// TestToJSON_DuplicateKeyEmitsBothOccurrences is the hard-constraint proof: a
// hand-built object with two BodyFields sharing a Key produces raw JSON text
// containing the key twice, verbatim -- something no map-based representation
// could do, and something encoding/json.Unmarshal would silently dedupe if we
// tried to verify it that way, so this asserts on the raw string only.
func TestToJSON_DuplicateKeyEmitsBothOccurrences(t *testing.T) {
	obj := newObjectValue(nil, "")
	obj.Fields = []BodyField{
		{Key: "id", Value: newNumberValue(nil, "", "1")},
		{Key: "id", Value: newStringValue(nil, "", "conflicting")},
	}
	got := obj.ToJSON()
	want := `{"id":1,"id":"conflicting"}`
	if got != want {
		t.Errorf("ToJSON() = %q, want %q", got, want)
	}
	if strings.Count(got, `"id"`) != 2 {
		t.Errorf("expected literal key \"id\" to appear twice in %q", got)
	}
}

func TestToJSON_NullValue(t *testing.T) {
	if got := newNullValue(nil, "").ToJSON(); got != "null" {
		t.Errorf("ToJSON() = %q, want null", got)
	}
}

func TestToForm_NestedUsesBracketNotation(t *testing.T) {
	inner := newObjectValue(nil, "")
	inner.Fields = []BodyField{{Key: "city", Value: newStringValue(nil, "", "NYC")}}
	root := newObjectValue(nil, "")
	root.Fields = []BodyField{{Key: "owner", Value: inner}}

	got := root.ToForm()
	want := "owner%5Bcity%5D=NYC"
	if got != want {
		t.Errorf("ToForm() = %q, want %q", got, want)
	}
}

func TestToForm_ArrayUsesEmptyBracketNotation(t *testing.T) {
	arr := newArrayValue(nil, "")
	arr.Items = []*BodyValue{newStringValue(nil, "", "a"), newStringValue(nil, "", "b")}
	root := newObjectValue(nil, "")
	root.Fields = []BodyField{{Key: "tags", Value: arr}}

	got := root.ToForm()
	if !strings.Contains(got, "tags%5B%5D=a") || !strings.Contains(got, "tags%5B%5D=b") {
		t.Errorf("ToForm() = %q, expected both tags[]=a and tags[]=b", got)
	}
}

func TestToMultipart_OneFieldOnePart(t *testing.T) {
	root := newObjectValue(nil, "")
	root.Fields = []BodyField{{Key: "name", Value: newStringValue(nil, "", "widget")}}

	got := root.ToMultipart("BOUNDARY")
	if !strings.Contains(got, "--BOUNDARY\r\n") {
		t.Errorf("expected opening boundary, got %q", got)
	}
	if !strings.Contains(got, `name="name"`) {
		t.Errorf("expected Content-Disposition name=\"name\", got %q", got)
	}
	if !strings.Contains(got, "widget") {
		t.Errorf("expected value widget in body, got %q", got)
	}
	if !strings.HasSuffix(got, "--BOUNDARY--\r\n") {
		t.Errorf("expected closing boundary, got %q", got)
	}
}

func TestBodyValue_Clone_DeepCopiesFieldsAndItems(t *testing.T) {
	arr := newArrayValue(nil, "")
	arr.Items = []*BodyValue{newStringValue(nil, "", "a")}
	orig := newObjectValue(nil, "")
	orig.Fields = []BodyField{{Key: "list", Value: arr}}

	cp := orig.clone()
	cp.Fields[0].Value.Items[0].Str = "mutated"

	if orig.Fields[0].Value.Items[0].Str != "a" {
		t.Errorf("expected clone to be independent, original was mutated: %q", orig.Fields[0].Value.Items[0].Str)
	}
}
