package engine

import (
	"encoding/json"
	"testing"
)

func TestBodyNode_DecodesScalarNode(t *testing.T) {
	raw := `{"node_type":"scalar","path":"title","field_name":"title","scalar_type":"string",
	         "min_length":3,"max_length":120,"nullable":true}`
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if !n.IsScalar() {
		t.Errorf("expected IsScalar() true, node_type=%q", n.NodeType)
	}
	if n.ScalarType != "string" || !n.Nullable {
		t.Errorf("scalar_type/nullable not decoded correctly: %+v", n)
	}
	if n.MinLength == nil || *n.MinLength != 3 {
		t.Errorf("expected MinLength=3, got %v", n.MinLength)
	}
	if n.MaxLength == nil || *n.MaxLength != 120 {
		t.Errorf("expected MaxLength=120, got %v", n.MaxLength)
	}
}

func TestBodyNode_DecodesNestedObject(t *testing.T) {
	raw := `{
		"node_type":"object","path":"","field_name":"",
		"properties":{
			"owner":{"node_type":"object","path":"owner","field_name":"owner",
				"properties":{"city":{"node_type":"scalar","path":"owner.city","field_name":"city","scalar_type":"string"}},
				"property_order":["city"],"required":["city"],"allow_additional":true}
		},
		"property_order":["owner"],"required":[],"allow_additional":false
	}`
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if !n.IsObject() {
		t.Fatalf("expected IsObject() true, node_type=%q", n.NodeType)
	}
	owner, ok := n.Properties["owner"]
	if !ok {
		t.Fatalf("expected properties[owner] to be present, got %+v", n.Properties)
	}
	city, ok := owner.Properties["city"]
	if !ok || city.Path != "owner.city" {
		t.Fatalf("expected nested city node with path owner.city, got %+v", owner.Properties)
	}
	if n.AllowAdditional {
		t.Errorf("expected root allow_additional=false to decode as false")
	}
	if !owner.AllowAdditional {
		t.Errorf("expected owner allow_additional=true to decode as true")
	}
}

func TestBodyNode_DecodesArrayWithItems(t *testing.T) {
	raw := `{"node_type":"array","path":"items","field_name":"items",
	         "items":{"node_type":"scalar","path":"items","field_name":"items","scalar_type":"string"},
	         "min_items":1,"max_items":5,"unique_items":true}`
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if !n.IsArray() {
		t.Fatalf("expected IsArray() true, node_type=%q", n.NodeType)
	}
	if n.Items == nil || n.Items.ScalarType != "string" {
		t.Fatalf("expected decoded Items scalar node, got %+v", n.Items)
	}
	if n.MinItems == nil || *n.MinItems != 1 || n.MaxItems == nil || *n.MaxItems != 5 {
		t.Errorf("min_items/max_items not decoded correctly: min=%v max=%v", n.MinItems, n.MaxItems)
	}
	if !n.UniqueItems {
		t.Errorf("expected unique_items=true")
	}
}

func TestBodyNode_DecodesOneOfWithDiscriminator(t *testing.T) {
	raw := `{"node_type":"oneOf","path":"payment","field_name":"payment",
	         "variants":[
	           {"node_type":"object","path":"payment","field_name":"payment","properties":{"cardNumber":{"node_type":"scalar","scalar_type":"string"}}},
	           {"node_type":"object","path":"payment","field_name":"payment","properties":{"walletId":{"node_type":"scalar","scalar_type":"string"}}}
	         ],
	         "discriminator":{"property_name":"type","mapping":{"card":0,"wallet":1}}}`
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if !n.IsVariant() {
		t.Fatalf("expected IsVariant() true, node_type=%q", n.NodeType)
	}
	if len(n.Variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(n.Variants))
	}
	if n.Discriminator == nil || n.Discriminator.PropertyName != "type" {
		t.Fatalf("expected discriminator.property_name=type, got %+v", n.Discriminator)
	}
	if n.Discriminator.Mapping["card"] != 0 || n.Discriminator.Mapping["wallet"] != 1 {
		t.Errorf("discriminator mapping not decoded correctly: %+v", n.Discriminator.Mapping)
	}
	if n.Variants[0].Properties["cardNumber"] == nil {
		t.Errorf("expected variant[0] to have cardNumber property")
	}
}

func TestBodyNode_DecodesAdditionalPropertiesSchema(t *testing.T) {
	raw := `{"node_type":"object","allow_additional":true,
	         "additional_properties":{"node_type":"scalar","scalar_type":"integer"}}`
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if n.AdditionalProperties == nil || n.AdditionalProperties.ScalarType != "integer" {
		t.Fatalf("expected additional_properties scalar node, got %+v", n.AdditionalProperties)
	}
}

func TestBodyNode_DecodesPayloadKey(t *testing.T) {
	raw := `{"node_type":"scalar","field_name":"orderId","scalar_type":"integer","payload_key":"orderid"}`
	var n BodyNode
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if n.PayloadKey != "orderid" {
		t.Errorf("expected payload_key=orderid, got %q", n.PayloadKey)
	}
}

// TestTemplate_OldGrammarLeavesBodySchemaNil is the explicit backward-compatibility
// pin: a template.export.json with no "body_schema" key at all (every grammar
// generated before this feature) must decode with Template.BodySchema == nil, not
// some zero-value BodyNode -- renderTemplateContext's typed-path branch (Stage 4)
// checks BodySchema != nil to decide whether to take the new path at all.
func TestTemplate_OldGrammarLeavesBodySchemaNil(t *testing.T) {
	raw := `{"id":0,"request_id":"GET/api/widgets","segments":[{"kind":"static","value":"GET /api/widgets HTTP/1.1\r\n\r\n"}],"reads":[],"writes":[]}`
	var tmpl Template
	if err := json.Unmarshal([]byte(raw), &tmpl); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if tmpl.BodySchema != nil {
		t.Errorf("expected BodySchema to stay nil when the JSON has no body_schema key, got %+v", tmpl.BodySchema)
	}
}

func TestTemplate_DecodesBodySchemaWhenPresent(t *testing.T) {
	raw := `{"id":1,"request_id":"POST/api/widgets","segments":[],"reads":[],"writes":[],
	         "body_schema":{"node_type":"object","properties":{"name":{"node_type":"scalar","scalar_type":"string"}}}}`
	var tmpl Template
	if err := json.Unmarshal([]byte(raw), &tmpl); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if tmpl.BodySchema == nil || !tmpl.BodySchema.IsObject() {
		t.Fatalf("expected a decoded object BodySchema, got %+v", tmpl.BodySchema)
	}
}
