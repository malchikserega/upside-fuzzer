package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"void/internal/config"
)

func widgetBodySchema() *BodyNode {
	return &BodyNode{
		NodeType:      "object",
		PropertyOrder: []string{"name", "count"},
		// Both required: this fixture's own tests assert both fields are
		// ALWAYS present in valid-mode output, which only holds if there's no
		// optional field for opAddRemoveFieldValid (body_mutate.go) to
		// legitimately drop -- Stage 5 added a 30%-chance valid-mode operator
		// application to buildAndMutateBodyTree, so an all-optional schema
		// here made this assertion flaky rather than actually wrong.
		Required: []string{"name", "count"},
		Properties: map[string]*BodyNode{
			"name":  {NodeType: "scalar", FieldName: "name", Path: "name", ScalarType: "string"},
			"count": {NodeType: "scalar", FieldName: "count", Path: "count", ScalarType: "integer"},
		},
	}
}

func typedBodyTemplate(id int) Template {
	tmpl := richFuzzableTemplate(id)
	tmpl.BodySchema = widgetBodySchema()
	return tmpl
}

// TestRenderTemplateContext_TypedBodyPathProducesValidJSON exercises the new
// branch end to end (render -> prepareItemForSend) for a template whose
// grammar declared a body_schema, with -typed-body-mutation on.
func TestRenderTemplateContext_TypedBodyPathProducesValidJSON(t *testing.T) {
	f := &Fuzzer{
		tmplByID: map[int]*Template{1: ptrTemplate(typedBodyTemplate(1))},
		runtime:  newRuntimeStore(),
		dict:     &DictStore{},
		cfg:      config.Config{TypedBodyMutation: true},
	}
	for i := 0; i < 20; i++ {
		item, err := f.renderTemplateContext(1, "none", 1, -1, nil)
		if err != nil {
			t.Fatalf("renderTemplateContext: %v", err)
		}
		if item.BodyTree == nil {
			t.Fatal("expected BodyTree to be set for a template with a BodySchema and TypedBodyMutation on")
		}
		sent := f.prepareItemForSend(item)
		var decoded map[string]any
		if err := json.Unmarshal([]byte(sent.Body), &decoded); err != nil {
			t.Fatalf("prepareItemForSend produced invalid JSON: %v; body=%q", err, sent.Body)
		}
		if _, ok := decoded["name"]; !ok {
			t.Errorf("expected decoded body to have a name field, got %v", decoded)
		}
		if _, ok := decoded["count"]; !ok {
			t.Errorf("expected decoded body to have a count field, got %v", decoded)
		}
	}
}

// TestRenderTemplateContext_TypedPathSkippedWhenFlagOff confirms
// -typed-body-mutation=false always takes the legacy path even when a
// BodySchema is present -- the flag genuinely gates the feature, not just the
// BodySchema's presence.
func TestRenderTemplateContext_TypedPathSkippedWhenFlagOff(t *testing.T) {
	f := &Fuzzer{
		tmplByID: map[int]*Template{1: ptrTemplate(typedBodyTemplate(1))},
		runtime:  newRuntimeStore(),
		dict:     &DictStore{},
		cfg:      config.Config{TypedBodyMutation: false},
	}
	item, err := f.renderTemplateContext(1, "none", 1, -1, nil)
	if err != nil {
		t.Fatalf("renderTemplateContext: %v", err)
	}
	if item.BodyTree != nil {
		t.Errorf("expected BodyTree to stay nil when TypedBodyMutation is off, got %+v", item.BodyTree)
	}
}

// TestRenderTemplateContext_FlatBodyPathUnchangedWhenNoBodySchema is the
// explicit backward-compatibility regression pin: a template with no
// BodySchema (every template.export.json generated before this feature)
// renders byte-identically through the legacy flat-segment path whether
// -typed-body-mutation is on or off -- the new branch is provably dead code
// for it either way.
func TestRenderTemplateContext_FlatBodyPathUnchangedWhenNoBodySchema(t *testing.T) {
	// Deliberately all-static (no fuzzable/custom_payload/dynamic segments) so
	// rendering is fully deterministic -- any difference between the two runs
	// below can only come from the code path taken, never from unrelated
	// randomization (pickDynamic/pickCorrelated/etc., unchanged by this feature
	// and already non-deterministic across renders on their own).
	staticBodyTemplate := Template{
		ID:        1,
		RequestID: "/api/widgets",
		Segments: []Segment{
			{Kind: "static", Value: "POST /api/widgets HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"name\":\"fixed\"}"},
		},
	}
	newFuzzer := func(typedOn bool) *Fuzzer {
		return &Fuzzer{
			tmplByID: map[int]*Template{1: ptrTemplate(staticBodyTemplate)}, // no BodySchema
			runtime:  newRuntimeStore(),
			dict:     &DictStore{},
			cfg:      config.Config{TypedBodyMutation: typedOn},
		}
	}

	itemOff, err := newFuzzer(false).renderTemplateContext(1, "none", 1, -1, nil)
	if err != nil {
		t.Fatalf("renderTemplateContext (flag off): %v", err)
	}
	itemOn, err := newFuzzer(true).renderTemplateContext(1, "none", 1, -1, nil)
	if err != nil {
		t.Fatalf("renderTemplateContext (flag on): %v", err)
	}

	if itemOff.BodyTree != nil || itemOn.BodyTree != nil {
		t.Fatalf("expected BodyTree nil in both cases (no BodySchema on the template), got off=%+v on=%+v",
			itemOff.BodyTree, itemOn.BodyTree)
	}
	if itemOff.Body != itemOn.Body {
		t.Errorf("expected identical rendered Body regardless of -typed-body-mutation when no BodySchema is present:\noff=%q\non=%q",
			itemOff.Body, itemOn.Body)
	}
	if itemOff.Method != itemOn.Method || itemOff.Path != itemOn.Path {
		t.Errorf("expected identical method/path, got off=%s %s on=%s %s", itemOff.Method, itemOff.Path, itemOn.Method, itemOn.Path)
	}
}

func TestPrepareItemForSend_SerializesBodyTreeToJSONBeforeAntiForgeryCheck(t *testing.T) {
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{{Key: "name", Value: newStringValue(nil, "", "widget")}}
	f := &Fuzzer{cfg: config.Config{AutoAntiForgery: false}} // deliberately off, to prove serialization isn't gated on it
	item := WorkItem{
		Method:   "POST",
		Path:     "/api/widgets",
		Headers:  map[string]string{"Content-Type": "application/json"},
		Body:     "STALE_PLACEHOLDER",
		BodyTree: tree,
	}
	got := f.prepareItemForSend(item)
	if got.Body != `{"name":"widget"}` {
		t.Errorf("expected BodyTree serialized to JSON regardless of AutoAntiForgery, got %q", got.Body)
	}
}

func TestPrepareItemForSend_SerializesToFormWhenContentTypeIsForm(t *testing.T) {
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{{Key: "name", Value: newStringValue(nil, "", "widget")}}
	f := &Fuzzer{cfg: config.Config{AutoAntiForgery: false}}
	item := WorkItem{
		Method:   "POST",
		Path:     "/api/widgets",
		Headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		BodyTree: tree,
	}
	got := f.prepareItemForSend(item)
	if got.Body != "name=widget" {
		t.Errorf("expected form-encoded body, got %q", got.Body)
	}
}

func TestPrepareItemForSend_SerializesToMultipartAndUpdatesContentType(t *testing.T) {
	tree := newObjectValue(nil, "")
	tree.Fields = []BodyField{{Key: "name", Value: newStringValue(nil, "", "widget")}}
	f := &Fuzzer{cfg: config.Config{AutoAntiForgery: false}}
	item := WorkItem{
		Method:   "POST",
		Path:     "/api/widgets",
		Headers:  map[string]string{"Content-Type": "multipart/form-data"},
		BodyTree: tree,
	}
	got := f.prepareItemForSend(item)
	if !strings.Contains(got.Body, "widget") || !strings.Contains(got.Body, `name="name"`) {
		t.Errorf("expected multipart body containing the field, got %q", got.Body)
	}
	ct := getHeaderCI(got.Headers, "Content-Type")
	if !strings.Contains(ct, "boundary=") {
		t.Errorf("expected Content-Type to carry the boundary used to serialize the body, got %q", ct)
	}
}

func TestPrepareItemForSend_LegacyItemWithNoBodyTreeUnaffected(t *testing.T) {
	f := &Fuzzer{cfg: config.Config{AutoAntiForgery: false}}
	item := WorkItem{Method: "GET", Path: "/api/widgets", Body: "unchanged"}
	got := f.prepareItemForSend(item)
	if got.Body != "unchanged" {
		t.Errorf("expected a nil-BodyTree item's Body untouched, got %q", got.Body)
	}
}
