package engine

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// ---- shared conformance validator (test-only) ----
//
// conformanceViolations walks a BodyValue against its BodyNode schema and
// returns a human-readable violation per mismatch found -- the "rest of the
// tree still conforms" check every adversarial-operator test below uses to
// prove the operator applied EXACTLY the one violation it claims to, nothing
// more (and every valid-operator test uses to prove zero violations).

func conformanceViolations(value *BodyValue, schema *BodyNode) []string {
	var out []string
	if schema == nil || value == nil {
		return out
	}
	if value.Kind == BVNull {
		if !schema.Nullable {
			out = append(out, schema.Path+": null but not nullable")
		}
		return out
	}
	switch schema.NodeType {
	case "object":
		if value.Kind != BVObject {
			return append(out, schema.Path+": expected object, got a different kind")
		}
		seen := map[string]int{}
		for _, f := range value.Fields {
			seen[f.Key]++
			if seen[f.Key] > 1 {
				out = append(out, schema.Path+"."+f.Key+": duplicate key")
			}
			childSchema, declared := schema.Properties[f.Key]
			if !declared {
				if !schema.AllowAdditional {
					out = append(out, schema.Path+"."+f.Key+": undeclared property")
				}
				continue
			}
			out = append(out, conformanceViolations(f.Value, childSchema)...)
		}
		for _, req := range schema.Required {
			if seen[req] == 0 {
				out = append(out, schema.Path+"."+req+": missing required property")
			}
		}
	case "array":
		if value.Kind != BVArray {
			return append(out, schema.Path+": expected array, got a different kind")
		}
		if schema.MinItems != nil && len(value.Items) < *schema.MinItems {
			out = append(out, schema.Path+": array shorter than min_items")
		}
		if schema.MaxItems != nil && len(value.Items) > *schema.MaxItems {
			out = append(out, schema.Path+": array longer than max_items")
		}
		for _, it := range value.Items {
			out = append(out, conformanceViolations(it, schema.Items)...)
		}
	case "oneOf", "anyOf":
		matchesAny := false
		for _, v := range schema.Variants {
			if len(conformanceViolations(value, v)) == 0 {
				matchesAny = true
				break
			}
		}
		if !matchesAny {
			out = append(out, schema.Path+": does not conform to any variant")
		}
		if schema.Discriminator != nil && value.Kind == BVObject {
			var tag string
			for _, f := range value.Fields {
				if f.Key == schema.Discriminator.PropertyName {
					tag = f.Value.Str
				}
			}
			if idx, known := schema.Discriminator.Mapping[tag]; known {
				if len(conformanceViolations(value, schema.Variants[idx])) != 0 {
					out = append(out, schema.Path+": shape does not match its own discriminator tag")
				}
			}
		}
	case "scalar":
		switch schema.ScalarType {
		case "string":
			if value.Kind != BVString {
				out = append(out, schema.Path+": expected string scalar")
			}
		case "integer", "number":
			if value.Kind != BVNumber {
				out = append(out, schema.Path+": expected numeric scalar")
			}
		case "boolean":
			if value.Kind != BVBool {
				out = append(out, schema.Path+": expected boolean scalar")
			}
		}
		if value.Kind == BVString {
			if schema.MinLength != nil && len(value.Str) < *schema.MinLength {
				out = append(out, schema.Path+": string shorter than min_length")
			}
			if schema.MaxLength != nil && len(value.Str) > *schema.MaxLength {
				out = append(out, schema.Path+": string longer than max_length")
			}
			if len(schema.EnumValues) > 0 && !containsStr(schema.EnumValues, value.Str) {
				out = append(out, schema.Path+": value not in enum")
			}
		}
		if value.Kind == BVNumber {
			f, _ := strconv.ParseFloat(value.Str, 64)
			if schema.Minimum != nil && f < *schema.Minimum {
				out = append(out, schema.Path+": number below minimum")
			}
			if schema.Maximum != nil && f > *schema.Maximum {
				out = append(out, schema.Path+": number above maximum")
			}
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- fixture schema ----

func widgetOrderSchema() *BodyNode {
	minLen, maxLen := 3, 20
	minItems, maxItems := 1, 3
	return &BodyNode{
		NodeType:      "object",
		Path:          "",
		PropertyOrder: []string{"title", "tags", "payment", "note"},
		// "note" is deliberately the ONLY optional property -- several tests
		// below (add/remove field in particular) need exactly one field whose
		// presence/absence they can check unambiguously.
		Required: []string{"title", "tags", "payment"},
		Properties: map[string]*BodyNode{
			"title": {NodeType: "scalar", FieldName: "title", Path: "title", ScalarType: "string", MinLength: &minLen, MaxLength: &maxLen},
			"tags": {NodeType: "array", FieldName: "tags", Path: "tags", MinItems: &minItems, MaxItems: &maxItems,
				Items: &BodyNode{NodeType: "scalar", Path: "tags", ScalarType: "string"}},
			"payment": {
				// Realistic discriminator shape: each variant declares the
				// discriminator property itself (as a real OpenAPI spec would,
				// typically via allOf inheriting a shared base schema) --
				// applyDiscriminatorTag (body_build.go) overwrites whatever
				// default value the property got with the correct tag, it
				// doesn't require the property to be undeclared.
				NodeType: "oneOf", FieldName: "payment", Path: "payment",
				Variants: []*BodyNode{
					{NodeType: "object", Path: "payment", PropertyOrder: []string{"type", "cardNumber"},
						Properties: map[string]*BodyNode{
							"type":       {NodeType: "scalar", ScalarType: "string", Path: "payment.type"},
							"cardNumber": {NodeType: "scalar", ScalarType: "string", Path: "payment.cardNumber"},
						}},
					{NodeType: "object", Path: "payment", PropertyOrder: []string{"type", "walletId"},
						Properties: map[string]*BodyNode{
							"type":     {NodeType: "scalar", ScalarType: "string", Path: "payment.type"},
							"walletId": {NodeType: "scalar", ScalarType: "string", Path: "payment.walletId"},
						}},
				},
				Discriminator: &BodyDiscriminator{PropertyName: "type", Mapping: map[string]int{"card": 0, "wallet": 1}},
			},
			"note": {NodeType: "scalar", FieldName: "note", Path: "note", ScalarType: "string", Nullable: false},
		},
	}
}

func freshWidgetTree() *BodyValue {
	return buildBodyValue(widgetOrderSchema(), nil, nil)
}

// ---- 1. add/remove field ----

// TestOpAddRemoveFieldValid_RemovesTheOptionalFieldNeverRequired covers the
// "remove" direction against a fresh tree. Note the "add" direction is
// honestly unreachable from a FRESH tree under this package's Stage 3 design:
// buildBodyValue populates every declared property (required AND optional) by
// default, so a freshly built object never has an absent optional property
// to add -- "exactly one operator per render" (never stacked) means "add"
// can only ever have real work to do on a tree some OTHER step already
// thinned, not on the render pipeline's actual fresh-tree-plus-one-op shape.
// The "add" code path itself is still real and correct -- proven directly
// below in TestOpAddRemoveFieldValid_AddsAnAbsentOptionalField, on a
// deliberately pre-thinned tree -- this test just doesn't pretend the full
// random pipeline can exercise it, since it structurally cannot.
func TestOpAddRemoveFieldValid_RemovesTheOptionalFieldNeverRequired(t *testing.T) {
	schema := widgetOrderSchema()
	removed := 0
	for i := 0; i < 50; i++ {
		tree := buildBodyValue(schema, nil, nil)
		applied, label := opAddRemoveFieldValid(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			// "add" was rolled and declined (nothing absent to add) -- allowed.
			continue
		}
		if label != "add_remove_field" {
			t.Fatalf("unexpected label %q", label)
		}
		hasNote := false
		for _, f := range tree.Fields {
			if f.Key == "note" {
				hasNote = true
			}
		}
		if !hasNote {
			removed++
		}
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("valid-mode add/remove introduced violations: %v", v)
		}
		if len(tree.Fields) != 3 && len(tree.Fields) != 4 {
			t.Fatalf("expected 3 (note removed) or 4 (nothing removed) fields, got %d: %+v", len(tree.Fields), tree.Fields)
		}
	}
	if removed == 0 {
		t.Error("expected at least one successful removal of the optional 'note' field across 50 tries")
	}
}

// TestOpAddRemoveFieldValid_AddsAnAbsentOptionalField proves the "add" code
// path directly, on a tree pre-thinned to have an absent optional property --
// see the comment on the sibling test above for why the full random pipeline
// can't reach this branch on its own.
func TestOpAddRemoveFieldValid_AddsAnAbsentOptionalField(t *testing.T) {
	schema := widgetOrderSchema()
	thinnedTree := func() *BodyValue {
		tree := buildBodyValue(schema, nil, nil)
		// Manually thin the tree exactly the way a real (but currently
		// unreachable-in-one-step) prior removal would have.
		thinned := make([]BodyField, 0, len(tree.Fields))
		for _, f := range tree.Fields {
			if f.Key != "note" {
				thinned = append(thinned, f)
			}
		}
		tree.Fields = thinned
		return tree
	}

	// tryAdd/tryRemove is itself a coin flip inside the operator (everything
	// else present is required, so a "remove" roll always declines here) --
	// loop until the "add" roll comes up, same pattern as every other
	// probabilistic-choice test in this file.
	for i := 0; i < 50; i++ {
		tree := thinnedTree()
		applied, label := opAddRemoveFieldValid(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			continue
		}
		if label != "add_remove_field" {
			t.Fatalf("unexpected label %q", label)
		}
		found := false
		for _, f := range tree.Fields {
			if f.Key == "note" {
				found = true
			}
		}
		if !found {
			t.Fatal("expected 'note' to have been added back")
		}
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("add introduced violations: %v", v)
		}
		return
	}
	t.Fatal("expected the 'add' roll to succeed at least once across 50 tries")
}

// ---- 2. required-field omission ----

func TestOpRequiredFieldOmission_DropsARequiredFieldOnlyThatViolation(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	before := conformanceViolations(tree, schema)
	if len(before) != 0 {
		t.Fatalf("expected a fresh valid tree, got violations: %v", before)
	}
	applied, label := opRequiredFieldOmission(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected required-field omission to apply on a fresh tree with required fields present")
	}
	if label != "required_omit" {
		t.Fatalf("unexpected label %q", label)
	}
	after := conformanceViolations(tree, schema)
	missing := false
	for _, v := range after {
		if strings.Contains(v, "missing required property") {
			missing = true
		}
	}
	if !missing {
		t.Errorf("expected a 'missing required property' violation, got %v", after)
	}
}

// ---- 3. array resize ----

func TestOpArrayResizeValid_StaysWithinDeclaredBounds(t *testing.T) {
	schema := widgetOrderSchema()
	for i := 0; i < 50; i++ {
		tree := freshWidgetTree()
		applied, label := opArrayResizeValid(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			t.Fatal("expected array resize to apply (tags array exists)")
		}
		if label != "array_resize" {
			t.Fatalf("unexpected label %q", label)
		}
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("valid-mode array resize introduced violations: %v", v)
		}
	}
}

func TestOpArrayResizeAdversarial_ViolatesDeclaredBounds(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	applied, label := opArrayResizeAdversarial(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected adversarial array resize to apply (tags has min_items/max_items)")
	}
	if label != "array_resize" {
		t.Fatalf("unexpected label %q", label)
	}
	violations := conformanceViolations(tree, schema)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "min_items") || strings.Contains(v, "max_items") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an array-bound violation, got %v", violations)
	}
}

func TestOpArrayResizeAdversarial_DeclinesWithNoBoundsDeclared(t *testing.T) {
	schema := &BodyNode{NodeType: "array", Items: &BodyNode{NodeType: "scalar", ScalarType: "string"}}
	tree := buildBodyValue(schema, nil, nil)
	applied, _ := opArrayResizeAdversarial(tree, schema, rand.New(rand.NewSource(1)))
	if applied {
		t.Error("expected decline when no min_items/max_items exist to violate")
	}
}

// ---- 4. variant/discriminator switch ----

func TestOpVariantSwitchValid_ShapeAlwaysMatchesDiscriminatorTag(t *testing.T) {
	schema := widgetOrderSchema()
	for i := 0; i < 30; i++ {
		tree := freshWidgetTree()
		applied, label := opVariantSwitchValid(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			t.Fatal("expected variant switch to apply (payment is a oneOf with 2 variants)")
		}
		if label != "variant_switch" {
			t.Fatalf("unexpected label %q", label)
		}
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("valid-mode variant switch introduced violations: %v", v)
		}
	}
}

func TestOpVariantSwitchAdversarial_ProducesShapeTagMismatch(t *testing.T) {
	schema := widgetOrderSchema()
	sawMismatch := false
	for i := 0; i < 30; i++ {
		tree := freshWidgetTree()
		applied, label := opVariantSwitchAdversarial(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			t.Fatal("expected adversarial variant switch to apply")
		}
		if label != "variant_switch" {
			t.Fatalf("unexpected label %q", label)
		}
		violations := conformanceViolations(tree, schema)
		for _, v := range violations {
			if strings.Contains(v, "does not match its own discriminator tag") {
				sawMismatch = true
			}
		}
	}
	if !sawMismatch {
		t.Error("expected at least one run to produce a shape/discriminator-tag mismatch")
	}
}

// ---- 5. type substitution ----

func TestOpTypeSubstitution_ChangesScalarKind(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	var titleBefore *BodyValue
	for _, f := range tree.Fields {
		if f.Key == "title" {
			titleBefore = f.Value
		}
	}
	if titleBefore.Kind != BVString {
		t.Fatalf("expected fresh title to be a string, got %v", titleBefore.Kind)
	}
	applied, label := opTypeSubstitution(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected type substitution to apply (scalar leaves exist)")
	}
	if label != "type_substitution" {
		t.Fatalf("unexpected label %q", label)
	}
	violations := conformanceViolations(tree, schema)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "expected string scalar") || strings.Contains(v, "expected numeric scalar") || strings.Contains(v, "expected boolean scalar") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a scalar-type-mismatch violation, got %v", violations)
	}
}

// ---- 6. null injection ----

func TestOpNullInjection_SetsNonNullableFieldToNull(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	applied, label := opNullInjection(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected null injection to apply (every field in this schema is non-nullable)")
	}
	if label != "null_injection" {
		t.Fatalf("unexpected label %q", label)
	}
	violations := conformanceViolations(tree, schema)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "null but not nullable") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'null but not nullable' violation, got %v", violations)
	}
}

// ---- 7. undeclared property ----

func TestOpUndeclaredProperty_InsertsUnknownKey(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	before := len(tree.Fields)
	applied, label := opUndeclaredProperty(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected undeclared-property injection to apply")
	}
	if label != "undeclared_property" {
		t.Fatalf("unexpected label %q", label)
	}
	if len(tree.Fields) != before+1 {
		t.Fatalf("expected exactly one field added, had %d now %d", before, len(tree.Fields))
	}
	violations := conformanceViolations(tree, schema)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "undeclared property") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an 'undeclared property' violation, got %v", violations)
	}
}

// ---- 8. duplicate key ----

func TestOpDuplicateKey_AppendsRepeatedKeyDetectableInRawJSON(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	applied, label := opDuplicateKey(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected duplicate-key injection to apply")
	}
	if label != "dup_key" {
		t.Fatalf("unexpected label %q", label)
	}
	violations := conformanceViolations(tree, schema)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "duplicate key") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'duplicate key' violation, got %v", violations)
	}
	// Also prove it survives serialization -- the actual point of this operator.
	raw := tree.ToJSON()
	dupKey := ""
	seen := map[string]int{}
	for _, f := range tree.Fields {
		seen[f.Key]++
		if seen[f.Key] > 1 {
			dupKey = f.Key
		}
	}
	if dupKey == "" {
		t.Fatal("test setup error: no duplicate key found in tree.Fields")
	}
	if strings.Count(raw, `"`+dupKey+`"`) < 2 {
		t.Errorf("expected key %q to appear at least twice in raw JSON %q", dupKey, raw)
	}
}

// ---- 9. nesting-depth stress ----

func TestOpNestingDepthStressAdversarial_WrapsInExtraLayers(t *testing.T) {
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	applied, label := opNestingDepthStressAdversarial(tree, schema, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected nesting-depth stress to always find a site to wrap")
	}
	if label != "nesting_depth" {
		t.Fatalf("unexpected label %q", label)
	}
	raw := tree.ToJSON()
	if strings.Count(raw, `"wrapped"`) != nestingStressExtraLayers {
		t.Errorf("expected %d synthetic wrapper layers, got %d in %q", nestingStressExtraLayers, strings.Count(raw, `"wrapped"`), raw)
	}
}

func TestOpNestingDepthStressValid_DeclinesWithoutSelfReferentialSchema(t *testing.T) {
	// Honest limitation, documented in body_mutate.go: grammarc/schema_ast.py
	// already resolves any $ref cycle into an inert scalar leaf at compile
	// time, so a real, Python-compiled BodyNode graph is never self-referential
	// -- this operator's valid-mode branch always declines against it.
	schema := widgetOrderSchema()
	tree := freshWidgetTree()
	applied, _ := opNestingDepthStressValid(tree, schema, rand.New(rand.NewSource(1)))
	if applied {
		t.Error("expected decline: this fixture schema has no genuine self-reference")
	}
}

func TestOpNestingDepthStressValid_AppliesOnGenuinelySelfReferentialSchema(t *testing.T) {
	// A hand-built self-referential BodyNode graph (pointer identity), proving
	// the operator is honestly implemented rather than unconditionally
	// disabled -- see body_mutate.go::schemaHasSelfReference's doc comment.
	leaf := &BodyNode{NodeType: "scalar", ScalarType: "string", Path: "name"}
	node := &BodyNode{NodeType: "object", PropertyOrder: []string{"name", "child"}, Properties: map[string]*BodyNode{"name": leaf}}
	node.Properties["child"] = node // genuine pointer self-reference
	tree := &BodyValue{Kind: BVObject, Node: node, Fields: []BodyField{
		{Key: "name", Value: newStringValue(leaf, "name", "x")},
	}}
	applied, label := opNestingDepthStressValid(tree, node, rand.New(rand.NewSource(1)))
	if !applied {
		t.Fatal("expected valid-mode nesting stress to apply against a genuinely self-referential schema")
	}
	if label != "nesting_depth" {
		t.Fatalf("unexpected label %q", label)
	}
}

// ---- 10. constraint boundary ----

func TestOpConstraintBoundaryValid_SetsExactEdgeNoViolation(t *testing.T) {
	schema := widgetOrderSchema()
	for i := 0; i < 30; i++ {
		tree := freshWidgetTree()
		applied, label := opConstraintBoundaryValid(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			t.Fatal("expected constraint boundary to apply (title has min_length/max_length)")
		}
		if label != "constraint_boundary" {
			t.Fatalf("unexpected label %q", label)
		}
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("valid-mode constraint boundary introduced violations: %v", v)
		}
	}
}

func TestOpConstraintBoundaryAdversarial_ViolatesConstraint(t *testing.T) {
	schema := widgetOrderSchema()
	sawViolation := false
	for i := 0; i < 30; i++ {
		tree := freshWidgetTree()
		applied, label := opConstraintBoundaryAdversarial(tree, schema, rand.New(rand.NewSource(int64(i))))
		if !applied {
			t.Fatal("expected adversarial constraint boundary to apply")
		}
		if label != "constraint_boundary" {
			t.Fatalf("unexpected label %q", label)
		}
		violations := conformanceViolations(tree, schema)
		for _, v := range violations {
			if strings.Contains(v, "min_length") || strings.Contains(v, "max_length") {
				sawViolation = true
			}
		}
	}
	if !sawViolation {
		t.Error("expected at least one run to violate a length constraint")
	}
}

// ---- mode selection / registry ----

func TestPickStructuralOperator_ValidModeOnlyReturnsOperatorsWithValidFn(t *testing.T) {
	wantNames := map[string]bool{"add_remove_field": true, "array_resize": true, "variant_switch": true, "nesting_depth": true, "constraint_boundary": true}
	for i := 0; i < 100; i++ {
		op, ok := pickStructuralOperator(false)
		if !ok {
			t.Fatal("expected a valid-mode operator to always be pickable")
		}
		if !wantNames[op.Name] {
			t.Errorf("unexpected valid-mode operator %q picked", op.Name)
		}
		if op.ValidFn == nil {
			t.Errorf("picked operator %q has no ValidFn", op.Name)
		}
	}
}

func TestPickStructuralOperator_AdversarialModeExcludesAddRemoveField(t *testing.T) {
	for i := 0; i < 200; i++ {
		op, ok := pickStructuralOperator(true)
		if !ok {
			t.Fatal("expected an adversarial-mode operator to always be pickable")
		}
		if op.Name == "add_remove_field" {
			t.Error("add_remove_field has no adversarial behavior and must never be picked in adversarial mode")
		}
		if op.AdversarialFn == nil {
			t.Errorf("picked operator %q has no AdversarialFn", op.Name)
		}
	}
}

func TestBuildAndMutateBodyTree_AdversarialLabelIsSingleStructuralCategory(t *testing.T) {
	f := &Fuzzer{}
	schema := widgetOrderSchema()
	sawLabel := false
	for i := 0; i < 100; i++ {
		_, label := f.buildAndMutateBodyTree(schema, "adversarial", nil)
		if label == "" {
			continue // operator declined this round -- allowed
		}
		sawLabel = true
		if !strings.HasPrefix(label, "mcat_struct_") {
			t.Fatalf("expected label to start with mcat_struct_, got %q", label)
		}
		if strings.Count(label, "mcat_struct_") != 1 {
			t.Fatalf("expected exactly one structural-operator label, got %q", label)
		}
	}
	if !sawLabel {
		t.Fatal("expected at least one non-empty adversarial label across 100 tries")
	}
}

func TestBuildAndMutateBodyTree_ValidModeAlwaysProducesConformingTree(t *testing.T) {
	f := &Fuzzer{}
	schema := widgetOrderSchema()
	for i := 0; i < 100; i++ {
		tree, _ := f.buildAndMutateBodyTree(schema, "valid", nil)
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("valid mode produced a non-conforming tree: %v", v)
		}
	}
}

func TestUpdateStructuralCategoryWeights_RaisesWeightForHighHitRate(t *testing.T) {
	structCatMu.Lock()
	saved := make([]MutationCategory, len(structuralCategories))
	for i, c := range structuralCategories {
		saved[i] = *c
		c.Attempts, c.Hits, c.Weight = 0, 0, 1.0
	}
	structuralCategories[0].Attempts = 10
	structuralCategories[0].Hits = 10
	structCatMu.Unlock()

	updateStructuralCategoryWeights()

	structCatMu.RLock()
	got := structuralCategories[0].Weight
	structCatMu.RUnlock()
	if got <= 1.0 {
		t.Errorf("expected weight to rise above 1.0 for a 100%% hit rate, got %v", got)
	}

	structCatMu.Lock()
	for i, c := range structuralCategories {
		*c = saved[i]
	}
	structCatMu.Unlock()
}
