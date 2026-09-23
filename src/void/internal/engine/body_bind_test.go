package engine

import (
	"testing"

	"void/internal/config"
)

// customerIdentity mirrors userIdentity/orderIdentity (resource_graph_test.go)
// for a "customer" resource type, used by the tenant-scoped binding tests
// below.
func customerIdentity(raw string) ResourceIdentity {
	return ResourceIdentity{
		ResourceType:    "customer",
		IdentityKind:    "scalar",
		NormalizedValue: normalizeResourceValue("customer", "scalar", raw),
		RawValue:        raw,
		SourcePath:      "$.id",
		Confidence:      0.8,
	}
}

// customerIDNode is a scalar leaf shaped the way schema_ast.py emits a
// nested id-shaped field: PayloadKey canonicalizes to something
// resourceTypeFromKeyName can strip an "id" suffix from ("customer").
func customerIDNode(path string) *BodyNode {
	return &BodyNode{NodeType: "scalar", FieldName: "customerId", Path: path, ScalarType: "string", PayloadKey: "customerId"}
}

func TestBindLeaf_PathQualifiedTierWinsOverTenantAndFlat(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore(), dict: &DictStore{}}
	f.runtime.recordPathValue("customer.order.customerId", "cust-path-1")

	bind := f.newBodyBindCtx(nil)
	node := customerIDNode("order.customerId")

	v, label, ok := bind.bindLeaf(node)
	if !ok {
		t.Fatal("expected bindLeaf to resolve via the path-qualified tier")
	}
	if v != "cust-path-1" {
		t.Errorf("expected the path-qualified value, got %q", v)
	}
	if label != "bodypath_customer" {
		t.Errorf("expected label bodypath_customer, got %q", label)
	}
}

func TestBindLeaf_TenantScopedResourceGraphFallsBackWhenNoPathValue(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	inst := g.recordInstance(customerIdentity("cust-tenant-a"), "POST /customers", "seq-1", LifecycleCreated, 0.9)
	inst.TenantKey = "tenant-a"

	f := &Fuzzer{
		runtime:       newRuntimeStore(),
		dict:          &DictStore{},
		resourceGraph: g,
		cfg:           config.Config{ResourceGraphEnabled: true},
	}
	ctx := &WorkItem{SeqState: &SequenceState{TenantKey: "tenant-a"}}
	bind := f.newBodyBindCtx(ctx)
	node := customerIDNode("order.customerId")

	v, label, ok := bind.bindLeaf(node)
	if !ok {
		t.Fatal("expected bindLeaf to resolve via the tenant-scoped resource graph tier")
	}
	if v != "cust-tenant-a" {
		t.Errorf("expected the tenant-scoped instance's value, got %q", v)
	}
	if label != "bodytenant_customer" {
		t.Errorf("expected label bodytenant_customer, got %q", label)
	}
}

func TestBindLeaf_CrossTenantResourceInstanceIsExcluded(t *testing.T) {
	g := newResourceGraph(ResourceGraphLimits{})
	inst := g.recordInstance(customerIdentity("cust-tenant-b"), "POST /customers", "seq-1", LifecycleCreated, 0.9)
	inst.TenantKey = "tenant-b" // a DIFFERENT tenant from the render context below

	f := &Fuzzer{
		runtime:       newRuntimeStore(),
		dict:          &DictStore{},
		resourceGraph: g,
		cfg:           config.Config{ResourceGraphEnabled: true},
	}
	ctx := &WorkItem{SeqState: &SequenceState{TenantKey: "tenant-a"}}
	bind := f.newBodyBindCtx(ctx)
	node := customerIDNode("order.customerId")

	_, label, ok := bind.bindLeaf(node)
	if ok && label == "bodytenant_customer" {
		t.Fatalf("expected the cross-tenant instance to be excluded from tier 2, got value bound via %q", label)
	}
}

func TestBindLeaf_FlatDictPoolIsFinalFallback(t *testing.T) {
	f := &Fuzzer{
		runtime: newRuntimeStore(),
		dict:    &DictStore{arrays: map[string][]string{"customerid": {"cust-from-dict"}}},
		cfg:     config.Config{ResourceGraphEnabled: false},
	}
	bind := f.newBodyBindCtx(nil)
	node := customerIDNode("order.customerId")

	// customPayloadCandidates (store.go) mixes the dict-sourced value in with
	// synthetic mutateBusinessID candidates for any "*id"-suffixed key, so the
	// exact value drawn is randomized -- only the tier (via the label) and
	// non-emptiness are asserted here.
	v, label, ok := bind.bindLeaf(node)
	if !ok {
		t.Fatal("expected bindLeaf to resolve via the flat dict fallback tier")
	}
	if v == "" {
		t.Error("expected a non-empty value from the flat dict fallback tier")
	}
	if label != "dict_customerId" {
		t.Errorf("expected label dict_customerId, got %q", label)
	}
}

func TestBindLeaf_DeclinesForNonIDShapedField(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore(), dict: &DictStore{}}
	bind := f.newBodyBindCtx(nil)
	node := &BodyNode{NodeType: "scalar", FieldName: "title", Path: "title", ScalarType: "string"} // no PayloadKey

	if _, _, ok := bind.bindLeaf(node); ok {
		t.Error("expected bindLeaf to decline a field with no PayloadKey")
	}
}

func TestBindLeaf_NilRuntimeDeclinesInsteadOfPanicking(t *testing.T) {
	f := &Fuzzer{} // zero-value Fuzzer: runtime, dict, resourceGraph all nil
	bind := f.newBodyBindCtx(nil)
	node := customerIDNode("order.customerId")

	if _, _, ok := bind.bindLeaf(node); ok {
		t.Error("expected bindLeaf to decline gracefully on a nil-runtime Fuzzer")
	}
}

func TestNewBodyBindCtx_TenantKeyEmptyWithoutSeqState(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore()}
	if bind := f.newBodyBindCtx(nil); bind.tenantKey != "" {
		t.Errorf("expected empty tenantKey for a nil WorkItem, got %q", bind.tenantKey)
	}
	if bind := f.newBodyBindCtx(&WorkItem{}); bind.tenantKey != "" {
		t.Errorf("expected empty tenantKey for a WorkItem with no SeqState, got %q", bind.tenantKey)
	}
}

// TestBodyLeafValueForBind_NonNumericBoundValueOnIntegerFieldStaysQuoted is a
// regression pin for a real bug found via a real-grammar stress pass: a
// resource-graph/runtime-observed value like "REF-9581" bound onto a
// schema-integer field must serialize as a quoted string (BVString), not be
// forced into BVNumber -- BVNumber writes its text unquoted, so an
// alphanumeric ID there would emit invalid JSON (`"authorUserId":REF-9581`).
func TestBodyLeafValueForBind_NonNumericBoundValueOnIntegerFieldStaysQuoted(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore(), dict: &DictStore{}}
	f.runtime.recordPathValue("customer.customerId", "REF-9581")
	bind := f.newBodyBindCtx(nil)
	leafFn := bodyLeafValueForBind(bind)

	node := &BodyNode{NodeType: "scalar", FieldName: "customerId", Path: "customerId", ScalarType: "integer", PayloadKey: "customerId"}
	v, kind := leafFn(node)
	if v != "REF-9581" {
		t.Fatalf("expected the bound value REF-9581, got %q", v)
	}
	if kind != BVString {
		t.Fatalf("expected a non-numeric bound value to serialize as BVString, got kind=%v", kind)
	}

	bv := newStringValue(node, node.Path, v)
	if bv.Kind != BVString {
		t.Fatal("sanity: constructed value should be BVString")
	}
	if got := bv.ToJSON(); got != `"REF-9581"` {
		t.Errorf("expected quoted JSON output, got %s", got)
	}
}

func TestBodyLeafValueForBind_UsesBoundValueThenFallsBackToDefault(t *testing.T) {
	f := &Fuzzer{runtime: newRuntimeStore(), dict: &DictStore{}}
	f.runtime.recordPathValue("customer.order.customerId", "cust-bound")
	bind := f.newBodyBindCtx(nil)
	leafFn := bodyLeafValueForBind(bind)

	boundVal, kind := leafFn(customerIDNode("order.customerId"))
	if boundVal != "cust-bound" || kind != BVString {
		t.Errorf("expected the bound value to win, got (%q, %v)", boundVal, kind)
	}

	// A field bindLeaf declines (no PayloadKey) must fall through to
	// defaultLeafValue's pure schema-derived synthesis, not an empty value.
	fallbackVal, _ := leafFn(&BodyNode{NodeType: "scalar", FieldName: "title", Path: "title", ScalarType: "string"})
	if fallbackVal == "" {
		t.Error("expected a non-empty synthesized default for a field with no binding")
	}
}
