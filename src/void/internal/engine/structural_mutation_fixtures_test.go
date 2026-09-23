package engine

import (
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"void/internal/config"
)

// structural_mutation_fixtures_test.go — Stage 8: the end-to-end proof for
// typed structural mutation (requirement #10's E2E fixture, per the approved
// plan). Follows the house pattern already established by
// stateful_security_fixtures_test.go: a real httptest.Server, real engine
// machinery, no fabricated results -- but additionally, and unlike that
// file, starts from the REAL Python compiler (testdata/structural_mutation_
// fixture.swagger.json compiled via the real `python3 -m grammarc.cli`, then
// loaded through the real loadTemplates()) so this proves the actual
// Python -> Go pipe end to end, not two independently hand-authored halves.
//
// CI wiring: run explicitly by .github/workflows/e2e.yml's "Structural
// mutation E2E fixture" step, mirroring the existing "Stateful-security E2E
// fixture matrix" step, so a regression here fails as its own named gate.

// compileStructuralMutationFixtureTemplates shells out to the real grammar
// compiler (same invocation compile-grammar.sh itself uses) against the
// checked-in fixture spec, then loads its real output through the real Go
// loader -- proving the Python AST shape (schema_ast.py) and the Go decode
// (body_schema.go) agree with each other, not just with themselves.
func compileStructuralMutationFixtureTemplates(t *testing.T) []Template {
	t.Helper()
	specPath, err := filepath.Abs("testdata/structural_mutation_fixture.swagger.json")
	if err != nil {
		t.Fatalf("resolving fixture spec path: %v", err)
	}
	outDir := t.TempDir()
	grammarDir, err := filepath.Abs("../../../../tools/grammar")
	if err != nil {
		t.Fatalf("resolving tools/grammar path: %v", err)
	}

	cmd := exec.Command("python3", "-m", "grammarc.cli", "--swagger", specPath, "--out", outDir)
	cmd.Dir = grammarDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 -m grammarc.cli failed: %v\n%s", err, out)
	}

	tmpls, err := loadTemplates(filepath.Join(outDir, "templates.export.json"))
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	return tmpls
}

func orderCreateBodySchema(t *testing.T, tmpls []Template) *BodyNode {
	t.Helper()
	for _, tp := range tmpls {
		if strings.Contains(tp.RequestID, "createOrder") || (tp.BodySchema != nil && tp.BodySchema.Properties != nil && tp.BodySchema.Properties["customerId"] != nil) {
			if tp.BodySchema != nil {
				return tp.BodySchema
			}
		}
	}
	t.Fatal("expected to find the createOrder template's body_schema among the compiled templates")
	return nil
}

func TestStructuralMutationFixture_PythonPipelineEmitsSchemaAndLegacySegmentsTogether(t *testing.T) {
	tmpls := compileStructuralMutationFixtureTemplates(t)
	if len(tmpls) != 2 {
		t.Fatalf("expected 2 compiled templates (POST + GET), got %d", len(tmpls))
	}

	var createTpl *Template
	for i := range tmpls {
		if tmpls[i].BodySchema != nil {
			createTpl = &tmpls[i]
		}
	}
	if createTpl == nil {
		t.Fatal("expected exactly one template (createOrder) to carry a body_schema")
	}

	// Backward compatibility, concretely: the legacy flat segments[] must
	// still be emitted unconditionally alongside body_schema, not replaced by
	// it -- old renderers reading only Segments must see the exact same thing
	// they always have.
	if len(createTpl.Segments) == 0 {
		t.Error("expected the legacy segments[] to still be populated alongside body_schema")
	}

	schema := createTpl.BodySchema
	if schema.NodeType != "object" {
		t.Fatalf("expected root node_type=object, got %q", schema.NodeType)
	}
	for _, want := range []string{"customerId", "title", "tags", "shippingAddress", "items", "payment", "note"} {
		if _, ok := schema.Properties[want]; !ok {
			t.Errorf("expected root property %q, got properties %v", want, mapKeysOf(schema.Properties))
		}
	}
	cust := schema.Properties["customerId"]
	if cust.PayloadKey == "" {
		t.Error("expected customerId to carry a PayloadKey (id-shaped field name)")
	}
	addr := schema.Properties["shippingAddress"]
	if addr.NodeType != "object" || addr.Properties["city"] == nil {
		t.Fatalf("expected shippingAddress to be a nested object with a city property, got %+v", addr)
	}
	if addr.Properties["city"].MinLength == nil || *addr.Properties["city"].MinLength != 2 {
		t.Error("expected shippingAddress.city minLength=2 to survive compilation")
	}
	items := schema.Properties["items"]
	if items.NodeType != "array" || items.Items == nil || items.Items.NodeType != "object" {
		t.Fatalf("expected items to be an array-of-objects, got %+v", items)
	}
	if items.Items.Properties["qty"] == nil || items.Items.Properties["qty"].Maximum == nil {
		t.Error("expected items[].qty to carry its maximum constraint")
	}
	payment := schema.Properties["payment"]
	if payment.NodeType != "oneOf" || len(payment.Variants) != 2 {
		t.Fatalf("expected payment to be a 2-variant oneOf, got %+v", payment)
	}
	if payment.Discriminator == nil || payment.Discriminator.PropertyName != "type" {
		t.Fatalf("expected an explicit discriminator on propertyName=type, got %+v", payment.Discriminator)
	}
	if len(payment.Discriminator.Mapping) != 2 {
		t.Errorf("expected both card/wallet discriminator tags mapped, got %v", payment.Discriminator.Mapping)
	}
}

func mapKeysOf(m map[string]*BodyNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestStructuralMutationFixture_ValidModeAlwaysProducesConformingNestedRequests(t *testing.T) {
	tmpls := compileStructuralMutationFixtureTemplates(t)
	schema := orderCreateBodySchema(t, tmpls)
	f := &Fuzzer{}

	for i := 0; i < 200; i++ {
		tree, _ := f.buildAndMutateBodyTree(schema, "valid", nil)
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("valid mode produced a non-conforming nested tree: %v\njson=%s", v, tree.ToJSON())
		}
	}
}

func TestStructuralMutationFixture_AllTenOperatorLabelsFireAcrossManyRenders(t *testing.T) {
	tmpls := compileStructuralMutationFixtureTemplates(t)
	schema := orderCreateBodySchema(t, tmpls)
	f := &Fuzzer{}

	seen := map[string]bool{}
	for i := 0; i < 4000; i++ {
		mode := "valid"
		if i%2 == 0 {
			mode = "adversarial"
		}
		_, label := f.buildAndMutateBodyTree(schema, mode, nil)
		if label == "" {
			continue
		}
		name := strings.TrimPrefix(label, "mcat_struct_")
		seen[name] = true
	}

	for _, op := range structuralOps {
		if !seen[op.Name] {
			t.Errorf("operator %q never fired across 4000 renders against the real compiled schema", op.Name)
		}
	}
}

func TestStructuralMutationFixture_DiscriminatorSwitchProducesAValidAlternateVariant(t *testing.T) {
	tmpls := compileStructuralMutationFixtureTemplates(t)
	schema := orderCreateBodySchema(t, tmpls)
	f := &Fuzzer{}

	sawCard, sawWallet := false, false
	for i := 0; i < 200; i++ {
		tree, _ := f.buildAndMutateBodyTree(schema, "valid", nil)
		opVariantSwitchValid(tree, schema, rand.New(rand.NewSource(int64(i))))
		if v := conformanceViolations(tree, schema); len(v) != 0 {
			t.Fatalf("variant-switched tree failed to conform: %v\njson=%s", v, tree.ToJSON())
		}
		js := tree.ToJSON()
		if strings.Contains(js, `"type":"card"`) && strings.Contains(js, "cardNumber") {
			sawCard = true
		}
		if strings.Contains(js, `"type":"wallet"`) && strings.Contains(js, "walletId") {
			sawWallet = true
		}
	}
	if !sawCard || !sawWallet {
		t.Errorf("expected both discriminator variants to appear (card=%v wallet=%v)", sawCard, sawWallet)
	}
}

func TestStructuralMutationFixture_TenantBoundCustomerIdNeverCrossesTenants(t *testing.T) {
	tmpls := compileStructuralMutationFixtureTemplates(t)
	schema := orderCreateBodySchema(t, tmpls)

	g := newResourceGraph(ResourceGraphLimits{})
	custA := g.recordInstance(customerIdentity("cust-org-a"), "POST /customers", "seq-a", LifecycleCreated, 0.9)
	custA.TenantKey = "org-a"
	custB := g.recordInstance(customerIdentity("cust-org-b"), "POST /customers", "seq-b", LifecycleCreated, 0.9)
	custB.TenantKey = "org-b"

	f := &Fuzzer{
		runtime:       newRuntimeStore(),
		dict:          &DictStore{},
		resourceGraph: g,
		cfg:           config.Config{ResourceGraphEnabled: true},
	}
	ctx := &WorkItem{SeqState: &SequenceState{TenantKey: "org-a"}}

	for i := 0; i < 100; i++ {
		tree, _ := f.buildAndMutateBodyTree(schema, "valid", ctx)
		js := tree.ToJSON()
		if strings.Contains(js, "cust-org-b") {
			t.Fatalf("a request scoped to tenant org-a bound the OTHER tenant's customer id: %s", js)
		}
	}
}

func TestStructuralMutationFixture_PlantedCrashMinimizesToMinimalReproducingItemsLength(t *testing.T) {
	tmpls := compileStructuralMutationFixtureTemplates(t)
	schema := orderCreateBodySchema(t, tmpls)

	// Planted bug: the order handler 500s once an order has MORE THAN 3 line
	// items -- an artificial but concrete "business logic" crash a purely
	// schema-conformance-checking client would never catch on its own,
	// exactly the class of bug typed valid-mode requests exist to reach.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Items []any `json:"items"`
		}
		buf, _ := io.ReadAll(r.Body)
		if json.Unmarshal(buf, &body) == nil && len(body.Items) > 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"order-1"}`))
	}))
	t.Cleanup(srv.Close)

	f := &Fuzzer{
		runtime: newRuntimeStore(),
		dict:    &DictStore{},
		cfg:     config.Config{MinimizeMaxProbes: 200},
		target:  srv.URL,
		client:  srv.Client(),
	}

	tree, _ := f.buildAndMutateBodyTree(schema, "valid", nil)
	itemsField := findObjectField(tree, "items")
	if itemsField == nil {
		t.Fatal("expected the built tree to carry an items field")
	}
	resizeArray(itemsField, 5) // 5 > 3 -- triggers the planted bug

	item := WorkItem{Method: "POST", Path: "/organizations/org-1/orders", BodyTree: tree, Body: tree.ToJSON()}
	got, changed, probes := f.minimizeCrashCandidate(item, http.StatusInternalServerError)
	if probes == 0 {
		t.Fatal("expected at least one minimization probe")
	}
	if !changed {
		t.Fatal("expected minimization to shrink the crashing request")
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(got.Body), &obj); err != nil {
		t.Fatalf("minimized body is not valid JSON: %v (%q)", err, got.Body)
	}
	items, ok := obj["items"].([]any)
	if !ok {
		t.Fatalf("expected items to survive minimization, got %v", obj)
	}
	if len(items) != 4 {
		t.Errorf("expected the minimal still-crashing item count (4, one past the >3 threshold), got %d", len(items))
	}
	// The planted bug depends on nothing but the items array's length -- a
	// faithful black-box minimizer correctly drops every other field too
	// (customerId/title/payment all disappear here), since they have zero
	// bearing on reproduction. That's the minimizer doing its job, not a
	// gap: it found an even smaller reproducer than "keep everything except
	// items" would have.
	if len(obj) != 1 {
		t.Errorf("expected every field irrelevant to reproduction to be dropped too, got %v", obj)
	}
}

func findObjectField(v *BodyValue, key string) *BodyValue {
	if v == nil || v.Kind != BVObject {
		return nil
	}
	for _, f := range v.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return nil
}
