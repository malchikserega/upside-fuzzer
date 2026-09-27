package engine

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
)

// body_mutate.go — the 10 typed structural mutation operators (requirement
// #4), "valid" vs. "adversarial" mode selection (requirement #3), and their
// own sibling MOpt-style adaptive-weight registry (requirement #7).
//
// Adversarial mode applies EXACTLY ONE operator per render: buildAndMutateBodyTree
// calls the chosen operator's function once and returns immediately, whether
// it succeeded or declined -- no retry loop, no stacking (deliberately does
// not mirror mutateHavoc's existing multi-round stacking elsewhere in this
// codebase, which is a different, byte-level concern).

type bodyOpFn func(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (ok bool, label string)

// structuralOperator names an operator once for both its valid and adversarial
// behavior (when it has one of each) -- MOpt weight tracking is per-name, not
// per-mode, since "how often did structural work targeting this schema
// feature find new coverage" is the signal that matters, regardless of which
// mode produced it.
type structuralOperator struct {
	Name          string
	ValidFn       bodyOpFn // nil if this operator has no meaningful valid-mode behavior
	AdversarialFn bodyOpFn // nil if this operator has no meaningful adversarial-mode behavior
}

var structuralOps = []structuralOperator{
	{Name: "add_remove_field", ValidFn: opAddRemoveFieldValid, AdversarialFn: nil},
	{Name: "required_omit", ValidFn: nil, AdversarialFn: opRequiredFieldOmission},
	{Name: "array_resize", ValidFn: opArrayResizeValid, AdversarialFn: opArrayResizeAdversarial},
	{Name: "variant_switch", ValidFn: opVariantSwitchValid, AdversarialFn: opVariantSwitchAdversarial},
	{Name: "type_substitution", ValidFn: nil, AdversarialFn: opTypeSubstitution},
	{Name: "null_injection", ValidFn: nil, AdversarialFn: opNullInjection},
	{Name: "undeclared_property", ValidFn: nil, AdversarialFn: opUndeclaredProperty},
	{Name: "dup_key", ValidFn: nil, AdversarialFn: opDuplicateKey},
	{Name: "nesting_depth", ValidFn: opNestingDepthStressValid, AdversarialFn: opNestingDepthStressAdversarial},
	{Name: "constraint_boundary", ValidFn: opConstraintBoundaryValid, AdversarialFn: opConstraintBoundaryAdversarial},
}

// structuralCategories is a SEPARATE, sibling registry from mutations.go's
// mutationCategories -- deliberately not appended into that shared slice.
// mutation_engine.go::mutateStringCategorized calls pickMutationCategory() and
// unconditionally indexes cat.Payloads[rand.Intn(len(cat.Payloads))]; a
// structural category has no Payloads (it's not a string-payload pool), so
// sharing the registry would let an ordinary string-segment mutation
// anywhere in the fuzzer draw a structural entry and panic on
// rand.Intn(0). Same MutationCategory struct/weight formula, own slice, own
// pick/record/update functions below -- zero lines of mutations.go touched.
var (
	structuralCategories []*MutationCategory
	structCatMu          sync.RWMutex
)

func init() {
	structuralCategories = make([]*MutationCategory, 0, len(structuralOps))
	for _, op := range structuralOps {
		structuralCategories = append(structuralCategories, &MutationCategory{Name: op.Name, Weight: 1.0})
	}
}

func structuralOpsWithFn(pickAdversarial bool) []structuralOperator {
	out := make([]structuralOperator, 0, len(structuralOps))
	for _, op := range structuralOps {
		if pickAdversarial {
			if op.AdversarialFn != nil {
				out = append(out, op)
			}
		} else if op.ValidFn != nil {
			out = append(out, op)
		}
	}
	return out
}

// pickStructuralOperator/pickValidStructuralOperator: MOpt-style weighted
// random selection, restricted to operators that actually have a function for
// the requested mode -- mirrors mutations.go::pickMutationCategory's formula
// exactly, against structuralCategories instead of mutationCategories.
func pickStructuralOperator(pickAdversarial bool) (structuralOperator, bool) {
	candidates := structuralOpsWithFn(pickAdversarial)
	if len(candidates) == 0 {
		return structuralOperator{}, false
	}
	structCatMu.RLock()
	weights := make([]float64, len(candidates))
	total := 0.0
	for i, op := range candidates {
		w := 1.0
		for _, c := range structuralCategories {
			if c.Name == op.Name {
				w = c.Weight
				break
			}
		}
		weights[i] = w
		total += w
	}
	structCatMu.RUnlock()
	if total <= 0 {
		return candidates[rand.Intn(len(candidates))], true
	}
	r := rand.Float64() * total
	for i, w := range weights {
		r -= w
		if r <= 0 {
			return candidates[i], true
		}
	}
	return candidates[len(candidates)-1], true
}

func updateStructuralCategoryWeights() {
	structCatMu.Lock()
	defer structCatMu.Unlock()
	for _, c := range structuralCategories {
		if c.Attempts == 0 {
			continue
		}
		hitRate := float64(c.Hits) / float64(c.Attempts)
		c.Weight = 1.0 + hitRate*4.0
	}
}

func recordStructuralCategoryHit(label string) {
	structCatMu.Lock()
	defer structCatMu.Unlock()
	for _, c := range structuralCategories {
		if strings.Contains(label, "mcat_struct_"+c.Name) {
			c.Hits++
			return
		}
	}
}

func recordStructuralCategoryAttempt(label string) {
	structCatMu.Lock()
	defer structCatMu.Unlock()
	for _, c := range structuralCategories {
		if strings.Contains(label, "mcat_struct_"+c.Name) {
			c.Attempts++
			return
		}
	}
}

// buildAndMutateBodyTree is renderTemplateContext's entry point into the
// typed body path. mode is "valid" or "adversarial" (chosen by the caller via
// -adversarial-body-rate). "Exactly one violation" (requirement #3/#4) is
// enforced here structurally, not probabilistically: the adversarial branch
// calls its chosen operator's function exactly once and returns immediately
// whether it succeeded or declined -- no retry, no stacking.
func (f *Fuzzer) buildAndMutateBodyTree(node *BodyNode, mode string, ctx *WorkItem) (*BodyValue, string) {
	bind := f.newBodyBindCtx(ctx)
	tree := buildBodyValue(node, bodyLeafValueForBind(bind), nil)

	if mode == "valid" {
		if rand.Float64() < 0.30 {
			if op, ok := pickStructuralOperator(false); ok {
				if applied, label := op.ValidFn(tree, node, rand.New(rand.NewSource(rand.Int63()))); applied {
					return tree, "mcat_struct_" + label
				}
			}
		}
		return tree, ""
	}

	op, ok := pickStructuralOperator(true)
	if !ok {
		return tree, ""
	}
	applied, label := op.AdversarialFn(tree, node, rand.New(rand.NewSource(rand.Int63())))
	if !applied {
		return tree, ""
	}
	return tree, "mcat_struct_" + label
}

// ---- shared site-collection helper ----

// bodySite is one co-walked (schema, value) position in a freshly-built tree.
// The co-walk assumes schema and value are still structurally parallel, which
// is only guaranteed immediately after buildBodyValue -- exactly when every
// operator above runs (exactly once, on a fresh tree, never on an
// already-mutated one). Every caller of collectBodySites passes a real root
// setter (`func(nv *BodyValue) { *tree = *nv }`), so set is never nil for any
// site, including the root -- found the hard way: an earlier version left the
// root setter nil, and opNestingDepthStressValid's own test (a genuinely
// self-referential fixture, which is exactly the case where the ONLY
// matching site can be the root) segfaulted calling a nil site.set.
type bodySite struct {
	schema *BodyNode
	value  *BodyValue
	set    func(*BodyValue)
}

// collectBodySites co-walks schema/value and returns every site matching
// filter (nil = every site). Deliberately does not recurse past a oneOf/anyOf
// schema node: buildBodyValue's oneOf/anyOf branch returns whichever variant
// it chose, discarding which one -- so schema (still "oneOf") and value
// (already "object", the chosen variant's shape) genuinely diverge below that
// point, with no reliable way to re-derive which variant produced it. A
// oneOf/anyOf site itself is still collected (opVariantSwitch's target);
// fields nested inside a polymorphic sub-object are out of reach for every
// OTHER operator -- a disclosed v1 scope limit, not silent data loss.
func collectBodySites(schema *BodyNode, value *BodyValue, set func(*BodyValue), filter func(*bodySite) bool) []bodySite {
	var out []bodySite
	var walk func(schema *BodyNode, value *BodyValue, set func(*BodyValue))
	walk = func(schema *BodyNode, value *BodyValue, set func(*BodyValue)) {
		if schema == nil || value == nil {
			return
		}
		site := bodySite{schema: schema, value: value, set: set}
		if filter == nil || filter(&site) {
			out = append(out, site)
		}
		if schema.NodeType == "oneOf" || schema.NodeType == "anyOf" {
			return
		}
		switch value.Kind {
		case BVObject:
			for i := range value.Fields {
				idx := i
				propName := value.Fields[idx].Key
				childSchema, ok := schema.Properties[propName]
				if !ok {
					continue
				}
				walk(childSchema, value.Fields[idx].Value, func(nv *BodyValue) { value.Fields[idx].Value = nv })
			}
		case BVArray:
			for i := range value.Items {
				idx := i
				walk(schema.Items, value.Items[idx], func(nv *BodyValue) { value.Items[idx] = nv })
			}
		}
	}
	walk(schema, value, set)
	return out
}

func pickSite(sites []bodySite, rng *rand.Rand) (bodySite, bool) {
	if len(sites) == 0 {
		return bodySite{}, false
	}
	return sites[rng.Intn(len(sites))], true
}

// ---- 1. add/remove field (valid only) ----

func opAddRemoveFieldValid(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool { return s.schema.NodeType == "object" })
	if len(sites) == 0 {
		return false, ""
	}
	// Shuffle so a site with no eligible action doesn't block every other site.
	rng.Shuffle(len(sites), func(i, j int) { sites[i], sites[j] = sites[j], sites[i] })
	tryAdd := rng.Intn(2) == 0
	for _, site := range sites {
		present := map[string]bool{}
		for _, f := range site.value.Fields {
			present[f.Key] = true
		}
		if tryAdd {
			for _, name := range site.schema.PropertyOrder {
				if present[name] {
					continue
				}
				child := site.schema.Properties[name]
				site.value.Fields = append(site.value.Fields, BodyField{Key: name, Value: buildBodyValue(child, nil, nil)})
				return true, "add_remove_field"
			}
		} else {
			required := map[string]bool{}
			for _, r := range site.schema.Required {
				required[r] = true
			}
			for i, f := range site.value.Fields {
				if required[f.Key] {
					continue
				}
				site.value.Fields = append(site.value.Fields[:i], site.value.Fields[i+1:]...)
				return true, "add_remove_field"
			}
		}
	}
	return false, ""
}

// ---- 2. required-field omission (adversarial only) ----

func opRequiredFieldOmission(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool {
		return s.schema.NodeType == "object" && len(s.schema.Required) > 0
	})
	rng.Shuffle(len(sites), func(i, j int) { sites[i], sites[j] = sites[j], sites[i] })
	for _, site := range sites {
		required := map[string]bool{}
		for _, r := range site.schema.Required {
			required[r] = true
		}
		for i, f := range site.value.Fields {
			if !required[f.Key] {
				continue
			}
			site.value.Fields = append(site.value.Fields[:i], site.value.Fields[i+1:]...)
			return true, "required_omit"
		}
	}
	return false, ""
}

// ---- 3. array resize ----

func opArrayResizeValid(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool { return s.schema.NodeType == "array" })
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	n := len(site.value.Items)
	min, max := 0, n+2
	if site.schema.MinItems != nil {
		min = *site.schema.MinItems
	}
	if site.schema.MaxItems != nil {
		max = *site.schema.MaxItems
	}
	if max < min {
		max = min
	}
	target := min
	if max > min {
		target = min + rng.Intn(max-min+1)
	}
	resizeArray(site.value, target)
	return true, "array_resize"
}

func opArrayResizeAdversarial(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool {
		return s.schema.NodeType == "array" && (s.schema.MinItems != nil || s.schema.MaxItems != nil)
	})
	rng.Shuffle(len(sites), func(i, j int) { sites[i], sites[j] = sites[j], sites[i] })
	for _, site := range sites {
		if site.schema.MinItems != nil && *site.schema.MinItems > 0 {
			resizeArray(site.value, *site.schema.MinItems-1)
			return true, "array_resize"
		}
		if site.schema.MaxItems != nil {
			resizeArray(site.value, *site.schema.MaxItems+1)
			return true, "array_resize"
		}
	}
	return false, ""
}

func resizeArray(arr *BodyValue, n int) {
	if n < 0 {
		n = 0
	}
	for len(arr.Items) < n {
		if arr.Node == nil || arr.Node.Items == nil {
			break
		}
		arr.Items = append(arr.Items, buildBodyValue(arr.Node.Items, nil, nil))
	}
	if len(arr.Items) > n {
		arr.Items = arr.Items[:n]
	}
}

// ---- 4. variant/discriminator switch ----

func opVariantSwitchValid(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	site, ok := pickVariantSite(schema, tree, rng)
	if !ok {
		return false, ""
	}
	idx := rng.Intn(len(site.schema.Variants))
	site.set(buildBodyValue(site.schema, nil, func(int) int { return idx }))
	return true, "variant_switch"
}

func opVariantSwitchAdversarial(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	site, ok := pickVariantSite(schema, tree, rng)
	if !ok {
		return false, ""
	}
	idx := rng.Intn(len(site.schema.Variants))
	built := buildBodyValue(site.schema, nil, func(int) int { return idx })
	// Shape now matches variant idx; if there's a discriminator, retag it to a
	// DIFFERENT variant's value -- shape says one thing, tag says another.
	if site.schema.Discriminator != nil && len(site.schema.Variants) > 1 && built.Kind == BVObject {
		wrongIdx := (idx + 1) % len(site.schema.Variants)
		if wrongTag := discriminatorTagForVariant(site.schema, wrongIdx); wrongTag != "" {
			prop := site.schema.Discriminator.PropertyName
			for i := range built.Fields {
				if built.Fields[i].Key == prop {
					built.Fields[i].Value = newStringValue(nil, built.Path+"."+prop, wrongTag)
				}
			}
		}
	}
	site.set(built)
	return true, "variant_switch"
}

func pickVariantSite(schema *BodyNode, tree *BodyValue, rng *rand.Rand) (bodySite, bool) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool {
		return (s.schema.NodeType == "oneOf" || s.schema.NodeType == "anyOf") && len(s.schema.Variants) > 1
	})
	return pickSite(sites, rng)
}

// ---- 5. type substitution (adversarial only) ----

func opTypeSubstitution(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool { return s.schema.NodeType == "scalar" })
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	site.set(wrongTypeValue(site.schema, rng))
	return true, "type_substitution"
}

func wrongTypeValue(node *BodyNode, rng *rand.Rand) *BodyValue {
	switch node.ScalarType {
	case "integer", "number":
		return newStringValue(node, node.Path, "not-a-number")
	case "boolean":
		return newStringValue(node, node.Path, "not-a-bool")
	default: // string (or unknown) -> substitute a non-string JSON type
		choices := []func() *BodyValue{
			func() *BodyValue { return newNumberValue(node, node.Path, "12345") },
			func() *BodyValue { return newBoolValue(node, node.Path, true) },
			func() *BodyValue { return newArrayValue(node, node.Path) },
			func() *BodyValue { return newObjectValue(node, node.Path) },
		}
		return choices[rng.Intn(len(choices))]()
	}
}

// ---- 6. null injection (adversarial only) ----

func opNullInjection(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool {
		return !s.schema.Nullable && s.schema.NodeType != ""
	})
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	site.set(newNullValue(site.schema, site.schema.Path))
	return true, "null_injection"
}

// ---- 7. undeclared property (adversarial only) ----

func opUndeclaredProperty(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool { return s.schema.NodeType == "object" })
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	key := undeclaredKeyFor(site.schema)
	field := BodyField{Key: key, Value: syntheticScalar(rng)}
	pos := rng.Intn(len(site.value.Fields) + 1)
	fields := make([]BodyField, 0, len(site.value.Fields)+1)
	fields = append(fields, site.value.Fields[:pos]...)
	fields = append(fields, field)
	fields = append(fields, site.value.Fields[pos:]...)
	site.value.Fields = fields
	return true, "undeclared_property"
}

func undeclaredKeyFor(schema *BodyNode) string {
	base := "__structFuzzExtra"
	if _, exists := schema.Properties[base]; !exists {
		return base
	}
	for i := 0; ; i++ {
		cand := fmt.Sprintf("%s%d", base, i)
		if _, exists := schema.Properties[cand]; !exists {
			return cand
		}
	}
}

func syntheticScalar(rng *rand.Rand) *BodyValue {
	switch rng.Intn(3) {
	case 0:
		return newStringValue(nil, "", "structfuzz")
	case 1:
		return newNumberValue(nil, "", "1337")
	default:
		return newBoolValue(nil, "", true)
	}
}

// ---- 8. duplicate key (adversarial only) ----

func opDuplicateKey(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool {
		return s.schema.NodeType == "object" && len(s.value.Fields) > 0
	})
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	orig := site.value.Fields[rng.Intn(len(site.value.Fields))]
	// A conflicting VALUE (not an exact copy) makes the duplicate observable
	// server-side regardless of which occurrence a naive last-wins/first-wins
	// JSON parser picks.
	conflict := BodyField{Key: orig.Key, Value: syntheticScalar(rng)}
	site.value.Fields = append(site.value.Fields, conflict)
	return true, "dup_key"
}

// ---- 9. nesting-depth stress ----

const nestingStressExtraLayers = 4

// opNestingDepthStressValid only fires when the schema graph is genuinely
// self-referential (a descendant BodyNode is the SAME pointer as an ancestor)
// -- honestly, this never happens with today's Python compiler
// (grammarc/schema_ast.py already resolves any $ref cycle into an inert
// scalar leaf at compile time, specifically so the Go side never has to
// reason about cyclic schemas at all), so this always declines against a
// real grammar right now. Implemented anyway (checking real pointer identity,
// not just declining unconditionally) so it's honestly correct rather than
// silently dead code if a future producer ever does hand this package a
// truly self-referential BodyNode graph.
func opNestingDepthStressValid(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool {
		return schemaHasSelfReference(s.schema)
	})
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	site.set(buildBodyValue(site.schema, nil, nil))
	return true, "nesting_depth"
}

func schemaHasSelfReference(node *BodyNode) bool {
	return schemaContainsPointer(node, node, 0, map[*BodyNode]bool{})
}

func schemaContainsPointer(root, node *BodyNode, depth int, seen map[*BodyNode]bool) bool {
	if node == nil || depth > 12 || seen[node] {
		return false
	}
	seen[node] = true
	for _, child := range node.Properties {
		if child == root || schemaContainsPointer(root, child, depth+1, seen) {
			return true
		}
	}
	if node.Items != nil && (node.Items == root || schemaContainsPointer(root, node.Items, depth+1, seen)) {
		return true
	}
	for _, v := range node.Variants {
		if v == root || schemaContainsPointer(root, v, depth+1, seen) {
			return true
		}
	}
	return false
}

// opNestingDepthStressAdversarial needs no schema cooperation: it fabricates
// synthetic extra object layers around an existing leaf, always available
// regardless of how shallow the real schema is.
func opNestingDepthStressAdversarial(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, nil)
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	// clone(), not the live site.value pointer: when the chosen site is the
	// tree's own root, site.set is `func(nv) { *tree = *nv }` -- it overwrites
	// the very struct site.value points to. Wrapping the *live* pointer would
	// make the innermost layer alias the exact memory about to be
	// overwritten, producing a genuine self-referential cycle the moment
	// site.set ran (found the hard way: writeJSON recursing forever over a
	// real grammar's root-level array field in the operator stress test).
	wrapped := site.value.clone()
	for i := 0; i < nestingStressExtraLayers; i++ {
		outer := newObjectValue(nil, "")
		outer.Fields = []BodyField{{Key: "wrapped", Value: wrapped}}
		wrapped = outer
	}
	site.set(wrapped)
	return true, "nesting_depth"
}

// ---- 10. constraint boundary ----

func opConstraintBoundaryValid(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool { return hasScalarConstraint(s.schema) })
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	site.set(constraintEdgeValue(site.schema))
	return true, "constraint_boundary"
}

func opConstraintBoundaryAdversarial(tree *BodyValue, schema *BodyNode, rng *rand.Rand) (bool, string) {
	sites := collectBodySites(schema, tree, func(nv *BodyValue) { *tree = *nv }, func(s *bodySite) bool { return hasScalarConstraint(s.schema) })
	site, ok := pickSite(sites, rng)
	if !ok {
		return false, ""
	}
	site.set(constraintViolatingValue(site.schema))
	return true, "constraint_boundary"
}

func hasScalarConstraint(node *BodyNode) bool {
	if node.NodeType != "scalar" {
		return false
	}
	return node.MinLength != nil || node.MaxLength != nil || node.Minimum != nil || node.Maximum != nil ||
		len(node.EnumValues) > 0 || node.Pattern != ""
}

func constraintEdgeValue(node *BodyNode) *BodyValue {
	if len(node.EnumValues) > 0 {
		return newStringValue(node, node.Path, node.EnumValues[0])
	}
	if node.ScalarType == "integer" || node.ScalarType == "number" {
		v := 0.0
		if node.Minimum != nil {
			v = *node.Minimum
		} else if node.Maximum != nil {
			v = *node.Maximum
		}
		return newNumberValue(node, node.Path, formatNumber(node.ScalarType, v))
	}
	if node.MinLength != nil {
		return newStringValue(node, node.Path, strings.Repeat("a", *node.MinLength))
	}
	if node.MaxLength != nil {
		return newStringValue(node, node.Path, strings.Repeat("a", *node.MaxLength))
	}
	return newStringValue(node, node.Path, "")
}

func constraintViolatingValue(node *BodyNode) *BodyValue {
	if node.ScalarType == "integer" || node.ScalarType == "number" {
		if node.Minimum != nil {
			return newNumberValue(node, node.Path, formatNumber(node.ScalarType, *node.Minimum-1))
		}
		if node.Maximum != nil {
			return newNumberValue(node, node.Path, formatNumber(node.ScalarType, *node.Maximum+1))
		}
	}
	if node.MaxLength != nil {
		return newStringValue(node, node.Path, strings.Repeat("a", *node.MaxLength+1))
	}
	if node.MinLength != nil && *node.MinLength > 0 {
		return newStringValue(node, node.Path, strings.Repeat("a", *node.MinLength-1))
	}
	if len(node.EnumValues) > 0 {
		return newStringValue(node, node.Path, node.EnumValues[0]+"_NOT_IN_ENUM")
	}
	if node.Pattern != "" {
		// v1 scope: no regex-negation engine (same disclosed limit as
		// mutation_engine.go::fieldConstraintStringCandidates) -- an empty
		// string is a broadly plausible non-match for most real-world patterns.
		return newStringValue(node, node.Path, "")
	}
	return newStringValue(node, node.Path, "")
}

func formatNumber(scalarType string, v float64) string {
	if scalarType == "integer" {
		return strconv.Itoa(int(v))
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
