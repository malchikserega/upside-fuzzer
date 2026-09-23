package engine

import (
	"strconv"
	"strings"
)

// body_build.go — builds a schema-correct BodyValue instance from a BodyNode
// schema tree ("valid mode" baseline, requirement #3). Every property declared
// on an object (required or optional) is populated by default -- the more
// complete a baseline instance is, the more likely it is to satisfy business
// logic that assumes a fully-formed payload; Stage 5's add/remove-field
// operator selectively thins this baseline back down for either mode.
//
// bodyLeafValueFunc is the pluggable scalar-value source: nil uses
// defaultLeafValue (pure schema-derived synthesis, no dict/runtime coupling),
// letting this file be fully unit-testable in isolation. Stage 6 wires a
// dict/runtime/resource-graph-aware implementation in through the same seam
// without needing to touch this builder's structure.
type bodyLeafValueFunc func(node *BodyNode) (value string, kind BodyValueKind)

const (
	defaultArrayLen    = 1
	maxDefaultArrayLen = 5

	// maxBuildDepth mirrors grammarc/schema_ast.py's _MAX_SCHEMA_DEPTH -- a
	// real, Python-compiled BodyNode graph is never cyclic (schema_ast.py
	// resolves any $ref cycle into an inert scalar leaf at compile time), but
	// buildBodyValue must not *trust* that invariant blindly: a hand-built or
	// malformed BodyNode graph (tests, a future producer, a hand-edited
	// grammar file) that IS self-referential would otherwise recurse forever
	// and crash the whole fuzzer process with a stack overflow -- a real
	// defense-in-depth gap, not just a hypothetical one (caught by this
	// package's own opNestingDepthStressValid test against a genuinely
	// self-referential fixture).
	maxBuildDepth = 12
)

// buildBodyValue recursively instantiates a schema-correct BodyValue tree.
// leafValue may be nil (defaultLeafValue is used). variantPicker selects which
// oneOf/anyOf branch to build (index into node.Variants); nil picks index 0
// (deterministic, the common case for a pure schema-conformance render).
func buildBodyValue(node *BodyNode, leafValue bodyLeafValueFunc, variantPicker func(n int) int) *BodyValue {
	return buildBodyValueDepth(node, leafValue, variantPicker, 0)
}

func buildBodyValueDepth(node *BodyNode, leafValue bodyLeafValueFunc, variantPicker func(n int) int, depth int) *BodyValue {
	if node == nil {
		return newNullValue(nil, "")
	}
	if leafValue == nil {
		leafValue = defaultLeafValue
	}
	if depth > maxBuildDepth {
		return newStringValue(node, node.Path, "fuzzstring")
	}

	switch node.NodeType {
	case "object":
		obj := newObjectValue(node, node.Path)
		for _, name := range node.PropertyOrder {
			child, ok := node.Properties[name]
			if !ok {
				continue
			}
			obj.Fields = append(obj.Fields, BodyField{Key: name, Value: buildBodyValueDepth(child, leafValue, variantPicker, depth+1)})
		}
		return obj

	case "array":
		arr := newArrayValue(node, node.Path)
		if node.Items == nil {
			return arr
		}
		n := defaultArrayLen
		if node.MinItems != nil && *node.MinItems > n {
			n = *node.MinItems
		}
		if n > maxDefaultArrayLen {
			n = maxDefaultArrayLen
		}
		for i := 0; i < n; i++ {
			arr.Items = append(arr.Items, buildBodyValueDepth(node.Items, leafValue, variantPicker, depth+1))
		}
		return arr

	case "oneOf", "anyOf":
		if len(node.Variants) == 0 {
			return newNullValue(node, node.Path)
		}
		idx := 0
		if variantPicker != nil {
			idx = variantPicker(len(node.Variants))
		}
		if idx < 0 || idx >= len(node.Variants) {
			idx = 0
		}
		val := buildBodyValueDepth(node.Variants[idx], leafValue, variantPicker, depth+1)
		applyDiscriminatorTag(val, node, idx)
		return val

	default: // "scalar" and any unrecognized type degrade to a scalar leaf
		s, kind := leafValue(node)
		switch kind {
		case BVNumber:
			return newNumberValue(node, node.Path, s)
		case BVBool:
			return newBoolValue(node, node.Path, s == "true")
		case BVNull:
			return newNullValue(node, node.Path)
		default:
			return newStringValue(node, node.Path, s)
		}
	}
}

// buildAndMutateBodyTree: see body_mutate.go for the real (Stage 5)
// implementation -- valid/adversarial mode selection plus the 10 structural
// operators.

// applyDiscriminatorTag overwrites (or injects, if absent) the discriminator
// property on a built variant object so the value tree stays internally
// consistent by default -- shape and discriminator tag agree. Stage 5's
// adversarial variant-switch operator deliberately skips this call to produce
// the shape/tag mismatch instead.
func applyDiscriminatorTag(val *BodyValue, node *BodyNode, variantIdx int) {
	if node.Discriminator == nil || val == nil || val.Kind != BVObject {
		return
	}
	tag := discriminatorTagForVariant(node, variantIdx)
	if tag == "" {
		return
	}
	prop := node.Discriminator.PropertyName
	for i := range val.Fields {
		if val.Fields[i].Key == prop {
			val.Fields[i].Value = newStringValue(nil, val.Path+"."+prop, tag)
			return
		}
	}
	val.Fields = append(val.Fields, BodyField{Key: prop, Value: newStringValue(nil, val.Path+"."+prop, tag)})
}

// discriminatorTagForVariant reverse-looks-up node.Discriminator.Mapping (value
// -> variant index) to find the string tag for a given variant index.
func discriminatorTagForVariant(node *BodyNode, variantIdx int) string {
	if node.Discriminator == nil {
		return ""
	}
	for tag, idx := range node.Discriminator.Mapping {
		if idx == variantIdx {
			return tag
		}
	}
	return ""
}

// defaultLeafValue synthesizes a schema-plausible scalar value with no
// dict/runtime/CmpLog coupling -- pure function of the schema node alone, kept
// deliberately simple to match this pipeline's existing, disclosed scope limit
// on pattern satisfaction (mutation_engine.go::fieldConstraintStringCandidates's
// own comment: "v1 scope: no regex-negation engine").
func defaultLeafValue(node *BodyNode) (string, BodyValueKind) {
	if len(node.EnumValues) > 0 {
		return node.EnumValues[0], BVString
	}
	switch node.ScalarType {
	case "integer", "number":
		return numericDefaultForNode(node), BVNumber
	case "boolean":
		return "true", BVBool
	default:
		return stringDefaultForNode(node), BVString
	}
}

func numericDefaultForNode(node *BodyNode) string {
	v := 1.0
	if node.Minimum != nil && v < *node.Minimum {
		v = *node.Minimum
	}
	if node.Maximum != nil && v > *node.Maximum {
		v = *node.Maximum
	}
	if node.ScalarType == "integer" {
		return strconv.Itoa(int(v))
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func stringDefaultForNode(node *BodyNode) string {
	s := "fuzzstring"
	if node.Format == "uuid" {
		// Genuinely v4-shaped (version nibble [1-5], variant nibble [89ab]) --
		// several existing oracles/regexes in this codebase (e.g. sequence.go's
		// reUUIDLike) reject a fake-but-wrong-shaped UUID outright.
		s = "11111111-1111-4111-8111-111111111111"
	}
	if node.MinLength != nil && len(s) < *node.MinLength {
		s = s + strings.Repeat("x", *node.MinLength-len(s))
	}
	if node.MaxLength != nil && len(s) > *node.MaxLength {
		s = s[:*node.MaxLength]
	}
	return s
}
