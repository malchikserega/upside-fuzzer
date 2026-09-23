package engine

// body_value.go — BodyValue: the disposable, per-render concrete value tree
// built from a template's shared, read-only *BodyNode schema (body_schema.go).
// Deliberately distinct from BodyNode: BodyNode is "what shape is allowed",
// BodyValue is "one instantiated request body," rewritten in place by
// body_mutate.go's operators and serialized to wire bytes only immediately
// before send (body_serialize.go, invoked from prepareItemForSend).

type BodyValueKind int

const (
	BVObject BodyValueKind = iota
	BVArray
	BVString
	BVNumber // Str holds the raw, unquoted numeric literal text (e.g. "42", "1.23")
	BVBool
	BVNull
)

// BodyField is an object's key/value pair as a SLICE ELEMENT, not a map entry
// -- the entire representational trick that makes the duplicate-key
// adversarial operator possible: appending a second BodyField with a Key
// that already exists elsewhere in Fields is a plain, unremarkable slice
// append, never blocked or deduped the way a Go map would.
type BodyField struct {
	Key   string
	Value *BodyValue
}

// BodyValue is one node of a concrete request-body instance.
type BodyValue struct {
	Kind   BodyValueKind
	Fields []BodyField  // BVObject: ordered, may contain repeated Keys
	Items  []*BodyValue // BVArray
	Str    string       // BVString / BVNumber
	Bool   bool         // BVBool

	Node *BodyNode // originating schema node; nil for synthetic/injected values
	Path string    // dotted path, mirrors Node.Path when Node != nil
}

func newObjectValue(node *BodyNode, path string) *BodyValue {
	return &BodyValue{Kind: BVObject, Node: node, Path: path}
}

func newArrayValue(node *BodyNode, path string) *BodyValue {
	return &BodyValue{Kind: BVArray, Node: node, Path: path}
}

func newStringValue(node *BodyNode, path, s string) *BodyValue {
	return &BodyValue{Kind: BVString, Node: node, Path: path, Str: s}
}

func newNumberValue(node *BodyNode, path, s string) *BodyValue {
	return &BodyValue{Kind: BVNumber, Node: node, Path: path, Str: s}
}

func newBoolValue(node *BodyNode, path string, b bool) *BodyValue {
	return &BodyValue{Kind: BVBool, Node: node, Path: path, Bool: b}
}

func newNullValue(node *BodyNode, path string) *BodyValue {
	return &BodyValue{Kind: BVNull, Node: node, Path: path}
}

// scalarText renders a BVString/BVNumber/BVBool/BVNull value's own text content,
// with no surrounding JSON quoting/escaping -- used by ToForm/ToMultipart, which
// have their own (different) escaping rules from ToJSON.
func (v *BodyValue) scalarText() string {
	if v == nil {
		return ""
	}
	switch v.Kind {
	case BVString, BVNumber:
		return v.Str
	case BVBool:
		if v.Bool {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// clone deep-copies a BodyValue tree -- used by body_mutate.go's
// opNestingDepthStressAdversarial (wrapping a value must never reuse the
// live pointer a root-site .set() is about to overwrite in place, or the
// wrapper's innermost layer ends up aliasing -- and therefore cycling back
// to -- the very struct it wraps) and by minimize.go (Stage 7) to build
// candidate trees without mutating the original.
func (v *BodyValue) clone() *BodyValue {
	return v.cloneDepth(0)
}

func (v *BodyValue) cloneDepth(depth int) *BodyValue {
	if v == nil {
		return nil
	}
	if depth > maxSerializeDepth {
		return newNullValue(v.Node, v.Path)
	}
	out := &BodyValue{Kind: v.Kind, Str: v.Str, Bool: v.Bool, Node: v.Node, Path: v.Path}
	if v.Fields != nil {
		out.Fields = make([]BodyField, len(v.Fields))
		for i, f := range v.Fields {
			out.Fields[i] = BodyField{Key: f.Key, Value: f.Value.cloneDepth(depth + 1)}
		}
	}
	if v.Items != nil {
		out.Items = make([]*BodyValue, len(v.Items))
		for i, it := range v.Items {
			out.Items[i] = it.cloneDepth(depth + 1)
		}
	}
	return out
}
