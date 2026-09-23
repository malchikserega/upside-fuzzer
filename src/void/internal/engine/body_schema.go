package engine

// body_schema.go — BodyNode: the immutable, JSON-decoded schema tree for a
// template's request body (grammarc/schema_ast.py::build_schema_node's Go
// mirror). One BodyNode tree is parsed per template at load time (via the
// standard json.Unmarshal path loadTemplates already uses -- no separate
// decode step needed) and shared read-only across every render of that
// template; see body_value.go for the separate, disposable per-render
// concrete value tree built from it.
//
// NodeType is one of: "object", "array", "scalar", "oneOf", "anyOf".

type BodyNode struct {
	NodeType  string `json:"node_type"`
	Path      string `json:"path,omitempty"`
	FieldName string `json:"field_name,omitempty"`
	Nullable  bool   `json:"nullable,omitempty"`

	// object
	Properties           map[string]*BodyNode `json:"properties,omitempty"`
	PropertyOrder        []string             `json:"property_order,omitempty"`
	Required             []string             `json:"required,omitempty"`
	AllowAdditional      bool                 `json:"allow_additional,omitempty"`
	AdditionalProperties *BodyNode            `json:"additional_properties,omitempty"`

	// array
	Items       *BodyNode `json:"items,omitempty"`
	MinItems    *int      `json:"min_items,omitempty"`
	MaxItems    *int      `json:"max_items,omitempty"`
	UniqueItems bool      `json:"unique_items,omitempty"`

	// oneOf / anyOf
	Variants      []*BodyNode        `json:"variants,omitempty"`
	Discriminator *BodyDiscriminator `json:"discriminator,omitempty"`

	// scalar
	ScalarType string   `json:"scalar_type,omitempty"`
	Format     string   `json:"format,omitempty"`
	EnumValues []string `json:"enum_values,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
	MinLength  *int     `json:"min_length,omitempty"`
	MaxLength  *int     `json:"max_length,omitempty"`
	Minimum    *float64 `json:"minimum,omitempty"`
	Maximum    *float64 `json:"maximum,omitempty"`

	// Recursive version of Segment.PayloadKey (types.go) -- a dependency-plan
	// override for top-level id-shaped fields, or a canonical-key fallback for
	// any id-shaped leaf regardless of depth (grammarc/schema_ast.py). Consulted
	// by body_bind.go (Stage 6); empty means "no known correlation key."
	PayloadKey string `json:"payload_key,omitempty"`
}

// BodyDiscriminator is an OpenAPI discriminator object resolved against this
// oneOf/anyOf node's own Variants: Mapping's values are indexes into Variants,
// not raw $ref strings, so Go-side code never needs to re-resolve a $ref.
type BodyDiscriminator struct {
	PropertyName string         `json:"property_name"`
	Mapping      map[string]int `json:"mapping,omitempty"`
}

// IsObject/IsArray/IsScalar/IsVariant are small readability helpers used by
// body_build.go/body_mutate.go's switches over NodeType.
func (n *BodyNode) IsObject() bool { return n != nil && n.NodeType == "object" }
func (n *BodyNode) IsArray() bool  { return n != nil && n.NodeType == "array" }
func (n *BodyNode) IsScalar() bool { return n != nil && n.NodeType == "scalar" }
func (n *BodyNode) IsVariant() bool {
	return n != nil && (n.NodeType == "oneOf" || n.NodeType == "anyOf")
}
