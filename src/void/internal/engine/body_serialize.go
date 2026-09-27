package engine

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

// newBodyTreeMultipartBoundary returns a boundary string vanishingly unlikely
// to collide with any real value in the payload -- callers (prepareItemForSend)
// use it both to serialize via ToMultipart and to set the outgoing
// Content-Type header, so the two always agree.
func newBodyTreeMultipartBoundary() string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 24)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "UpsideFuzzBody" + string(b)
}

// body_serialize.go — serializes a BodyValue tree to wire bytes. Hand-rolled,
// not encoding/json.Marshal: a duplicate-key adversarial BodyValue (two
// BodyFields sharing a Key in the same object) cannot be represented by any
// map-based Marshal path, so ToJSON walks the ordered []BodyField slice
// directly and writes both occurrences verbatim, by construction. Invoked from
// prepareItemForSend (template.go) -- structure is preserved as a tree from
// render through scheduling and mutation, and only turned into bytes here,
// immediately before the HTTP body reader is built.

// maxSerializeDepth is a defense-in-depth cap, independent of buildBodyValue's
// own maxBuildDepth: every operator is written to never construct a cyclic
// BodyValue (a real instance of exactly this class of bug -- a self-aliasing
// tree, not a schema cycle -- was found and fixed in
// opNestingDepthStressAdversarial), but the serializer must not simply trust
// that invariant either. Without this, a cyclic tree reaching ToJSON/ToForm/
// ToMultipart would recurse forever and crash the entire fuzzer process with
// a stack overflow -- a real DoS risk to the tool itself, not a hypothetical.
const maxSerializeDepth = 64

// ToJSON renders the tree as JSON text.
func (v *BodyValue) ToJSON() string {
	var b strings.Builder
	v.writeJSON(&b, 0)
	return b.String()
}

func (v *BodyValue) writeJSON(b *strings.Builder, depth int) {
	if v == nil {
		b.WriteString("null")
		return
	}
	if depth > maxSerializeDepth {
		b.WriteString("null")
		return
	}
	switch v.Kind {
	case BVObject:
		b.WriteByte('{')
		for i, f := range v.Fields {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsonEscapeString(f.Key))
			b.WriteByte(':')
			f.Value.writeJSON(b, depth+1)
		}
		b.WriteByte('}')
	case BVArray:
		b.WriteByte('[')
		for i, it := range v.Items {
			if i > 0 {
				b.WriteByte(',')
			}
			it.writeJSON(b, depth+1)
		}
		b.WriteByte(']')
	case BVString:
		b.WriteString(jsonEscapeString(v.Str))
	case BVNumber:
		if strings.TrimSpace(v.Str) == "" {
			b.WriteString("0")
		} else {
			b.WriteString(v.Str)
		}
	case BVBool:
		if v.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case BVNull:
		b.WriteString("null")
	default:
		b.WriteString("null")
	}
}

// jsonEscapeString quotes and escapes s per RFC 8259: only '"', '\', and
// control characters (U+0000-U+001F) MUST be escaped -- everything else
// (including raw UTF-8, and deliberately including '<'/'>'/'&') passes
// through unescaped. This matters for fidelity: an injection payload (SSTI/
// XSS candidate strings) must reach the wire byte-for-byte, not silently
// rewritten the way encoding/json.Marshal's default HTML-escaping would.
func jsonEscapeString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ToForm renders the tree as application/x-www-form-urlencoded, using
// bracket notation for nested structure (parent[child]=x, parent[]=x for
// array elements) -- the same convention PHP/Rails-style form APIs use, and
// distinct enough from a flat key collision to still exercise nesting on a
// form-encoded target.
func (v *BodyValue) ToForm() string {
	vals := url.Values{}
	v.collectForm("", vals, 0)
	return vals.Encode()
}

func (v *BodyValue) collectForm(prefix string, vals url.Values, depth int) {
	if v == nil || depth > maxSerializeDepth {
		return
	}
	switch v.Kind {
	case BVObject:
		for _, f := range v.Fields {
			key := f.Key
			if prefix != "" {
				key = prefix + "[" + f.Key + "]"
			}
			f.Value.collectForm(key, vals, depth+1)
		}
	case BVArray:
		key := prefix + "[]"
		for _, it := range v.Items {
			it.collectForm(key, vals, depth+1)
		}
	default:
		vals.Add(prefix, v.scalarText())
	}
}

// ToMultipart renders the tree as multipart/form-data, one part per leaf
// value (nested structure flattened via the same bracket-notation keys as
// ToForm). No producer wires this in yet -- grammarc only emits body_schema
// for non-multipart operations (Stage 1) -- but the type is multipart-capable
// from the start rather than requiring a redesign later.
func (v *BodyValue) ToMultipart(boundary string) string {
	var b strings.Builder
	v.writeMultipartParts("", &b, boundary, 0)
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

func (v *BodyValue) writeMultipartParts(prefix string, b *strings.Builder, boundary string, depth int) {
	if v == nil || depth > maxSerializeDepth {
		return
	}
	switch v.Kind {
	case BVObject:
		for _, f := range v.Fields {
			key := f.Key
			if prefix != "" {
				key = prefix + "[" + f.Key + "]"
			}
			f.Value.writeMultipartParts(key, b, boundary, depth+1)
		}
	case BVArray:
		key := prefix + "[]"
		for _, it := range v.Items {
			it.writeMultipartParts(key, b, boundary, depth+1)
		}
	default:
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(`Content-Disposition: form-data; name="` + prefix + `"` + "\r\n\r\n")
		b.WriteString(v.scalarText())
		b.WriteString("\r\n")
	}
}
