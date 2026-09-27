"""Tests for body_serializer.py -- turning a resolved OpenAPI schema into the
static/fuzzable/custom_payload segment list void/go/template.go renders into request
bytes. Confirms segment JSON shape matches what void/go/types.go's Segment struct
expects (in particular the payload_key fix from Top-20 #9/#10's migration).

Run with: python3 -m unittest grammarc.test_body_serializer -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import json
import unittest

from .body_serializer import _leaf_segments, seg_fuzzable, seg_payload, seg_static, serialize_body
from .dependencies import DependencyPlan
from .oas import FieldHint, OASParser


class SegmentConstructorTests(unittest.TestCase):
    def test_seg_static_shape(self):
        self.assertEqual(seg_static("{"), {"kind": "static", "value": "{"})

    def test_seg_fuzzable_shape_and_defaults(self):
        seg = seg_fuzzable("string", "fuzzstring", quoted=True)
        self.assertEqual(seg["kind"], "fuzzable")
        self.assertEqual(seg["value_type"], "string")
        self.assertEqual(seg["default"], "fuzzstring")
        self.assertTrue(seg["quoted"])

    def test_seg_payload_uses_payload_key_json_field(self):
        # THE bug fix (Top-20 #9/#10): must be "payload_key", not "name" -- matches
        # void/go/types.go's Segment.PayloadKey json tag.
        seg = seg_payload("orderid", quoted=True)
        self.assertEqual(seg["kind"], "custom_payload")
        self.assertIn("payload_key", seg)
        self.assertNotIn("name", seg)
        self.assertEqual(seg["payload_key"], "orderid")

    def test_constraint_fields_included_when_hint_has_them(self):
        hint = FieldHint(name="qty", type_name="integer", minimum=1, maximum=100)
        seg = seg_fuzzable("integer", "1", hint=hint)
        self.assertEqual(seg["minimum"], 1)
        self.assertEqual(seg["maximum"], 100)

    def test_constraint_fields_omitted_when_hint_has_none(self):
        hint = FieldHint(name="notes", type_name="string")
        seg = seg_fuzzable("string", "x", hint=hint)
        self.assertNotIn("min_length", seg)
        self.assertNotIn("minimum", seg)
        self.assertNotIn("enum_values", seg)


class LeafSegmentsTests(unittest.TestCase):
    def test_plain_unconstrained_field_is_fuzzable(self):
        hint = FieldHint(name="notes", type_name="string")
        segs = _leaf_segments(hint, "notes", 0, None)
        self.assertEqual(segs[0]["kind"], "fuzzable")

    def test_enum_field_is_custom_payload(self):
        hint = FieldHint(name="status", type_name="string", enum_values=["Active", "Inactive"])
        segs = _leaf_segments(hint, "status", 0, None)
        self.assertEqual(segs[0]["kind"], "custom_payload")
        self.assertEqual(segs[0]["payload_key"], "status")

    def test_dependency_plan_override_forces_custom_payload_even_when_unconstrained(self):
        hint = FieldHint(name="id", type_name="integer")
        plan = DependencyPlan()
        plan.payload_key[0]["id"] = "orderid"
        segs = _leaf_segments(hint, "id", 0, plan)
        self.assertEqual(segs[0]["kind"], "custom_payload")
        self.assertEqual(segs[0]["payload_key"], "orderid")

    def test_force_unquoted_overrides_string_quoting(self):
        hint = FieldHint(name="id", type_name="string")
        segs = _leaf_segments(hint, "id", 0, None, force_unquoted=True)
        self.assertFalse(segs[0]["quoted"])

    def test_string_field_quoted_by_default_for_body_serialization(self):
        hint = FieldHint(name="name", type_name="string")
        segs = _leaf_segments(hint, "name", 0, None)
        self.assertTrue(segs[0]["quoted"])

    def test_integer_field_never_quoted(self):
        hint = FieldHint(name="qty", type_name="integer")
        segs = _leaf_segments(hint, "qty", 0, None)
        self.assertFalse(segs[0]["quoted"])


def _segments_to_json_skeleton(segs):
    """Renders static segments verbatim and fuzzable/custom_payload segments as their
    default value, to reconstruct the JSON shape serialize_body would produce at
    render time -- lets these tests assert on real, parseable JSON structure instead
    of just eyeballing the segment list."""
    parts = []
    for seg in segs:
        if seg["kind"] == "static":
            parts.append(seg["value"])
        elif seg["kind"] == "fuzzable":
            v = seg["default"]
            parts.append(f'"{v}"' if seg["quoted"] else v)
        else:  # custom_payload
            parts.append('"__PAYLOAD__"' if seg["quoted"] else "0")
    return "".join(parts)


class SerializeBodyTests(unittest.TestCase):
    def test_flat_object_produces_valid_json_skeleton(self):
        schema = {
            "type": "object",
            "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
        }
        parser = OASParser({"openapi": "3.0.0"})
        segs = serialize_body(schema, parser, {}, None, 0)
        rendered = _segments_to_json_skeleton(segs)
        parsed = json.loads(rendered)  # must be valid JSON
        self.assertIn("id", parsed)
        self.assertIn("name", parsed)

    def test_nested_object_produces_valid_nested_json(self):
        schema = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "shipping": {"type": "object", "properties": {"city": {"type": "string"}}},
            },
        }
        parser = OASParser({"openapi": "3.0.0"})
        segs = serialize_body(schema, parser, {}, None, 0)
        rendered = _segments_to_json_skeleton(segs)
        parsed = json.loads(rendered)
        self.assertIsInstance(parsed["shipping"], dict)
        self.assertIn("city", parsed["shipping"])

    def test_array_of_objects_produces_valid_json_array(self):
        schema = {
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "object", "properties": {"sku": {"type": "string"}}}},
            },
        }
        parser = OASParser({"openapi": "3.0.0"})
        segs = serialize_body(schema, parser, {}, None, 0)
        rendered = _segments_to_json_skeleton(segs)
        parsed = json.loads(rendered)
        self.assertIsInstance(parsed["items"], list)

    def test_top_level_merged_hint_used_over_raw_schema_when_present(self):
        # emit_templates.py passes a Roslyn-merged FieldHint for top-level fields when
        # available -- must take precedence over the OAS-only schema for that field.
        schema = {"type": "object", "properties": {"code": {"type": "string"}}}
        merged = {"code": FieldHint(name="code", type_name="string", enum_values=["A", "B"])}
        parser = OASParser({"openapi": "3.0.0"})
        segs = serialize_body(schema, parser, merged, None, 0)
        payload_segs = [s for s in segs if s["kind"] == "custom_payload"]
        self.assertTrue(payload_segs, "expected the enum-constrained merged hint to route through custom_payload")


if __name__ == "__main__":
    unittest.main()
