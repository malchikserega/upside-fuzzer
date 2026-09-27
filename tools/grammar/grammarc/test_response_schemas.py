"""Tests for response-schema capture/emission (Top-20+ #23), the data feeding
void/go/schema_oracle.go's undeclared-field / type-drift oracle.

Run with: python3 -m unittest grammarc.test_response_schemas -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .emit_templates import build_template
from .oas import OASParser


def _spec_with_two_statuses():
    return {
        "openapi": "3.0.0",
        "paths": {
            "/items/{id}": {
                "get": {
                    "operationId": "getItem",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        },
                        "201": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"id": {"type": "integer"}},
                                    }
                                }
                            }
                        },
                        "404": {"description": "not found, no body schema"},
                    },
                }
            }
        },
    }


class OASParserResponseSchemasTests(unittest.TestCase):
    def test_captures_every_2xx_status_not_just_first(self):
        parser = OASParser(_spec_with_two_statuses())
        op = parser.parse()[0]
        self.assertEqual(set(op.response_schemas.keys()), {"200", "201"})
        self.assertNotIn("404", op.response_schemas)

    def test_singular_response_schema_still_first_found(self):
        # Back-compat: existing producer-field-inference callers read
        # response_schema/response_schema_ref_name (singular), which must keep
        # meaning "the first declared 2xx schema" exactly as before this feature.
        parser = OASParser(_spec_with_two_statuses())
        op = parser.parse()[0]
        self.assertEqual(op.response_schema, {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}})

    def test_no_response_schema_leaves_dict_empty(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/ping": {"get": {"operationId": "ping", "responses": {"204": {"description": "no content"}}}}},
        }
        parser = OASParser(spec)
        op = parser.parse()[0]
        self.assertEqual(op.response_schemas, {})


class BuildTemplateResponseSchemasTests(unittest.TestCase):
    def test_emits_status_to_field_type_map(self):
        parser = OASParser(_spec_with_two_statuses())
        op = parser.parse()[0]
        template = build_template(op, 0, parser, None, None)
        self.assertEqual(
            template["response_schemas"],
            {"200": {"id": "integer", "name": "string"}, "201": {"id": "integer"}},
        )

    def test_omits_key_entirely_when_no_response_schema_declared(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/ping": {"get": {"operationId": "ping", "responses": {"204": {"description": "no content"}}}}},
        }
        parser = OASParser(spec)
        op = parser.parse()[0]
        template = build_template(op, 0, parser, None, None)
        self.assertNotIn("response_schemas", template)

    def test_nested_object_fields_use_dotted_paths(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/orders/{id}": {
                    "get": {
                        "operationId": "getOrder",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        ],
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "shipping": {
                                                    "type": "object",
                                                    "properties": {"city": {"type": "string"}},
                                                },
                                            },
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            },
        }
        parser = OASParser(spec)
        op = parser.parse()[0]
        template = build_template(op, 0, parser, None, None)
        # _collect_schema_fields (reused as-is from the request-body path) emits an
        # entry for the intermediate object node itself *and* recurses into it -- so
        # both "shipping" (type "object") and the flattened leaf "shipping.city" are
        # present. This is important for schema_oracle.go's own JSON flattener to
        # mirror symmetrically: it must also emit an "object"-typed entry for
        # intermediate keys, or a live response's "shipping" key would wrongly look
        # undeclared even though the schema does describe it (just one level up).
        self.assertEqual(
            template["response_schemas"]["200"],
            {"id": "integer", "shipping": "object", "shipping.city": "string"},
        )


if __name__ == "__main__":
    unittest.main()
