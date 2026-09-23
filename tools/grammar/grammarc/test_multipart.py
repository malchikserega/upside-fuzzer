"""Tests for multipart/form-data request template synthesis (multipart.py).

Run with: python3 -m unittest grammarc.test_multipart -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import unittest

from .multipart import build_multipart_template, multipart_dict_seeds
from .oas import FieldHint, MultipartEndpoint


def _render(segs) -> str:
    """Renders static segments verbatim and payload segments as a placeholder, for
    structural assertions on the produced HTTP request text."""
    out = []
    for seg in segs:
        if seg["kind"] == "static":
            out.append(seg["value"])
        else:
            out.append(f"<{seg['payload_key']}>")
    return "".join(out)


class BuildMultipartTemplateTests(unittest.TestCase):
    def test_produces_valid_http_request_line_and_headers(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[
            FieldHint(name="file", type_name="string", fmt="binary", multipart_file=True),
        ])
        tmpl = build_multipart_template(ep, template_id=0)
        rendered = _render(tmpl["segments"])
        self.assertTrue(rendered.startswith("POST /upload HTTP/1.1\r\n"))
        self.assertIn("Content-Type: multipart/form-data; boundary=", rendered)
        self.assertIn("Authorization: Bearer TOKEN\r\n", rendered)

    def test_file_field_emits_filename_contenttype_and_content_payload_keys(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[
            FieldHint(name="file", type_name="string", fmt="binary", multipart_file=True),
        ])
        tmpl = build_multipart_template(ep, template_id=0)
        payload_keys = [s["payload_key"] for s in tmpl["segments"] if s["kind"] == "custom_payload"]
        self.assertIn("file.filename", payload_keys)
        self.assertIn("file.contentType", payload_keys)
        self.assertIn("file.content", payload_keys)

    def test_non_file_field_emits_a_single_payload_key(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[
            FieldHint(name="description", type_name="string"),
        ])
        tmpl = build_multipart_template(ep, template_id=0)
        payload_keys = [s["payload_key"] for s in tmpl["segments"] if s["kind"] == "custom_payload"]
        self.assertEqual(payload_keys, ["description"])

    def test_no_fields_falls_back_to_a_default_file_field(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[])
        tmpl = build_multipart_template(ep, template_id=0)
        payload_keys = [s["payload_key"] for s in tmpl["segments"] if s["kind"] == "custom_payload"]
        self.assertIn("file.content", payload_keys)

    def test_path_parameter_becomes_a_custom_payload_segment(self):
        ep = MultipartEndpoint(method="POST", path="/orders/{orderId}/attachments", fields=[
            FieldHint(name="file", type_name="string", fmt="binary", multipart_file=True),
        ])
        tmpl = build_multipart_template(ep, template_id=0)
        payload_keys = [s["payload_key"] for s in tmpl["segments"] if s["kind"] == "custom_payload"]
        self.assertIn("orderId", payload_keys)

    def test_request_id_combines_method_and_path(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[])
        tmpl = build_multipart_template(ep, template_id=5)
        self.assertEqual(tmpl["id"], 5)
        self.assertEqual(tmpl["request_id"], "POST/upload")


class MultipartDictSeedsTests(unittest.TestCase):
    def test_file_field_gets_filename_contenttype_content_pools(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[
            FieldHint(name="file", type_name="string", fmt="binary", multipart_file=True),
        ])
        seeds = multipart_dict_seeds(ep)
        self.assertIn("file.filename", seeds)
        self.assertIn("file.contentType", seeds)
        self.assertIn("file.content", seeds)
        self.assertGreater(len(seeds["file.filename"]), 0)

    def test_non_file_field_gets_no_seeds(self):
        ep = MultipartEndpoint(method="POST", path="/upload", fields=[
            FieldHint(name="description", type_name="string"),
        ])
        seeds = multipart_dict_seeds(ep)
        self.assertEqual(seeds, {})


if __name__ == "__main__":
    unittest.main()
