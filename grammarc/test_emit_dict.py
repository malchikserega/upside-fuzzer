"""Tests for the custom dictionary convention (dict.custom.json) in emit_dict.py.

Run with: python3 -m unittest grammarc.test_emit_dict -v
Stdlib-only, matching the rest of grammarc -- no pip install needed.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from .emit_dict import (
    CUSTOM_DICT_FILENAME,
    merge_custom_dict_convention,
    merge_external_dict,
    scaffold_custom_dict_if_missing,
    write_dict,
)


class ScaffoldCustomDictTests(unittest.TestCase):
    def test_creates_file_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            created = scaffold_custom_dict_if_missing(out_dir)
            self.assertTrue(created)
            path = out_dir / CUSTOM_DICT_FILENAME
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("_readme", data)
            self.assertIsInstance(data["_readme"], list)
            self.assertGreater(len(data["_readme"]), 0)
            # Every line is a plain string (valid JSON, no comment syntax needed).
            for line in data["_readme"]:
                self.assertIsInstance(line, str)

    def test_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            path = out_dir / CUSTOM_DICT_FILENAME
            out_dir.mkdir(parents=True, exist_ok=True)
            custom_value = {"myRealField": ["my-real-value-i-added-by-hand"]}
            path.write_text(json.dumps(custom_value), encoding="utf-8")

            created = scaffold_custom_dict_if_missing(out_dir)

            self.assertFalse(created)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data, custom_value)

    def test_scaffold_key_is_obviously_not_a_real_field(self):
        # The one example key in the scaffold must be unmistakably a placeholder,
        # never something that could be confused with data harvested from a real
        # target's spec (which is the whole point of dict.json living separately).
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            scaffold_custom_dict_if_missing(out_dir)
            data = json.loads((out_dir / CUSTOM_DICT_FILENAME).read_text(encoding="utf-8"))
            keys = [k for k in data.keys() if k != "_readme"]
            self.assertEqual(len(keys), 1)
            self.assertIn("example", keys[0].lower())


class MergeCustomDictConventionTests(unittest.TestCase):
    def test_merges_values_into_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / CUSTOM_DICT_FILENAME).write_text(
                json.dumps({"currencyCode": ["ZAR", "MXN"]}), encoding="utf-8"
            )

            pool = {"currencyCode": ["USD", "EUR"]}
            merge_custom_dict_convention(pool, out_dir)

            self.assertEqual(set(pool["currencyCode"]), {"USD", "EUR", "ZAR", "MXN"})

    def test_no_file_is_a_silent_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            pool = {"currencyCode": ["USD"]}
            merge_custom_dict_convention(pool, out_dir)
            self.assertEqual(pool, {"currencyCode": ["USD"]})

    def test_survives_regeneration_end_to_end(self):
        # Simulates two compile-grammar.sh runs: the first scaffolds + writes
        # dict.json from an auto-discovered pool; the user then hand-edits
        # dict.custom.json; the second run must merge those edits into the fresh
        # dict.json without the scaffold step touching the user's file at all.
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)

            # --- Run 1: fresh compile, nothing custom yet ---
            scaffold_custom_dict_if_missing(out_dir)
            pool_run1 = {"userId": ["usr-001"]}
            merge_custom_dict_convention(pool_run1, out_dir)
            write_dict(pool_run1, out_dir / "dict.json")
            self.assertNotIn("tenantId", pool_run1)

            # --- User hand-edits dict.custom.json between runs ---
            custom_path = out_dir / CUSTOM_DICT_FILENAME
            custom_data = json.loads(custom_path.read_text(encoding="utf-8"))
            custom_data["tenantId"] = ["acme-corp", "globex-inc"]
            custom_path.write_text(json.dumps(custom_data), encoding="utf-8")

            # --- Run 2: spec changed, pool is rebuilt from scratch, dict.json
            #     is fully overwritten -- but the custom file must not be touched
            #     and its values must land in the new dict.json. ---
            scaffolded_again = scaffold_custom_dict_if_missing(out_dir)
            pool_run2 = {"userId": ["usr-002"], "orderId": ["ord-777"]}  # spec drifted
            merge_custom_dict_convention(pool_run2, out_dir)
            write_dict(pool_run2, out_dir / "dict.json")

            self.assertFalse(scaffolded_again, "must not re-scaffold over the user's edited file")
            final = json.loads((out_dir / "dict.json").read_text(encoding="utf-8"))
            self.assertEqual(set(final["tenantId"]), {"acme-corp", "globex-inc"})
            self.assertIn("orderId", final)  # new spec-derived key still present
            self.assertEqual(
                json.loads(custom_path.read_text(encoding="utf-8"))["tenantId"],
                ["acme-corp", "globex-inc"],
            )


class MergeExternalDictWarningTests(unittest.TestCase):
    """merge_external_dict's JSON-parse-failure path used to be completely
    silent for both of its callers. That's still correct for the always-on
    dict.custom.json convention merge (a file that may legitimately not exist
    or be mid-edit) -- but an explicit, user-supplied `--dict <path>` deserves
    a warning when it fails to parse, the same way every other compile-grammar
    error path already prints one. warn_on_parse_error controls this."""

    def test_malformed_dict_silent_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text("{not valid json", encoding="utf-8")
            pool: dict = {}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                merge_external_dict(pool, bad_path)  # warn_on_parse_error defaults False
            self.assertEqual(pool, {})
            self.assertEqual(buf.getvalue(), "")

    def test_malformed_dict_warns_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text("{not valid json", encoding="utf-8")
            pool: dict = {}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                merge_external_dict(pool, bad_path, warn_on_parse_error=True)
            self.assertEqual(pool, {})
            self.assertIn("WARNING", buf.getvalue())
            self.assertIn(str(bad_path), buf.getvalue())

    def test_valid_dict_never_warns_either_way(self):
        with tempfile.TemporaryDirectory() as tmp:
            good_path = Path(tmp) / "good.json"
            good_path.write_text(json.dumps({"currencyCode": ["USD"]}), encoding="utf-8")
            pool: dict = {}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                merge_external_dict(pool, good_path, warn_on_parse_error=True)
            self.assertEqual(pool, {"currencyCode": ["USD"]})
            self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
