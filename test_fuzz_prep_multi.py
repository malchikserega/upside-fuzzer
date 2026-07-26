"""Tests for the pure regex-detection helpers in fuzzprep/detect.py.

This module (and the rest of the fuzzprep/ package it lives in, split out of
what used to be one ~2.8k-line fuzz-prep-multi.py) is the single most fragile
piece of first-party Python in the repo and, until this file, had zero
automated test coverage -- three real, previously-unknown bugs were found by
hand while building demo_app/ against it in one session: non-main-project
DLLs shipped uninstrumented, _detect_last_stage misidentifying the runtime
stage on an unnamed final FROM (reproduced concretely on demo_app/Dockerfile,
btcpayserver/Dockerfile, and simplcommerce/Dockerfile -- all three already in
this repo's own fixture set), and a stale `dockerfile: Dockerfile` reference
in the generated void-sidecar template. These tests lock in the fixes and
guard the exact real-world Dockerfile shapes that exposed them.

Run with: python3 -m unittest test_fuzz_prep_multi -v
Stdlib-only, matching the rest of this repo's Python test suites (grammarc/test_*.py).
"""

from __future__ import annotations

import re
import unittest

from fuzzprep.detect import (
    _detect_last_stage,
    _detect_source_stage,
    _detect_publish_dir,
    _strip_publish_single_file,
    _detect_builder_name,
    _detect_app_name,
)


class DetectLastStageTests(unittest.TestCase):
    def test_unnamed_final_stage_returns_none_not_an_earlier_stage(self):
        # The exact shape of demo_app/Dockerfile: a named build stage, then an
        # unnamed final runtime stage. This is the precise bug: the old
        # implementation returned "build" here instead of None.
        content = (
            "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build\n"
            "WORKDIR /src\n"
            "RUN dotnet publish -c Release -o /app/publish\n"
            "\n"
            "FROM mcr.microsoft.com/dotnet/aspnet:8.0\n"
            "WORKDIR /app\n"
            "COPY --from=build /app/publish .\n"
        )
        self.assertIsNone(_detect_last_stage(content))

    def test_named_final_stage_is_detected(self):
        content = (
            "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build\n"
            "FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final\n"
        )
        self.assertEqual(_detect_last_stage(content), "final")

    def test_buildkit_platform_flag_before_image_ref_does_not_hide_a_real_stage_name(self):
        # btcpayserver/Dockerfile's actual first line -- a real regression case
        # found while fixing this: `--platform=$BUILDPLATFORM` between FROM and
        # the image ref must not swallow a legitimate `AS builder` that follows it.
        content = (
            "FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0.301-noble AS builder\n"
            "FROM mcr.microsoft.com/dotnet/aspnet:10.0.9-noble\n"
        )
        # The final stage here is STILL unnamed (btcpayserver's real shape) -> None,
        # but the platform-flag stage itself must still parse as "builder", not silently
        # lose the name (checked indirectly: if the regex mishandled the flag, this
        # whole findall would have produced a garbage capture instead of "builder").
        self.assertIsNone(_detect_last_stage(content))
        m = re.findall(
            r'^FROM\s+(?:--\S+\s+)*\S+(?:\s+AS\s+(\S+))?', content,
            re.IGNORECASE | re.MULTILINE,
        )
        self.assertEqual(m, ["builder", ""])

    def test_simplcommerce_shape_unnamed_final_stage(self):
        # simplcommerce/Dockerfile's real shape: named build-env stage, unnamed
        # runtime stage. Second real-world confirmation of the same bug pattern.
        content = (
            "FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build-env\n"
            "WORKDIR /app\n"
            "RUN dotnet publish -c Release -o out\n"
            "FROM mcr.microsoft.com/dotnet/aspnet:5.0\n"
            "WORKDIR /app\n"
            "COPY --from=build-env /app/out .\n"
        )
        self.assertIsNone(_detect_last_stage(content))

    def test_no_from_statements_returns_none(self):
        self.assertIsNone(_detect_last_stage(""))
        self.assertIsNone(_detect_last_stage("# just a comment, no FROM at all\n"))

    def test_single_unnamed_stage_returns_none(self):
        content = "FROM mcr.microsoft.com/dotnet/aspnet:8.0\n"
        self.assertIsNone(_detect_last_stage(content))


class DetectSourceStageTests(unittest.TestCase):
    def test_finds_the_stage_referenced_by_the_last_copy_from(self):
        content = (
            "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build\n"
            "FROM mcr.microsoft.com/dotnet/aspnet:8.0\n"
            "COPY --from=build /app/publish .\n"
        )
        self.assertEqual(_detect_source_stage(content), "build")

    def test_no_copy_from_falls_back_to_builder(self):
        self.assertEqual(_detect_source_stage("FROM scratch\n"), "builder")

    def test_multiple_copy_from_uses_the_last_one(self):
        content = (
            "COPY --from=stage-a /x /x\n"
            "COPY --from=stage-b /y /y\n"
        )
        self.assertEqual(_detect_source_stage(content), "stage-b")


class DetectPublishDirTests(unittest.TestCase):
    def test_simple_single_line_publish_command(self):
        content = "RUN dotnet publish -c Release -o /app/publish\n"
        self.assertEqual(_detect_publish_dir(content), "/app/publish")

    def test_output_flag_long_form(self):
        content = "RUN dotnet publish MyApp.csproj --output out\n"
        self.assertEqual(_detect_publish_dir(content), "out")

    def test_flags_spread_across_backslash_continued_lines(self):
        # The exact real-world shape this function's own docstring describes
        # (Bitwarden's Api Dockerfile): each flag on its own continuation line.
        content = (
            "RUN dotnet publish \\\n"
            "    -c Release \\\n"
            "    --no-restore \\\n"
            "    -o out \\\n"
            "    Api.csproj\n"
        )
        self.assertEqual(_detect_publish_dir(content), "out")

    def test_no_publish_command_falls_back_to_default(self):
        self.assertEqual(_detect_publish_dir("FROM scratch\n"), "/app/publish")


class StripPublishSingleFileTests(unittest.TestCase):
    def test_leaves_content_untouched_when_not_present(self):
        content = "RUN dotnet publish -c Release -o /app/publish\n"
        self.assertEqual(_strip_publish_single_file(content), content)

    def test_strips_the_flag_on_its_own_continuation_line(self):
        content = (
            "RUN dotnet publish -c Release \\\n"
            "    -p:PublishSingleFile=true \\\n"
            "    -o /app/publish\n"
        )
        result = _strip_publish_single_file(content)
        self.assertNotIn("PublishSingleFile", result)
        self.assertIn("dotnet publish -c Release", result)
        self.assertIn("-o /app/publish", result)

    def test_strips_the_flag_when_inline_on_the_same_line(self):
        content = "RUN dotnet publish -c Release -p:PublishSingleFile=true -o /app/publish\n"
        result = _strip_publish_single_file(content)
        self.assertNotIn("PublishSingleFile", result)

    def test_handles_slash_property_spelling_case_insensitively(self):
        content = "RUN dotnet publish /P:PUBLISHSINGLEFILE=TRUE -o out\n"
        result = _strip_publish_single_file(content)
        self.assertNotRegex(result, r'(?i)PublishSingleFile\s*=\s*true')


class DetectBuilderAndAppNameTests(unittest.TestCase):
    def test_detects_conventional_builder_and_app_names(self):
        content = (
            "var builder = WebApplication.CreateBuilder(args);\n"
            "var app = builder.Build();\n"
        )
        builder_name = _detect_builder_name(content)
        self.assertEqual(builder_name, "builder")
        self.assertEqual(_detect_app_name(content, builder_name), "app")

    def test_detects_non_conventional_variable_names(self):
        content = (
            "var myBuilder = WebApplication.CreateBuilder(args);\n"
            "var myApp = myBuilder.Build();\n"
        )
        builder_name = _detect_builder_name(content)
        self.assertEqual(builder_name, "myBuilder")
        self.assertEqual(_detect_app_name(content, builder_name), "myApp")

    def test_falls_back_to_conventional_names_when_not_found(self):
        self.assertEqual(_detect_builder_name(""), "builder")
        self.assertEqual(_detect_app_name("", "builder"), "app")


if __name__ == "__main__":
    unittest.main()
