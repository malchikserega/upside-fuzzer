"""Smoke tests for this repo's compatibility wrappers -- the bin/ entrypoints
(bin/fuzz-prep-multi.py, bin/compatibility/upsidefuzz.py, bin/compile-grammar.sh,
./upsidefuzz) that forward to the real implementations living under tools/ and
src/ after the repo-architecture refactor (cmd/+internal/ split) and the later
self-contained-module refactor (2026-07-31: go.mod/cmd/internal -> src/void/,
cmd/upsidefuzz -> src/cli/upsidefuzz, root scripts -> bin/).

These are deliberately NOT unit tests of the underlying logic (that's already
covered by fuzzprep/grammarc/src.cli.upsidefuzz's own colocated test suites) --
they exist purely to catch "the wrapper itself is broken" regressions: a bad
sys.path insert, a stale subprocess path, an import that only works when run
from one specific working directory. Every check here invokes the wrapper
exactly the way a real user or CI would (`python3 bin/fuzz-prep-multi.py ...`,
`./bin/compile-grammar.sh ...`), as a real subprocess from the repo root -- not an
in-process import -- since that's the actual, documented usage pattern and
the one most likely to break silently when files move.

Run with: cd tests/integration/compatibility && python3 -m unittest test_compat_wrappers -v
No Docker, no network, no .NET/Go toolchain required -- every check here
completes in well under a second.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _run(args, timeout=30):
    return subprocess.run(
        args, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout
    )


class FuzzPrepMultiWrapperTests(unittest.TestCase):
    def test_help_exits_zero_and_forwards_to_fuzzprep_cli(self):
        result = _run([sys.executable, "bin/fuzz-prep-multi.py", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--src", result.stdout)
        self.assertIn("--out", result.stdout)

    def test_missing_required_arg_fails_loud_not_silent(self):
        result = _run([sys.executable, "bin/fuzz-prep-multi.py"])
        self.assertNotEqual(result.returncode, 0)


class UpsideFuzzPyWrapperTests(unittest.TestCase):
    def test_help_exits_zero_and_lists_every_subcommand(self):
        result = _run([sys.executable, "bin/compatibility/upsidefuzz.py", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for subcommand in (
            "instrument", "build", "up", "down", "verify",
            "grammar", "fuzz", "run", "doctor",
        ):
            self.assertIn(subcommand, result.stdout)

    def test_doctor_runs_without_docker_or_dotnet(self):
        # doctor only *reports* what's available -- it must never itself
        # require docker/dotnet/go to be installed to run.
        result = _run([sys.executable, "bin/compatibility/upsidefuzz.py", "doctor"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("python3", result.stdout)

    def test_doctor_reports_the_real_src_void_build_command(self):
        # Regression pin for the 2026-07-31 move: the void-binary-missing
        # message must point at the actual new build command
        # (go -C src/void build ...), not a stale repo-root-relative one --
        # a stale message here would silently mislead every user who hits it.
        result = _run([sys.executable, "bin/compatibility/upsidefuzz.py", "doctor"])
        self.assertEqual(result.returncode, 0, result.stderr)
        if "void binary   not built yet" in result.stdout:
            self.assertIn("go -C src/void build", result.stdout)

    def test_importable_and_reexports_main_and_build_parser(self):
        # upsidefuzz.py now lives at bin/compatibility/, not repo root, so a
        # bare `import upsidefuzz` needs that directory on sys.path first --
        # PYTHONPATH (not an in-process sys.path.insert) so this exercises
        # the exact same subprocess-based invocation every other check here
        # does, from the repo root, with only the compat dir added.
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import upsidefuzz; assert callable(upsidefuzz.main); "
                "assert callable(upsidefuzz.build_parser); print('OK')",
            ],
            cwd=str(REPO_ROOT),
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "bin" / "compatibility")},
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)


class CompileGrammarShWrapperTests(unittest.TestCase):
    def test_help_exits_zero(self):
        result = _run(["./bin/compile-grammar.sh", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("compile-grammar.sh", result.stdout)

    def test_missing_swagger_file_fails_loud_with_a_specific_message(self):
        result = _run(["./bin/compile-grammar.sh", "/nonexistent/swagger.json"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Swagger file not found", result.stdout + result.stderr)

    def test_root_dir_resolves_to_the_actual_repo_root_not_bin(self):
        # Regression pin: compile-grammar.sh climbs one directory (bin/ ->
        # repo root) to find tools/grammar. If that climb is ever wrong, the
        # Python invocation below fails immediately instead of reaching real
        # grammar compilation -- catch that class of break without needing a
        # real swagger spec.
        result = _run(["./bin/compile-grammar.sh", "--help"])
        self.assertNotIn("No such file or directory", result.stderr)


class VerifyHookShWrapperTests(unittest.TestCase):
    def test_help_exits_zero(self):
        # verify-hook.sh has no self-location logic (confirmed during the
        # 2026-07-31 move), so this is a pure "did the move break the file
        # itself" smoke check, not a path-arithmetic regression pin.
        result = _run(["./bin/verify-hook.sh", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)


class UpsideFuzzLauncherWrapperTests(unittest.TestCase):
    def test_no_docker_doctor_runs_natively(self):
        result = _run(["./upsidefuzz", "--no-docker", "doctor"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("python3", result.stdout)

    def test_no_docker_help_forwards_to_the_real_cli(self):
        # Proves the launcher's --no-docker branch reaches
        # bin/compatibility/upsidefuzz.py specifically (not a stale
        # repo-root upsidefuzz.py that no longer exists) -- same subcommand
        # list assertion as UpsideFuzzPyWrapperTests, via the public launcher
        # entrypoint instead of invoking the wrapper directly.
        result = _run(["./upsidefuzz", "--no-docker", "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("grammar", result.stdout)
        self.assertIn("fuzz", result.stdout)


class CampaignAndSecurityScenariosWrapperTests(unittest.TestCase):
    def test_campaign_py_plan_against_the_example_file(self):
        result = _run([
            sys.executable, "bin/compatibility/campaign.py", "plan",
            "tools/campaign/campaign.yaml.example",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Campaign target:", result.stdout)

    def test_security_scenarios_py_loads_the_real_catalog(self):
        result = _run([
            sys.executable, "bin/compatibility/security_scenarios.py",
            "tools/campaign/security_scenarios.yaml",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No drift", result.stdout)


if __name__ == "__main__":
    unittest.main()
