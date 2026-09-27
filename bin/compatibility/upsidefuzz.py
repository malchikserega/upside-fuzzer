#!/usr/bin/env python3
"""upsidefuzz.py - compatibility wrapper.

The actual implementation moved to cmd/upsidefuzz/cli.py during the
repo-architecture refactor, then to src/cli/upsidefuzz/cli.py during the
self-contained-module refactor (2026-07-31), and this wrapper itself moved
from the repo root to bin/compatibility/ in the same pass. This file exists
so every existing invocation (`python3 bin/compatibility/upsidefuzz.py
<subcommand> ...`, the ./upsidefuzz Docker launcher, docs, CI) keeps working
unchanged.

Loaded by file path via importlib rather than a normal package import.
Originally this was required, not just a style choice: when the target lived
at cmd/upsidefuzz/cli.py, `from cmd.upsidefuzz.cli import ...` could never
work because Python's stdlib already owns the top-level name "cmd" (cmd.py,
for line-oriented command interpreters), which always wins that lookup over
a same-named local directory. Now that the target lives at
src/cli/upsidefuzz/cli.py, that specific collision no longer applies (`from
src.cli.upsidefuzz.cli import ...` would work) -- kept as an importlib load
anyway for a minimal diff and because it makes zero assumption about this
wrapper's own working directory or sys.path state, which matters for a
compatibility shim invoked from arbitrary contexts (CI, Docker, docs
examples). cli.py itself has no internal relative imports, so this remains a
safe, complete load either way.
"""

import importlib.util
import sys
from pathlib import Path

_CLI_PATH = Path(__file__).resolve().parent.parent.parent / "src" / "cli" / "upsidefuzz" / "cli.py"
_spec = importlib.util.spec_from_file_location("_upsidefuzz_cli_impl", _CLI_PATH)
_impl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_impl)

main = _impl.main
build_parser = _impl.build_parser

__all__ = ["main", "build_parser"]

if __name__ == "__main__":
    sys.exit(main())
