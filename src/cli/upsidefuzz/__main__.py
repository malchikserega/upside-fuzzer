"""Thin entrypoint for cli.py.

Historical note: this package used to live at `cmd/upsidefuzz/`, where
`python3 -m cmd.upsidefuzz`/`import cmd.upsidefuzz` could never work --
Python's own stdlib already owns the top-level name `cmd` (cmd.py, for
line-oriented command interpreters), and always wins that lookup over a
same-named local directory. Moved to `src/cli/upsidefuzz/` in the
self-contained-module refactor (2026-07-31), which incidentally removes that
collision entirely (`src`/`cli` are not stdlib names) -- `python3 -m
src.cli.upsidefuzz` would work fine today. The documented, still-recommended
invocation remains the repo-root `./upsidefuzz` Docker launcher or its
`bin/compatibility/upsidefuzz.py` native fallback (loads this package's
cli.py by file path via importlib), for consistency and because neither
needs the caller to know this package's internal layout at all.

This file itself is invoked the same way regardless: sys.path gets its own
directory so `import cli` resolves as a plain top-level module.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli import main  # noqa: E402  (path insert must come first)

if __name__ == "__main__":
    sys.exit(main())
