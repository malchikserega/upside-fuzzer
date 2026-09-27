#!/usr/bin/env python3
"""
fuzz-prep-multi.py - Multi-Project .NET Business Logic Analyzer for Fuzzing

Thin entry-point wrapper: the actual implementation lives in
tools/prep/fuzzprep/ (split into single-responsibility modules — see
tools/prep/fuzzprep/__init__.py for the map). This file exists so every
existing invocation (`python3 bin/fuzz-prep-multi.py --src ... --out ...`,
from docs, the upsidefuzz CLI, and CI) keeps working unchanged; it does
nothing but forward to fuzzprep.cli.main(). Lives in bin/ (one directory
below the actual repo root, since 2026-07-31) -- climbs one extra parent to
reach tools/prep versus when this lived at the repo root directly.

Platform evolution of UpsideFuzz to support solutions with multiple projects/DLLs.
Automatically detects cross-project business logic dependencies and instruments them.

Requirements: .NET 8+
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "prep"))

from fuzzprep.cli import main

if __name__ == "__main__":
    sys.exit(main())
