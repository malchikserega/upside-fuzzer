#!/usr/bin/env python3
"""
fuzz-prep-multi.py - Multi-Project .NET Business Logic Analyzer for Fuzzing

Thin entry-point wrapper: the actual implementation lives in fuzzprep/ (split
into single-responsibility modules — see fuzzprep/__init__.py for the map).
This file exists so every existing invocation (`python3 fuzz-prep-multi.py
--src ... --out ...`, from docs, upsidefuzz.py, and CI) keeps working
unchanged; it does nothing but forward to fuzzprep.cli.main().

Platform evolution of UpsideFuzz to support solutions with multiple projects/DLLs.
Automatically detects cross-project business logic dependencies and instruments them.

Requirements: .NET 8+
"""

import sys

from fuzzprep.cli import main

if __name__ == "__main__":
    sys.exit(main())
