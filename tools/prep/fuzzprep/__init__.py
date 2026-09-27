"""fuzzprep — instruments a .NET solution for coverage-guided fuzzing.

This package is the implementation behind the repo-root `bin/fuzz-prep-multi.py`
entry-point script (a thin wrapper: `from fuzzprep.cli import main`), split
into single-responsibility modules for readability and testability:

  models.py              Shared dataclasses (ProjectInfo, MultiAnalysisResult)
  analysis.py             MultiProjectAnalyzer: scans the solution, classifies
                          business-logic files, builds a MultiAnalysisResult
  detect.py               Pure regex helpers over Dockerfile/C# source text
                          (build/runtime stage detection, publish dir, etc.)
  docker_gen.py           Dockerfile + docker-compose generation/adaptation
  instrumentor_gen.py     Instrumentor tool source copy + zero-edit
                          DOTNET_STARTUP_HOOKS coverage-hook assembly
  coverage_helper_gen.py  Legacy --inject-mode source support (in-source
                          coverage middleware, csproj/Program.cs patching)
  cli.py                  Argument parsing and orchestration (main())

Run via `python3 bin/fuzz-prep-multi.py --src ... --out ...` (unchanged CLI) or
`python3 -m fuzzprep --src ... --out ...`.
"""

from .models import ProjectInfo, MultiAnalysisResult
from .analysis import MultiProjectAnalyzer
from .cli import main

__all__ = ["ProjectInfo", "MultiAnalysisResult", "MultiProjectAnalyzer", "main"]
