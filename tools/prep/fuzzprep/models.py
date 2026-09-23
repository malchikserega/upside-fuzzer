"""Shared data structures for the fuzz-prep pipeline.

ProjectInfo/MultiAnalysisResult are the contract every other fuzzprep module
reads and writes -- analysis.py builds a MultiAnalysisResult, and everything
in docker_gen.py/instrumentor_gen.py/coverage_helper_gen.py consumes one.
"""

from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class ProjectInfo:
    """Info about a single project in the solution"""
    name: str
    path: Path
    csproj_path: Path
    is_web: bool
    target_framework: str
    namespaces: List[str]
    business_logic_files: List[str]
    root_namespace: str = ""
    assembly_name: str = ""

    @property
    def dll_name(self) -> str:
        """The project's actual build output filename.

        Defaults to `name` (the project/csproj stem), which is correct for the
        vast majority of .NET projects -- but a project can override
        <AssemblyName> in its own .csproj to ship a differently-named DLL
        (e.g. Jellyfin.Server.csproj -> jellyfin.dll). Every Dockerfile-generation
        codepath must reference this, not `name`, when constructing a real
        on-disk .dll path.
        """
        return f"{self.assembly_name or self.name}.dll"


# Mirrors tools/dotnet/instrumentor/Program.cs's `frameworkPrefixes` — kept in sync manually.
# Used to decide, per solution, whether `--instrument-all-user-code` is safe (see
# `_collides_with_framework_denylist` / MultiAnalysisResult.instrument_all_safe).
FRAMEWORK_DENYLIST_PREFIXES = [
    "System.", "Microsoft.", "SharpFuzz.", "Mono.", "Internal.",
    "Newtonsoft.", "Swashbuckle.", "NSwag.", "FluentValidation.",
    "Serilog.", "MediatR.", "AutoMapper.", "Dapper.",
    "Npgsql.", "MySqlConnector.", "StackExchange.",
    "Polly.", "Grpc.", "Google.Protobuf.",
]


def _collides_with_framework_denylist(root_namespace: str) -> bool:
    probe = root_namespace + "."
    return any(probe.startswith(prefix) for prefix in FRAMEWORK_DENYLIST_PREFIXES)


@dataclass
class MultiAnalysisResult:
    """Aggregated results across all projects"""
    solution_name: str
    projects: List[ProjectInfo]
    main_project: str
    all_namespaces: List[str]
    total_files: int
    instrumented_projects: int
    sdk_version: Optional[str] = None
    exclude_namespaces: List[str] = field(default_factory=list)
    instrument_all_safe: bool = False

