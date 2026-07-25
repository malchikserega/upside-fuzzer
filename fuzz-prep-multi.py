#!/usr/bin/env python3
"""
fuzz-prep-multi.py - Multi-Project .NET Business Logic Analyzer for Fuzzing

Platform evolution of UpsideFuzz to support solutions with multiple projects/DLLs.
Automatically detects cross-project business logic dependencies and instruments them.

Requirements: .NET 8+
"""

import os
import re
import json
import sys
import argparse
import shutil
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, asdict, field


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


# Mirrors instrumentor/Program.cs's `frameworkPrefixes` — kept in sync manually.
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


class MultiProjectAnalyzer:
    """Analyzes entire .NET solutions for multi-project instrumentation"""

    BUSINESS_PATTERNS = [
        # Classic MVC / Clean Architecture
        r'.*Controller\.cs$',
        r'.*Service\.cs$',
        r'.*Repository\.cs$',
        r'.*Handler\.cs$',
        r'.*Validator\.cs$',
        r'.*Logic\.cs$',
        r'.*Manager\.cs$',
        r'.*Provider\.cs$',
        # CQRS / MediatR
        r'.*Command\.cs$',
        r'.*Query\.cs$',
        r'.*CommandHandler\.cs$',
        r'.*QueryHandler\.cs$',
        # Minimal API / REPR / FastEndpoints
        r'.*Endpoint\.cs$',
        r'.*Endpoints\.cs$',
        # DDD / Event-Driven
        r'.*Aggregate\.cs$',
        r'.*DomainEvent\.cs$',
        r'.*IntegrationEvent\.cs$',
        r'.*Specification\.cs$',
        # Pipeline / Middleware
        r'.*Filter\.cs$',
        r'.*Middleware\.cs$',
        r'.*Mapper\.cs$',
    ]

    EXCLUDE_PATTERNS = [
        r'.*/obj/.*', r'.*/bin/.*', r'.*\.Designer\.cs$', r'.*\.g\.cs$',
        r'.*\.AssemblyInfo\.cs$', r'.*/Migrations/.*', r'.*/Program\.cs$',
        r'.*/Startup\.cs$',
    ]

    BUSINESS_DIRECTORIES = {
        'Controllers', 'Services', 'Handlers', 'Repositories',
        'Commands', 'Queries', 'Endpoints', 'Features',
        'Domain', 'Application', 'UseCases', 'CQRS',
        'Aggregates', 'Events', 'Validators', 'Specifications',
    }

    def __init__(self, src_path: str, verbose: bool = True):
        self.src_path = Path(src_path)
        self.verbose = verbose

    def log(self, message: str):
        if self.verbose:
            print(message)

    def _detect_sdk_version(self) -> Optional[str]:
        """Read SDK version from global.json if present"""
        global_json = self.src_path / "global.json"
        if global_json.exists():
            try:
                data = json.loads(global_json.read_text())
                return data.get("sdk", {}).get("version")
            except Exception:
                pass
        return None

    def _extract_root_namespace(self, csproj_content: str, csproj_stem: str) -> str:
        """Extract RootNamespace from csproj, falling back to project name"""
        m = re.search(r'<RootNamespace>(.*?)</RootNamespace>', csproj_content)
        return m.group(1) if m else csproj_stem

    @staticmethod
    def _target_framework_from_xml(content: str) -> Optional[str]:
        """Pull the highest net* TFM out of a <TargetFramework(s)> tag, if present."""
        m = re.search(r'<TargetFrameworks?>(.*?)</TargetFrameworks?>', content)
        if not m:
            return None
        fw_value = m.group(1)
        if ';' in fw_value:
            frameworks = [f.strip() for f in fw_value.split(';')]
            net_versions = [f for f in frameworks if f.startswith('net') and not f.startswith('netstandard')]
            return sorted(net_versions, reverse=True)[0] if net_versions else frameworks[0]
        return fw_value

    def _resolve_target_framework(self, csproj_content: str, csproj_path: Path) -> str:
        """Resolve the effective TargetFramework for a project.

        Many modern .NET solutions (Bitwarden's server repo included) centralize
        `<TargetFramework>` in a `Directory.Build.props` at the solution root instead
        of repeating it in every .csproj — MSBuild merges it in automatically. The
        previous version of this check only looked inside the individual .csproj and
        silently defaulted to "net8.0" otherwise, which is wrong for any such solution
        and (for Bitwarden specifically) picked a net8.0 SDK image for the tool's own
        injected build stages against a net10.0 target. Walk up from the project
        directory toward the source root, checking each Directory.Build.props found,
        nearest first, before giving up and using the "net8.0" fallback.
        """
        fw = self._target_framework_from_xml(csproj_content)
        if fw:
            return fw
        directory = csproj_path.parent
        src_root = self.src_path.resolve()
        while True:
            props = directory / "Directory.Build.props"
            if props.exists():
                try:
                    fw = self._target_framework_from_xml(props.read_text(encoding='utf-8'))
                except Exception:
                    fw = None
                if fw:
                    self.log(f"  (TargetFramework {fw} resolved from {props.relative_to(src_root) if directory.resolve() != src_root else props.name})")
                    return fw
            resolved = directory.resolve()
            if resolved == src_root or directory.parent == directory:
                break
            directory = directory.parent
        return "net8.0"

    def _is_business_logic(self, cs_path: Path, project_dir: Path) -> bool:
        """Determine if a .cs file contains business logic worth instrumenting"""
        filename = cs_path.name

        if any(re.match(p, filename) for p in self.BUSINESS_PATTERNS):
            return True

        rel_parts = cs_path.relative_to(project_dir).parts
        if any(part in self.BUSINESS_DIRECTORIES for part in rel_parts):
            return True

        return False

    def analyze_solution(self, manual_main: Optional[str] = None) -> MultiAnalysisResult:
        self.log("\n" + "=" * 70)
        self.log("  UpsideFuzz: Multi-Project Solution Analyzer")
        self.log("=" * 70 + "\n")

        sdk_version = self._detect_sdk_version()
        if sdk_version:
            self.log(f"  Detected SDK version from global.json: {sdk_version}")

        csproj_files = list(self.src_path.rglob('*.csproj'))
        csproj_files = [p for p in csproj_files if 'instrumentor' not in str(p) and 'instrumented' not in str(p)]

        self.log(f"  Found {len(csproj_files)} projects in solution.")

        projects = []
        all_namespaces = set()
        total_files_count = 0
        main_project_name = ""

        for csproj in csproj_files:
            project_dir = csproj.parent
            rel_dir = project_dir.relative_to(self.src_path)
            csproj_lower = csproj.stem.lower()

            # Skip test projects entirely -- they shouldn't be instrumented
            if ('test' in csproj_lower
                    or '/test/' in str(csproj).lower()
                    or '\\test\\' in str(csproj).lower()):
                self.log(f"\n--- Skipping Test Project: {csproj.name} ---")
                continue

            self.log(f"\n--- Analyzing Project: {csproj.name} ---")

            content = csproj.read_text()
            is_web = (
                'Sdk="Microsoft.NET.Sdk.Web"' in content
                or (project_dir / 'Startup.cs').exists()
                or (project_dir / 'Program.cs').exists()
            )
            root_ns = self._extract_root_namespace(content, csproj.stem)

            # Accept --main as either a bare stem ('Api') or a path suffix ('src/Api')
            # so both invocations match the correct project.
            manual_main_stem = Path(manual_main).stem if manual_main else None
            if manual_main and (
                csproj.stem.lower() == manual_main.lower()
                or (manual_main_stem and csproj.stem.lower() == manual_main_stem.lower())
            ):
                main_project_name = csproj.stem
                is_web = True
                self.log(f"  * Forced Main Project: {main_project_name}")
            elif not manual_main and is_web and not main_project_name:
                main_project_name = csproj.stem

            # Handle both <TargetFramework> and <TargetFrameworks>, falling back to
            # Directory.Build.props if the csproj itself doesn't declare one.
            framework = self._resolve_target_framework(content, csproj)

            cs_files = list(project_dir.rglob('*.cs'))
            total_files_count += len(cs_files)

            project_namespaces = set()
            business_files = []

            for cs in cs_files:
                if any(re.match(p, str(cs)) for p in self.EXCLUDE_PATTERNS):
                    continue

                ns = ""
                try:
                    txt = cs.read_text(encoding='utf-8')
                    # Anchored to line start (mod. leading whitespace) and requiring the
                    # `;` (file-scoped) or `{` (block-scoped) terminator that a real C#
                    # namespace declaration has — a bare `r'namespace\s+([\w.]+)'` search
                    # also matches free text inside comments (e.g. "// TODO: move this
                    # namespace to Bit.Foo"), which silently mis-detects the namespace for
                    # that file (seen in Bitwarden's IPushRegistrationService.cs, which
                    # captured "to" from a comment instead of its real namespace).
                    m = re.search(r'^[ \t]*namespace\s+([\w][\w.]*)\s*[{;]', txt, re.MULTILINE)
                    if m:
                        ns = m.group(1)
                except Exception:
                    continue

                if self._is_business_logic(cs, project_dir):
                    business_files.append(str(cs.relative_to(project_dir)))
                    if ns:
                        project_namespaces.add(ns)
                        all_namespaces.add(ns)

            if business_files:
                self.log(f"  + {len(business_files)} business logic files detected.")
                projects.append(ProjectInfo(
                    name=csproj.stem,
                    path=rel_dir,
                    csproj_path=csproj,
                    is_web=is_web,
                    target_framework=framework,
                    namespaces=sorted(list(project_namespaces)),
                    business_logic_files=sorted(business_files),
                    root_namespace=root_ns,
                ))
            elif csproj.stem == main_project_name:
                self.log(f"  + Included as Main Project (despite 0 detected logic files).")
                projects.append(ProjectInfo(
                    name=csproj.stem,
                    path=rel_dir,
                    csproj_path=csproj,
                    is_web=is_web,
                    target_framework=framework,
                    namespaces=sorted(list(project_namespaces)),
                    business_logic_files=[],
                    root_namespace=root_ns,
                ))
            else:
                self.log("  - No significant business logic detected in this project.")

        if not main_project_name and projects:
            main_project_name = projects[0].name

        exclude_namespaces = getattr(self, 'exclude_namespaces', [])

        # --instrument-all-user-code is strictly more complete than the namespace
        # allowlist (no BUSINESS_PATTERNS/BUSINESS_DIRECTORIES naming-convention gaps —
        # see skipped_no_match in instrumentor output) — but it's only SAFE when the
        # solution's own root namespace(s) don't collide with the hardcoded framework
        # prefix denylist (e.g. Microsoft.eShopWeb.* collides with "Microsoft."), which
        # would silently exclude the target's own business logic. Decide per-solution
        # instead of hardcoding one mode for every target. An explicit
        # --exclude-namespaces always forces allowlist mode, since instrumentAll has no
        # exclude mechanism of its own.
        instrument_all_safe = bool(projects) and not exclude_namespaces and not any(
            _collides_with_framework_denylist(p.root_namespace) for p in projects
        )
        if projects:
            colliding = [p.root_namespace for p in projects if _collides_with_framework_denylist(p.root_namespace)]
            if colliding:
                self.log(f"\n  Root namespace(s) collide with the framework denylist ({', '.join(sorted(set(colliding)))}) "
                         f"— using namespace allowlist mode, not --instrument-all-user-code.")
            elif exclude_namespaces:
                self.log(f"\n  --exclude-namespaces given — using namespace allowlist mode, not --instrument-all-user-code.")
            else:
                self.log(f"\n  No root namespace collides with the framework denylist — using "
                         f"--instrument-all-user-code (covers 100% of non-framework/generated code, "
                         f"no naming-convention gaps).")

        return MultiAnalysisResult(
            solution_name=self.src_path.name,
        projects=projects,
        main_project=main_project_name,
        all_namespaces=sorted(list(all_namespaces)),
        total_files=total_files_count,
        instrumented_projects=len(projects),
        exclude_namespaces=exclude_namespaces,
        sdk_version=sdk_version,
        instrument_all_safe=instrument_all_safe,
    )


# ============================================================================
# Dockerfile & Compose generation
# ============================================================================

def _detect_last_stage(content: str) -> Optional[str]:
    """Find the name of the last named stage (the runtime/final stage)"""
    stages = re.findall(r'FROM\s+\S+\s+AS\s+(\w+)', content, re.IGNORECASE)
    return stages[-1] if stages else None


def _detect_publish_dir(content: str) -> str:
    """Extract publish output directory from Dockerfile.

    re.DOTALL is required: real-world `dotnet publish` invocations are commonly
    spread across multiple backslash-continued lines (e.g. Bitwarden's Api
    Dockerfile puts each flag, including `-o out`, on its own line), and without
    it `.` never crosses the embedded newlines, so the search silently fails and
    falls back to the "/app/publish" default — which is wrong for any Dockerfile
    using a different output directory, and produces instrumentation RUN commands
    that check a path with nothing in it (silently instrumenting zero DLLs).
    """
    m = re.search(r'dotnet\s+publish\b.*?(?:-o|--output)\s+(\S+)', content, re.DOTALL)
    return m.group(1) if m else "/app/publish"


# MSBuild property flag spellings that enable single-file bundling: -p:, /p:,
# --property:, -property: (all case-insensitive; MSBuild treats -p and /p the same).
_PUBLISH_SINGLEFILE_LINE_RE = re.compile(
    r'^[ \t]*[-/]p(?:roperty)?:PublishSingleFile=true[ \t]*\\?[ \t]*\r?\n',
    re.IGNORECASE | re.MULTILINE,
)
_PUBLISH_SINGLEFILE_INLINE_RE = re.compile(
    r'[ \t]*[-/]p(?:roperty)?:PublishSingleFile=true', re.IGNORECASE
)


def _strip_publish_single_file(content: str) -> str:
    """Disable PublishSingleFile in the target's own `dotnet publish` command.

    WHY: PublishSingleFile bundles every managed dependency assembly (the app's
    own DLLs included) into one native executable — SharpFuzz/Cecil rewrites IL
    in loose .dll files, and there are none to rewrite once the app is bundled
    this way (only .pdb symbol files and non-.NET native interop DLLs remain on
    disk; e.g. Bitwarden's `Api.dll` and `Core.dll` become embedded resources
    inside the `Api` ELF bundle with nothing left to instrument). Without this,
    the instrumentation RUN commands silently no-op (the `if [ -f ... ]` guard
    finds no file and just prints a WARN) and the fuzzer runs against completely
    uninstrumented code with a flat, always-zero coverage signal.

    This only changes our own instrumented build variant — the target's real
    release Dockerfile on disk is untouched by this tool.
    """
    if not re.search(r'PublishSingleFile\s*=\s*true', content, re.IGNORECASE):
        return content
    new_content = _PUBLISH_SINGLEFILE_LINE_RE.sub('', content)
    new_content = _PUBLISH_SINGLEFILE_INLINE_RE.sub('', new_content)
    if new_content != content:
        print("  Detected PublishSingleFile=true — disabled for the instrumented build "
              "(single-file bundling leaves no loose .dll files for SharpFuzz/Cecil to rewrite).")
    return new_content


def _detect_source_stage(content: str) -> str:
    """Find the build stage that the runtime stage copies from"""
    copy_matches = list(re.finditer(r'COPY\s+--from=(\S+)', content))
    return copy_matches[-1].group(1) if copy_matches else "builder"


def generate_multi_docker_configs(result: MultiAnalysisResult, output_path: Path, inject_mode: str = "hook"):
    """Adapt original Dockerfile if present, or generate from scratch.

    inject_mode:
      'hook'   — zero-edit: build the UpsideFuzz.Coverage assembly in a dedicated
                 stage, drop it (and SharpFuzz.Common.dll) into /coverage in the
                 runtime image, and wire DOTNET_STARTUP_HOOKS +
                 ASPNETCORE_HOSTINGSTARTUPASSEMBLIES via ENV. No app source edits.
      'source' — legacy: coverage lives in CoverageExtensions.cs injected into the app.
    """

    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])
    framework = main_proj.target_framework
    fw_tag = framework.replace('net', '')

    # Build stage that compiles the zero-edit coverage hook assembly (hook mode only).
    coverage_hook_stage = ""
    if inject_mode == "hook":
        coverage_hook_stage = f"""
# Stage: Build the zero-edit UpsideFuzz.Coverage hook assembly
FROM mcr.microsoft.com/dotnet/sdk:{fw_tag} AS coverage-hook-build
WORKDIR /covhook
COPY coverage_hook_src/ ./
RUN dotnet publish -c Release -o /covhook/out
"""

    # Runtime-stage lines that install the hook DLLs and wire the env vars.
    def _hook_runtime_block() -> str:
        return (
            "\n# ---- UpsideFuzz zero-edit coverage hook (DOTNET_STARTUP_HOOKS) ----\n"
            "COPY --from=coverage-hook-build /covhook/out/UpsideFuzz.Coverage.dll /coverage/UpsideFuzz.Coverage.dll\n"
            "COPY --from=coverage-hook-build /covhook/out/SharpFuzz.Common.dll /coverage/SharpFuzz.Common.dll\n"
            "ENV DOTNET_STARTUP_HOOKS=/coverage/UpsideFuzz.Coverage.dll\n"
            "ENV ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=UpsideFuzz.Coverage\n"
            "# ---- END coverage hook ----\n"
        )

    # Use SDK version from global.json if available, otherwise derive from framework
    sdk_tag = fw_tag
    if result.sdk_version:
        major = result.sdk_version.split('.')[0]
        if major.isdigit() and int(major) >= 8:
            sdk_tag = fw_tag

    dll_names = [f"{p.name}.dll" for p in result.projects]

    # --- Find Dockerfile ---
    original_dockerfile = None
    candidates = list(output_path.rglob('Dockerfile')) + list(output_path.rglob('dockerfile'))
    candidates = [c for c in candidates
                  if 'instrumentor' not in str(c) and '/bin/' not in str(c) and '/obj/' not in str(c)]

    if candidates:
        for c in candidates:
            if result.main_project.lower() in str(c).lower():
                original_dockerfile = c
                break
        if not original_dockerfile:
            original_dockerfile = candidates[0]

    if original_dockerfile:
        print(f"  Found original Dockerfile: {original_dockerfile}")
        content = original_dockerfile.read_text()
        content = _strip_publish_single_file(content)

        publish_dir = _detect_publish_dir(content)
        source_stage = _detect_source_stage(content)
        runtime_stage = _detect_last_stage(content)

        print(f"  Detected build stage: {source_stage}, runtime stage: {runtime_stage or '(unnamed)'}")

        # Choose --instrument-all-user-code when safe (result.instrument_all_safe,
        # decided in analyze_solution), namespace allowlist (namespaces.json)
        # otherwise.
        #
        # WHY namespace allowlist exists at all: --instrument-all-user-code has a
        # hardcoded framework prefix filter that includes "Microsoft." — silently
        # skipping ALL Microsoft.eShopWeb.* (and similar) business logic. This caused
        # edges=0 on eShopOnWeb because zero real business logic was instrumented.
        # The namespace allowlist check runs BEFORE the framework prefix filter, so
        # explicitly listed namespaces like Microsoft.eShopWeb.* are instrumented
        # even though they carry the "Microsoft." prefix.
        #
        # WHY --instrument-all-user-code is preferred when safe: the allowlist is
        # only as complete as BUSINESS_PATTERNS/BUSINESS_DIRECTORIES — any namespace
        # whose files don't match one of those naming conventions is silently
        # excluded (seen on Bitwarden: skipped_no_match in the hundreds per DLL even
        # with 332 auto-collected namespaces). Bitwarden's own root namespaces
        # ("Bit.*") don't collide with the framework denylist, so instrument-all
        # is both safe and strictly more complete there.
        #
        # namespaces.json is still generated from source analysis either way (used
        # by --config in allowlist mode; harmless/unused in instrument-all mode) and
        # copied into the image at /instrumentor/bin/namespaces.json (see
        # injected_stages below). Fail-loud (exit 1) so an under-instrumented image
        # never ships unnoticed.
        unique_dlls = sorted(list(set(dll_names)))
        if result.instrument_all_safe:
            instrument_flag = "--instrument-all-user-code"
            mode_label = "instrument-all-user-code"
        else:
            instrument_flag = "--config /instrumentor/bin/namespaces.json"
            mode_label = "namespace allowlist"
        # Top-20+ #21: CmpLog only in hook mode -- its recorder calls target
        # UpsideFuzz.Coverage.CmpLogProbe by assembly name, which only resolves at
        # runtime when DOTNET_STARTUP_HOOKS actually loads that assembly. A
        # --inject-mode source build never loads it, so passing --cmplog there would
        # just throw at the first instrumented comparison call.
        if inject_mode == "hook":
            instrument_flag += " --cmplog"
        instrument_cmds = "\n".join([
            f'RUN if [ -f {publish_dir}/{dll} ]; then '
            f'echo "Instrumenting {dll} ({mode_label})"; '
            f'DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll {publish_dir}/{dll} '
            f'{instrument_flag} '
            f'|| {{ echo "FATAL: instrumentation failed for {dll}"; exit 1; }}; '
            f'else echo "WARN: {dll} not found (skipping)"; fi'
            for dll in unique_dlls
        ])


        injected_stages = f"""
# ---- INJECTED BY fuzz-prep-multi.py ----
# Stage: Build the SharpFuzz instrumentor
FROM mcr.microsoft.com/dotnet/sdk:{sdk_tag} AS instrumentor-build
WORKDIR /instrumentor
RUN dotnet new console -n instrumentor -o . --force
COPY instrumentor_src/Program.cs ./
COPY instrumentor_src/namespaces.json ./
RUN dotnet add package SharpFuzz
RUN dotnet add package System.Text.Json
RUN dotnet add package Mono.Cecil --version 0.11.6
RUN dotnet build -c Release -o /instrumentor/bin
RUN cp namespaces.json /instrumentor/bin/namespaces.json

# Stage: Apply instrumentation to published DLLs
FROM {source_stage} AS instrumentation
COPY --from=instrumentor-build /instrumentor/bin /instrumentor/bin
{instrument_cmds}
{coverage_hook_stage}
# ---- END INSTRUMENTATION ----
"""
        # Insert injected stages before the runtime/final stage
        if runtime_stage:
            runtime_pattern = re.compile(
                rf'^(FROM\s+\S+\s+AS\s+{re.escape(runtime_stage)})',
                re.MULTILINE | re.IGNORECASE
            )
            runtime_match = runtime_pattern.search(content)
            if runtime_match:
                pos = runtime_match.start()
                content = content[:pos] + injected_stages + "\n" + content[pos:]
        else:
            # No named stages: insert before the last FROM
            from_matches = list(re.finditer(r'^FROM\s+', content, re.MULTILINE))
            if len(from_matches) >= 2:
                pos = from_matches[-1].start()
                content = content[:pos] + injected_stages + "\n" + content[pos:]

        # Replace COPY --from= ONLY in the runtime/final stage section (not globally)
        if runtime_stage:
            rt_pattern = re.compile(
                rf'(FROM\s+\S+\s+AS\s+{re.escape(runtime_stage)})(.*)',
                re.DOTALL | re.IGNORECASE
            )
            rt_match = rt_pattern.search(content)
            if rt_match:
                before_runtime = content[:rt_match.start()]
                runtime_header = rt_match.group(1)
                runtime_body = rt_match.group(2)
                runtime_body = runtime_body.replace(
                    f'--from={source_stage}', '--from=instrumentation'
                )
                content = before_runtime + runtime_header + runtime_body
        else:
            content = content.replace(f'--from={source_stage}', '--from=instrumentation')

        # Hook mode: drop the coverage assembly + env vars into the runtime stage.
        if inject_mode == "hook":
            hook_block = _hook_runtime_block()
            if runtime_stage:
                content = re.sub(
                    rf'(?m)^(FROM\s+\S+\s+AS\s+{re.escape(runtime_stage)}[^\n]*\n)',
                    lambda m: m.group(0) + hook_block,
                    content, count=1
                )
            else:
                froms = list(re.finditer(r'(?m)^FROM[^\n]*\n', content))
                if froms:
                    last = froms[-1]
                    content = content[:last.end()] + hook_block + content[last.end():]

        original_dockerfile.write_text(content)
        print("  Adapted original Dockerfile with instrumentation stages.")

        # Warn about .dockerignore
        dockerignore = original_dockerfile.parent / ".dockerignore"
        if dockerignore.exists():
            di_content = dockerignore.read_text()
            if 'instrumentor_src' not in di_content and ('*' in di_content or '!' in di_content):
                di_content += "\n!instrumentor_src/\n"
                dockerignore.write_text(di_content)
                print("  Updated .dockerignore to allow instrumentor_src/")
    else:
        print("  No original Dockerfile found, generating from scratch.")
        dll_list = [f"/src/{p.path}/bin/Release/{p.target_framework}/{p.name}.dll" for p in result.projects]
        instrument_flag = "--instrument-all-user-code" if result.instrument_all_safe else "--config /instrumentor/bin/namespaces.json"
        # Top-20+ #21: see the matching comment in the "adapt original Dockerfile"
        # branch above -- CmpLog only makes sense (and only gets wired) in hook mode.
        if inject_mode == "hook":
            instrument_flag += " --cmplog"
        instrument_commands = "\n".join(
            [f"RUN DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll {dll} {instrument_flag}" for dll in dll_list]
        )

        dockerfile_content = f"""# AUTO-GENERATED by fuzz-prep-multi.py
FROM mcr.microsoft.com/dotnet/sdk:{sdk_tag} AS build
WORKDIR /src
COPY . ./
RUN dotnet restore
RUN dotnet build -c Release -p:CreateLauncher=false

FROM mcr.microsoft.com/dotnet/sdk:{sdk_tag} AS instrumentor-build
WORKDIR /instrumentor
RUN dotnet new console -n instrumentor -o . --force
COPY instrumentor_src/Program.cs ./
COPY instrumentor_src/namespaces.json ./
RUN dotnet add package SharpFuzz
RUN dotnet add package System.Text.Json
RUN dotnet add package Mono.Cecil --version 0.11.6
RUN dotnet build -c Release -o /instrumentor/bin
RUN cp namespaces.json /instrumentor/bin/namespaces.json

FROM build AS instrumentation
COPY --from=instrumentor-build /instrumentor/bin /instrumentor/bin
{instrument_commands}
{coverage_hook_stage}
FROM mcr.microsoft.com/dotnet/aspnet:{fw_tag}
WORKDIR /app
COPY --from=instrumentation /src/{main_proj.path}/bin/Release/{main_proj.target_framework}/ .
{_hook_runtime_block() if inject_mode == "hook" else ""}EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "{main_proj.name}.dll"]
"""
        (output_path / "Dockerfile").write_text(dockerfile_content)
        print("  Generated Dockerfile from scratch.")

    # --- Adapt compose file ---
    original_compose = None
    for name in ['compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml']:
        candidate = output_path / name
        if candidate.exists():
            original_compose = candidate
            break

    if original_compose:
        print(f"  Found original compose: {original_compose.name}")
        compose_content = original_compose.read_text()

        # Detect services by indentation (2-space or 4-space indented under services:)
        main_svc_regex = re.compile(r'^\s{2,4}(\w[\w-]*):\s*$', re.MULTILINE)
        raw_services = [m.group(1) for m in main_svc_regex.finditer(compose_content)]
        ignored_keys = {'version', 'services', 'volumes', 'networks', 'secrets', 'configs'}
        services = [s for s in raw_services if s not in ignored_keys and not s.startswith('x-')]

        target_service = None
        if result.main_project.lower() in services:
            target_service = result.main_project.lower()
        else:
            for s in services:
                if result.main_project.lower() in s.lower() and 'db' not in s and 'sql' not in s:
                    target_service = s
                    break

        if not target_service and services:
            target_service = services[0]

        if target_service:
            print(f"  Targeting service for SHM: {target_service}")

            # Detect exact indent level of this service to find block boundaries
            svc_indent_match = re.search(
                rf'^(\s+){re.escape(target_service)}:',
                compose_content, re.MULTILINE
            )
            svc_indent = svc_indent_match.group(1) if svc_indent_match else "  "

            # Capture from service name to next line at the SAME indent or end of file
            service_pattern = re.compile(
                rf'(^{re.escape(svc_indent)}{re.escape(target_service)}:.*?)'
                rf'(^{re.escape(svc_indent)}[A-Za-z0-9_-]+:|\Z)',
                re.MULTILINE | re.DOTALL
            )
            match = service_pattern.search(compose_content)

            if match:
                block = match.group(1)
                # Determine service child indent from existing keys in the service block.
                child_indent = svc_indent + "  "
                for line in block.splitlines()[1:]:
                    m = re.match(r'^(\s+)[A-Za-z0-9_-]+:\s*', line)
                    if m and len(m.group(1)) > len(svc_indent):
                        child_indent = m.group(1)
                        break

                if '/dev/shm' not in block:
                    # Derive nested entry indentation from existing content if possible.
                    nested_indent_match = re.search(
                        rf'(?m)^({re.escape(child_indent)}\s+)\S',
                        block
                    )
                    entry_indent = nested_indent_match.group(1) if nested_indent_match else (child_indent + "  ")
                    volumes_key_re = re.compile(rf'(?m)^({re.escape(child_indent)}volumes:\s*)$')
                    if volumes_key_re.search(block):
                        block = volumes_key_re.sub(
                            rf"\1\n{entry_indent}- /dev/shm:/dev/shm\n{entry_indent}- coverage_shm:/coverage_shm",
                            block,
                            count=1,
                        )
                    else:
                        block = re.sub(
                            rf'(?m)^({re.escape(svc_indent)}{re.escape(target_service)}:\s*)$',
                            rf"\1\n{child_indent}volumes:\n{entry_indent}- /dev/shm:/dev/shm\n{entry_indent}- coverage_shm:/coverage_shm",
                            block,
                            count=1,
                        )

                # Inject ASPNETCORE_ENVIRONMENT into THIS service's block only
                if 'ASPNETCORE_ENVIRONMENT' not in block:
                    env_key_re = re.compile(rf'(?m)^({re.escape(child_indent)}environment:\s*)$')
                    nested_indent_match = re.search(
                        rf'(?m)^({re.escape(child_indent)}\s+)\S',
                        block
                    )
                    entry_indent = nested_indent_match.group(1) if nested_indent_match else (child_indent + "  ")
                    if env_key_re.search(block):
                        # Preserve existing style: list (`- KEY=VALUE`) or map (`KEY: VALUE`).
                        env_block_match = re.search(
                            rf'(?ms)^{re.escape(child_indent)}environment:\s*\n(.*?)(?=^{re.escape(child_indent)}[A-Za-z0-9_-]+:\s*|\Z)',
                            block
                        )
                        env_is_list = False
                        if env_block_match:
                            env_body = env_block_match.group(1)
                            env_is_list = re.search(r'(?m)^\s*-\s', env_body) is not None
                        env_line = "- ASPNETCORE_ENVIRONMENT=Development" if env_is_list else "ASPNETCORE_ENVIRONMENT: Development"
                        block = env_key_re.sub(
                            rf"\1\n{entry_indent}{env_line}",
                            block,
                            count=1,
                        )
                    else:
                        block = re.sub(
                            rf'(?m)^({re.escape(svc_indent)}{re.escape(target_service)}:\s*)$',
                            rf"\1\n{child_indent}environment:\n{entry_indent}ASPNETCORE_ENVIRONMENT: Development",
                            block,
                            count=1,
                        )

                compose_content = compose_content.replace(match.group(1), block)

            # Add top-level coverage_shm volume definition if not present
            # (check for indented definition, not the mount reference like "- coverage_shm:/...")
            if not re.search(r'^\s{2}coverage_shm:', compose_content, re.MULTILINE):
                coverage_vol_block = (
                    "\nvolumes:\n"
                    "  coverage_shm:\n"
                    "    driver: local\n"
                    "    driver_opts:\n"
                    "      type: tmpfs\n"
                    "      device: tmpfs\n"
                    "      o: size=4m\n"
                )
                # Append to existing top-level volumes: or add new block
                if re.search(r'^volumes:\s*$', compose_content, re.MULTILINE):
                    compose_content = re.sub(
                        r'^(volumes:\s*)$',
                        r'\1\n  coverage_shm:\n'
                        r'    driver: local\n'
                        r'    driver_opts:\n'
                        r'      type: tmpfs\n'
                        r'      device: tmpfs\n'
                        r'      o: size=4m',
                        compose_content, count=1, flags=re.MULTILINE
                    )
                else:
                    compose_content += coverage_vol_block

            # Add commented-out smartfuzzer sidecar service
            if not re.search(r'^\s+smartfuzzer:', compose_content, re.MULTILINE):
                svc_name = target_service or 'app'
                fuzzer_block = (
                    "\n"
                    "  # --- Void sidecar (uncomment to use direct SHM mode) ---\n"
                    "  # smartfuzzer:\n"
                    "  #   build:\n"
                    "  #     context: ../void\n"
                    "  #     dockerfile: Dockerfile\n"
                    "  #   volumes:\n"
                    "  #     - coverage_shm:/coverage_shm\n"
                    "  #   environment:\n"
                    f"  #     - TARGET_HOST=http://{svc_name}:8080\n"
                    f"  #     - SHM_HOST=http://{svc_name}:8080\n"
                    "  #   command: [\"--direct-shm\", \"--time-budget\", \"2\"]\n"
                    "  #   depends_on:\n"
                    f"  #     - {svc_name}\n"
                )
                # Insert before top-level volumes: if it exists, otherwise at end of services
                vol_match = re.search(r'^volumes:', compose_content, re.MULTILINE)
                if vol_match:
                    compose_content = (
                        compose_content[:vol_match.start()]
                        + fuzzer_block + "\n"
                        + compose_content[vol_match.start():]
                    )
                else:
                    compose_content += fuzzer_block

        else:
            print("  Could not identify target service for SHM injection.")

        original_compose.write_text(compose_content)
        print("  Adapted original compose with /dev/shm + coverage_shm volumes.")
    else:
        docker_compose_content = """services:
  instrumented:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "7777:8080"
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
    volumes:
      - /dev/shm:/dev/shm
      - coverage_shm:/coverage_shm

  # --- Void sidecar (uncomment to use direct SHM mode) ---
  # smartfuzzer:
  #   build:
  #     context: ../void
  #     dockerfile: Dockerfile
  #   volumes:
  #     - coverage_shm:/coverage_shm
  #   environment:
  #     - TARGET_HOST=http://instrumented:8080
  #     - SHM_HOST=http://instrumented:8080
  #   command: ["--direct-shm", "--time-budget", "2"]
  #   depends_on:
  #     - instrumented

volumes:
  coverage_shm:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=4m
"""
        (output_path / "docker-compose.instrumented.yml").write_text(docker_compose_content)
        print("  Generated compose file from scratch.")


# ============================================================================
# Instrumentor generation
# ============================================================================

def generate_unified_instrumentor(result: MultiAnalysisResult, output_path: Path):
    """Generate config-driven instrumentor using the generic Program.cs and a namespaces.json config."""

    instr_dir = output_path / "instrumentor_src"
    instr_dir.mkdir(parents=True, exist_ok=True)

    # Copy the generic instrumentor from the repository root
    repo_instrumentor = Path(__file__).parent / "instrumentor" / "Program.cs"
    if repo_instrumentor.exists():
        shutil.copy2(repo_instrumentor, instr_dir / "Program.cs")
        print(f"  Copied generic instrumentor from {repo_instrumentor}")
    else:
        # Fallback: write a minimal version inline (e.g. when running from a packaged install)
        print("  WARNING: instrumentor/Program.cs not found at expected path, writing inline fallback")
        (instr_dir / "Program.cs").write_text(_FALLBACK_INSTRUMENTOR_CS)

    # Generate namespaces.json config with discovered business-logic namespaces
    config_data = {
        "namespaces": sorted(set(result.all_namespaces)),
        "excludes": sorted(set(result.exclude_namespaces))
    }
    config_path = instr_dir / "namespaces.json"
    config_path.write_text(json.dumps(config_data, indent=2))
    print(f"  Generated namespaces.json with {len(result.all_namespaces)} allowed, {len(result.exclude_namespaces)} excluded namespace(s).")


# Inline fallback instrumentor for when the repo file isn't accessible.
_FALLBACK_INSTRUMENTOR_CS = r'''
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

if (args.Length == 0) { Console.Error.WriteLine("Usage: instrumentor <dll> [--namespaces Ns1 Ns2] [--instrument-all-user-code]"); return; }
string dllPath = args[0];
bool instrumentAll = args.Any(a => a == "--instrument-all-user-code");
var allowedNamespaces = new List<string>();
var excludedNamespaces = new List<string>();
for (int i = 1; i < args.Length; i++)
    if (args[i] == "--namespaces") for (int j = i+1; j < args.Length && !args[j].StartsWith("--"); j++) { allowedNamespaces.Add(args[j]); i = j; }
if (allowedNamespaces.Count == 0 && !instrumentAll) {
    var cfgPath = Path.Combine(Path.GetDirectoryName(dllPath) ?? ".", "namespaces.json");
    if (File.Exists(cfgPath)) {
        var doc = JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(File.ReadAllText(cfgPath));
        if (doc != null && doc.TryGetValue("namespaces", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var e in arr.EnumerateArray()) { var v = e.GetString(); if (!string.IsNullOrWhiteSpace(v)) allowedNamespaces.Add(v); }
        if (doc != null && doc.TryGetValue("excludes", out var extArr) && extArr.ValueKind == JsonValueKind.Array)
            foreach (var e in extArr.EnumerateArray()) { var v = e.GetString(); if (!string.IsNullOrWhiteSpace(v)) excludedNamespaces.Add(v); }
    }
}
if (allowedNamespaces.Count == 0 && !instrumentAll) { Console.Error.WriteLine("ERROR: no namespaces"); Environment.Exit(1); }
var skip = new[]{"System.","Microsoft.","SharpFuzz.","Mono.","Internal."};
bool Filter(string fn) {
    if (fn.Contains("<PrivateImplementationDetails>") || fn.Contains("c__DisplayClass") || fn.Contains("d__") || fn.Contains(".g.")) return false;
    foreach (var p in skip) if (fn.StartsWith(p)) return false;
    foreach (var ex in excludedNamespaces) if (fn.Contains(ex)) return false;
    if (fn.Contains("Migration") || fn.Contains("CoverageExtensions") || fn.EndsWith(".Program") || fn.EndsWith(".Startup")) return false;
    if (instrumentAll) { Console.WriteLine($"  + {fn}"); return true; }
    foreach (var ns in allowedNamespaces) if (fn.Contains(ns)) { Console.WriteLine($"  + {fn}"); return true; }
    return false;
}
try { SharpFuzz.Fuzzer.Instrument(dllPath, Filter, SharpFuzz.Options.Value); Console.WriteLine("Done"); }
catch (SharpFuzz.InstrumentationException ex) when (ex.Message.Contains("already instrumented")) { Console.WriteLine("Already instrumented"); }
catch (Exception ex) { Console.Error.WriteLine($"FAILED: {ex.Message}"); Environment.Exit(1); }
'''


# ============================================================================
# Zero-edit coverage hook assembly (DOTNET_STARTUP_HOOKS + ASP.NET hosting startup)
# ============================================================================

# Pure C# source (no Python substitutions) — kept as a raw string so its many
# braces don't need f-string escaping.
_COVERAGE_HOOK_CS = r'''// AUTO-GENERATED by fuzz-prep-multi.py — UpsideFuzz zero-edit coverage runtime.
//
// Loaded two ways, both requiring ZERO edits to the target application:
//   1. DOTNET_STARTUP_HOOKS -> StartupHook.Initialize() runs before Main. It maps
//      the shared coverage bitmap, links every SharpFuzz-instrumented assembly to it
//      (including assemblies loaded lazily/dynamically at request time, via an
//      AppDomain.AssemblyLoad handler), and registers an assembly resolver so this
//      DLL + SharpFuzz.Common.dll load from /coverage without being in the app dir.
//   2. ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=UpsideFuzz.Coverage -> CoverageHostingStartup
//      registers an IStartupFilter that inserts the coverage middleware, which serves
//      the /shm/* control endpoints and emits per-request X-Coverage-Delta headers.
#nullable disable
#pragma warning disable

using System;
using System.Collections.Concurrent;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

[assembly: HostingStartup(typeof(UpsideFuzz.Coverage.CoverageHostingStartup))]

// StartupHook MUST be in the global namespace and named exactly "StartupHook".
internal class StartupHook
{
    public static void Initialize()
    {
        try { UpsideFuzz.Coverage.CoverageRuntime.Bootstrap(); } catch { }
    }
}

namespace UpsideFuzz.Coverage
{
    public static class CoverageRuntime
    {
        private const string SHM_PATH = "/coverage_shm/bitmap";
        private const int DEFAULT_SHM_SIZE = 262144;
        private const int MIN_SHM_SIZE = 65536;
        private const int MAX_SHM_SIZE = 8 * 1024 * 1024;
        // Top-20 #17: real instrumented-type count captured at build time by
        // instrumentor/Program.cs, used both to auto-size SHM_SIZE below (when the
        // env var isn't explicitly set) and reported via /shm/health for transparency.
        internal static readonly int InstrumentedTypeCount = ResolveInstrumentedTypeCount();
        internal static readonly int SHM_SIZE = ResolveShmSize();

        private static IntPtr globalShmAddr = IntPtr.Zero;
        private static bool isFileBacked = false;
        private static MemoryMappedFile mmf;
        private static MemoryMappedViewAccessor accessor;

        // AFL-style hit-count buckets + bucketed virgin map (see coverage.go / ARCHITECTURE.md).
        private static readonly byte[] CountClass = BuildCountClass();
        private static byte[] seenBuckets;
        private static int totalClasses = 0;
        private static readonly object covLock = new object();

        private static readonly ConcurrentDictionary<string, byte> linkedAssemblies = new ConcurrentDictionary<string, byte>();
        private static int linkCount = 0;
        private static volatile bool booted = false;
        private static string hookDir = "/coverage";

        // Self-verifying, fail-closed instrumentation (Top-20 #4): track which
        // assemblies are "app" code (not framework/SharpFuzz itself) so /shm/health
        // can report whether instrumentation actually reached the target's own
        // code, not just that the SharpFuzz runtime loaded. Mirrors
        // instrumentor/Program.cs's `frameworkPrefixes` — kept in sync manually.
        private static readonly string[] frameworkPrefixes = {
            "System.", "Microsoft.", "SharpFuzz.", "Mono.", "Internal.",
            "Newtonsoft.", "Swashbuckle.", "NSwag.", "FluentValidation.",
            "Serilog.", "MediatR.", "AutoMapper.", "Dapper.",
            "Npgsql.", "MySqlConnector.", "StackExchange.",
            "Polly.", "Grpc.", "Google.Protobuf.",
        };
        // linked_app_assemblies is deliberately NOT tracked per-assembly: SharpFuzz's
        // Trace.SharedMem type lives only in SharpFuzz.Common.dll, never in the app's
        // own IL-rewritten assemblies, so "does this app assembly define the Trace
        // type" is always false and would be a false-negative fail-closed signal.
        // The only architecturally honest way to verify instrumentation reached app
        // code is to check whether the shared bitmap actually moves after real
        // traffic — done engine-side (void/go/coverage.go::checkCoverageHealth) via a
        // warm-up probe. This list is purely informational: which app assemblies the
        // runtime has observed loaded, for diagnostics when that probe fails.
        private static readonly ConcurrentDictionary<string, byte> seenAppAssemblies = new ConcurrentDictionary<string, byte>();

        private static bool IsAppAssembly(string name)
        {
            if (string.IsNullOrEmpty(name) || name == "UpsideFuzz.Coverage") return false;
            foreach (var prefix in frameworkPrefixes)
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }

        private static string JsonStringArray(System.Collections.Generic.IEnumerable<string> values)
        {
            var sb = new StringBuilder("[");
            bool first = true;
            foreach (var v in values)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(SanitizeHeader(v)).Append('"');
            }
            sb.Append(']');
            return sb.ToString();
        }

        // Called before Main via DOTNET_STARTUP_HOOKS.
        public static void Bootstrap()
        {
            if (booted) return;
            booted = true;
            try { hookDir = Path.GetDirectoryName(typeof(CoverageRuntime).Assembly.Location); } catch { }
            if (string.IsNullOrEmpty(hookDir)) hookDir = "/coverage";

            // Resolve UpsideFuzz.Coverage + SharpFuzz.Common from /coverage even though
            // they are NOT in the app's probing path — so the target dir stays untouched.
            AssemblyLoadContext.Default.Resolving += (ctx, name) =>
            {
                try
                {
                    var candidate = Path.Combine(hookDir, name.Name + ".dll");
                    if (File.Exists(candidate)) return ctx.LoadFromAssemblyPath(candidate);
                }
                catch { }
                return null;
            };

            InitializeShm();

            // Force-load + link the shared SharpFuzz coverage assembly immediately.
            foreach (var n in new[] { "SharpFuzz.Common", "SharpFuzz" })
            {
                try { LinkAssembly(Assembly.Load(n)); } catch { }
            }

            // Link everything already loaded, and everything loaded later. The
            // AssemblyLoad handler is the fix for lazily/dynamically loaded modules
            // (e.g. plugin-style module assemblies) whose coverage was previously lost.
            AppDomain.CurrentDomain.AssemblyLoad += (s, e) =>
            {
                try { LinkAssembly(e.LoadedAssembly); } catch { }
            };
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) LinkAssembly(a);
        }

        // ResolveInstrumentedTypeCount reads the JSONL meta file instrumentor/Program.cs
        // appends next to the app's DLLs (one line per instrumented assembly) and sums
        // instrumented_types across them. Returns 0 if the file is absent (e.g. a build
        // predating this feature, or the meta write failed) -- callers must treat 0 as
        // "unknown", not "zero types instrumented".
        private static int ResolveInstrumentedTypeCount()
        {
            try
            {
                var metaPath = Path.Combine(AppContext.BaseDirectory, ".upsidefuzz_instrumented.jsonl");
                if (!File.Exists(metaPath)) return 0;
                int total = 0;
                const string key = "\"instrumented_types\":";
                foreach (var line in File.ReadAllLines(metaPath))
                {
                    var idx = line.IndexOf(key, StringComparison.Ordinal);
                    if (idx < 0) continue;
                    int start = idx + key.Length;
                    int end = start;
                    while (end < line.Length && char.IsDigit(line[end])) end++;
                    if (end > start && int.TryParse(line.Substring(start, end - start), out var n))
                        total += n;
                }
                return total;
            }
            catch { return 0; }
        }

        private static int ResolveShmSize()
        {
            try
            {
                var raw = Environment.GetEnvironmentVariable("SHM_SIZE");
                if (int.TryParse(raw, out var parsed))
                    return parsed < MIN_SHM_SIZE ? MIN_SHM_SIZE : parsed;
            }
            catch { }
            // Top-20 #17: size the bitmap from the real instrumented-type count instead
            // of a fixed 256KB guess, when the caller hasn't pinned SHM_SIZE explicitly.
            // SharpFuzz exposes no public branch/edge count, so instrumented TYPE count
            // is used as a proxy -- budget ~512 bitmap bytes per instrumented type
            // (generous enough to keep hash collisions rare for typical controller/
            // service-sized classes), rounded up to a power of two and clamped to
            // [MIN_SHM_SIZE, MAX_SHM_SIZE] so very small or very large apps stay sane.
            try
            {
                if (InstrumentedTypeCount > 0)
                {
                    long estimate = (long)InstrumentedTypeCount * 512;
                    int size = MIN_SHM_SIZE;
                    while (size < estimate && size < MAX_SHM_SIZE) size <<= 1;
                    return size;
                }
            }
            catch { }
            return DEFAULT_SHM_SIZE;
        }

        private static byte[] BuildCountClass()
        {
            var t = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte c = (byte)i;
                byte v;
                if (c == 0) v = 0;
                else if (c == 1) v = 1;
                else if (c == 2) v = 2;
                else if (c == 3) v = 4;
                else if (c <= 7) v = 8;
                else if (c <= 15) v = 16;
                else if (c <= 31) v = 32;
                else if (c <= 127) v = 64;
                else v = 128;
                t[i] = v;
            }
            return t;
        }

        private static void InitializeShm()
        {
            if (globalShmAddr != IntPtr.Zero) return;
            if (Directory.Exists(Path.GetDirectoryName(SHM_PATH)))
            {
                try
                {
                    var fs = new FileStream(SHM_PATH, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                    fs.SetLength(SHM_SIZE);
                    mmf = MemoryMappedFile.CreateFromFile(fs, null, SHM_SIZE, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, false);
                    accessor = mmf.CreateViewAccessor(0, SHM_SIZE);
                    unsafe
                    {
                        byte* ptr = null;
                        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
                        globalShmAddr = (IntPtr)ptr;
                    }
                    isFileBacked = true;
                }
                catch { globalShmAddr = Marshal.AllocHGlobal(SHM_SIZE); }
            }
            else
            {
                globalShmAddr = Marshal.AllocHGlobal(SHM_SIZE);
            }
            unsafe { byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }
            seenBuckets = new byte[SHM_SIZE];
            totalClasses = 0;
        }

        // Point a single assembly's SharpFuzz.Common.Trace.SharedMem at our bitmap.
        internal static void LinkAssembly(Assembly a)
        {
            if (a == null || globalShmAddr == IntPtr.Zero) return;
            try
            {
                string asmName = a.GetName().Name ?? a.FullName;
                bool isApp = IsAppAssembly(asmName);
                if (isApp) seenAppAssemblies.TryAdd(asmName, 1);

                string[] typeNames = { "SharpFuzz.Common.Trace", "SharpFuzz.Common.Instrumenter", "SharpFuzz.Trace", "SharpFuzz.Instrumenter" };
                bool matched = false;
                foreach (var tn in typeNames)
                {
                    Type t = a.GetType(tn, false);
                    if (t == null) continue;
                    string[] members = { "SharedMem", "SharedMemory", "sharedMemory", "_sharedMemory" };
                    foreach (var m in members)
                    {
                        var p = t.GetProperty(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                        if (p != null)
                        {
                            try { unsafe { p.SetValue(null, System.Reflection.Pointer.Box(globalShmAddr.ToPointer(), typeof(byte*))); } matched = true; } catch { }
                        }
                        var f = t.GetField(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                        if (f != null)
                        {
                            try { f.SetValue(null, globalShmAddr); matched = true; } catch { }
                        }
                    }
                }
                if (matched && linkedAssemblies.TryAdd(asmName, 1))
                    Interlocked.Increment(ref linkCount);
            }
            catch { }
        }

        // Single-pass novelty merge against the shared bucketed virgin map
        // (first-observer-wins) — see ARCHITECTURE.md section 5.
        internal static int MergeAndCountNovel()
        {
            if (globalShmAddr == IntPtr.Zero || seenBuckets == null) return 0;
            int novel = 0;
            lock (covLock)
            {
                unsafe
                {
                    byte* b = (byte*)globalShmAddr;
                    int n = SHM_SIZE;
                    int i = 0;
                    for (; i + 8 <= n; i += 8)
                    {
                        if (*(ulong*)(b + i) == 0UL) continue;
                        for (int j = 0; j < 8; j++)
                        {
                            byte c = b[i + j];
                            if (c == 0) continue;
                            byte bucket = CountClass[c];
                            if ((seenBuckets[i + j] & bucket) == 0) { seenBuckets[i + j] |= bucket; novel++; }
                        }
                    }
                    for (; i < n; i++)
                    {
                        byte c = b[i];
                        if (c == 0) continue;
                        byte bucket = CountClass[c];
                        if ((seenBuckets[i] & bucket) == 0) { seenBuckets[i] |= bucket; novel++; }
                    }
                }
                totalClasses += novel;
            }
            return novel;
        }

        private static long RawHits()
        {
            if (globalShmAddr == IntPtr.Zero) return 0;
            long hits = 0;
            unsafe { byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) hits += b[i]; }
            return hits;
        }

        private static string SanitizeHeader(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(Math.Min(s.Length, 1024));
            foreach (var c in s)
            {
                if (sb.Length >= 1024) break;
                if (c == '\r' || c == '\n' || c == '\t') { sb.Append(' '); continue; }
                if (c >= 32 && c < 127) sb.Append(c);
            }
            return sb.ToString();
        }

        private static Task WriteJson(HttpContext ctx, string json)
        {
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            return ctx.Response.WriteAsync(json);
        }

        // Serves /shm/create, /shm/coverage, /shm/reset, /shm/health.
        public static Task HandleControlEndpoint(HttpContext context, string rawPath)
        {
            string path = rawPath.TrimEnd('/').ToLowerInvariant();
            if (path == "/shm/create")
            {
                InitializeShm();
                foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) LinkAssembly(a);
                return WriteJson(context, "{\"mode\":\"" + (isFileBacked ? "file-backed-mmap" : "heap") +
                    "\",\"size\":" + SHM_SIZE + ",\"status\":\"synced\",\"linked_assemblies\":" + linkCount + "}");
            }
            if (path == "/shm/coverage")
                return WriteJson(context, "{\"edges\":" + totalClasses + ",\"hits\":" + RawHits() + ",\"size\":" + SHM_SIZE + "}");
            if (path == "/shm/reset")
            {
                lock (covLock)
                {
                    if (globalShmAddr != IntPtr.Zero) unsafe { byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }
                    if (seenBuckets != null) Array.Clear(seenBuckets, 0, seenBuckets.Length);
                    totalClasses = 0;
                }
                return WriteJson(context, "{\"status\":\"reset\"}");
            }
            if (path == "/shm/health")
            {
                // Reports facts only, not a verdict: SharpFuzz's Trace type lives in
                // SharpFuzz.Common.dll, never in the app's own rewritten assemblies, so
                // per-assembly "linked" status can't be measured by type reflection here.
                // The fail-closed ok/degraded decision is made engine-side (Go), which can
                // send real warm-up traffic and check whether the bitmap actually moves —
                // see void/go/coverage.go::checkCoverageHealth. app_assemblies below is
                // purely diagnostic context for that decision.
                bool shmBound = globalShmAddr != IntPtr.Zero;
                var (cmplogStrs, cmplogInts) = CmpLogProbe.Counts();
                return WriteJson(context, "{\"linked_assemblies\":" + linkCount + ",\"total_classes\":" + totalClasses +
                    ",\"shm_bound\":" + (shmBound ? "true" : "false") +
                    ",\"mode\":\"" + (isFileBacked ? "file-backed-mmap" : "heap") + "\"" +
                    ",\"instrumented_types\":" + InstrumentedTypeCount +
                    ",\"cmplog_strings\":" + cmplogStrs + ",\"cmplog_ints\":" + cmplogInts +
                    ",\"app_assemblies\":" + JsonStringArray(seenAppAssemblies.Keys) + "}");
            }
            // Top-20+ #21: comparison operands harvested from the target's own IL by
            // instrumentor/Program.cs's CmpLogInstrumentor (--cmplog, hook mode only).
            // Absent (404, handled by the fallthrough below) on a target built without
            // --cmplog or in --inject-mode source -- the Go engine treats that as
            // "nothing available", not an error.
            if (path == "/shm/cmplog")
                return WriteJson(context, CmpLogProbe.ToJson());
            context.Response.StatusCode = 404;
            return Task.CompletedTask;
        }

        // Per-request coverage attribution + production-mode exception capture.
        public static async Task RunWithCoverage(HttpContext context, RequestDelegate next)
        {
            bool isFuzzRequest = !string.IsNullOrEmpty(context.Request.Headers["X-Fuzz-Request-Id"]);
            string exType = null, exMsg = null;
            int coverageDelta = -1;
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                exType = ex.GetType().FullName;
                exMsg = ex.Message;
                if (isFuzzRequest && !context.Response.HasStarted)
                {
                    try
                    {
                        context.Response.Clear();
                        context.Response.StatusCode = 500;
                        coverageDelta = MergeAndCountNovel();
                        context.Response.Headers["X-Coverage-Delta"] = coverageDelta.ToString();
                        context.Response.Headers["X-Coverage-Edges"] = totalClasses.ToString();
                        context.Response.Headers["X-Exception-Type"] = SanitizeHeader(exType);
                        context.Response.Headers["X-Exception-Message"] = SanitizeHeader(exMsg);
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync("{\"error\":\"unhandled_exception\"}");
                    }
                    catch { }
                    return;
                }
                throw;
            }
            finally
            {
                if (coverageDelta < 0) coverageDelta = MergeAndCountNovel();
                try
                {
                    if (!context.Response.HasStarted)
                    {
                        context.Response.Headers["X-Coverage-Delta"] = coverageDelta.ToString();
                        context.Response.Headers["X-Coverage-Edges"] = totalClasses.ToString();
                        if (exType != null) context.Response.Headers["X-Exception-Type"] = SanitizeHeader(exType);
                        if (exMsg != null) context.Response.Headers["X-Exception-Message"] = SanitizeHeader(exMsg);
                    }
                }
                catch { }
            }
        }
    }

    // Top-20+ #21: runtime side of CmpLog/RedQueen via IL comparison instrumentation.
    // instrumentor/Program.cs's CmpLogInstrumentor pass (--cmplog, hook mode only)
    // rewrites the target's own IL so every String.Equals/op_Equality/StartsWith/
    // EndsWith/Contains call and every integer-literal-vs-compare (ceq/beq/bne.un)
    // site calls RecordString/RecordInt here with its operand(s) BEFORE the original
    // comparison executes -- the instrumented program's behavior is unchanged, this
    // is purely an observer. Bounded, deduped, thread-safe (concurrent requests hit
    // instrumented code from many threads); served over GET /shm/cmplog for the Go
    // engine to poll into its own mutation-candidate pool (void/go/cmplog.go).
    public static class CmpLogProbe
    {
        private const int MAX_STRINGS = 512;
        private const int MAX_INTS = 256;
        private const int MAX_STRING_LEN = 256;

        private static readonly ConcurrentQueue<string> stringQueue = new ConcurrentQueue<string>();
        private static readonly ConcurrentDictionary<string, byte> stringSeen = new ConcurrentDictionary<string, byte>();
        private static readonly ConcurrentQueue<long> intQueue = new ConcurrentQueue<long>();
        private static readonly ConcurrentDictionary<long, byte> intSeen = new ConcurrentDictionary<long, byte>();

        public static void RecordString(string a, string b)
        {
            RecordOne(a);
            RecordOne(b);
        }

        private static void RecordOne(string v)
        {
            if (string.IsNullOrEmpty(v) || v.Length > MAX_STRING_LEN) return;
            if (!stringSeen.TryAdd(v, 1)) return;
            stringQueue.Enqueue(v);
            while (stringQueue.Count > MAX_STRINGS && stringQueue.TryDequeue(out var old))
                stringSeen.TryRemove(old, out _);
        }

        public static void RecordInt(long v)
        {
            if (!intSeen.TryAdd(v, 1)) return;
            intQueue.Enqueue(v);
            while (intQueue.Count > MAX_INTS && intQueue.TryDequeue(out var old))
                intSeen.TryRemove(old, out _);
        }

        public static (int strings, int ints) Counts() => (stringQueue.Count, intQueue.Count);

        // ConcurrentQueue enumeration is a weakly-consistent snapshot -- safe to read
        // while RecordString/RecordInt run concurrently on other request threads;
        // worst case a poll misses a value added mid-enumeration, which the next
        // poll picks up (this is a best-effort dictionary source, not a correctness-
        // critical coverage signal).
        internal static string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{\"strings\":[");
            bool first = true;
            foreach (var s in stringQueue)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(JsonEscape(s)).Append('"');
            }
            sb.Append("],\"ints\":[");
            first = true;
            foreach (var n in intQueue)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(n).Append('"');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private static string JsonEscape(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                if (c == '"' || c == '\\') { sb.Append('\\').Append(c); continue; }
                if (c == '\n') { sb.Append("\\n"); continue; }
                if (c == '\r') { sb.Append("\\r"); continue; }
                if (c < 32) continue;
                sb.Append(c);
            }
            return sb.ToString();
        }
    }

    // ASP.NET hosting startup (loaded via ASPNETCORE_HOSTINGSTARTUPASSEMBLIES).
    public class CoverageHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddSingleton<IStartupFilter, CoverageStartupFilter>();
            });
        }
    }

    internal class CoverageStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                // Inserted at the very front so it always runs and can serve /shm/*.
                app.Use(async (context, mwNext) =>
                {
                    var path = context.Request.Path.Value ?? "";
                    if (path.StartsWith("/shm/", StringComparison.OrdinalIgnoreCase))
                    {
                        await CoverageRuntime.HandleControlEndpoint(context, path);
                        return;
                    }
                    await CoverageRuntime.RunWithCoverage(context, _ => mwNext());
                });
                next(app);
            };
        }
    }
}
'''


def generate_startup_hook_assembly(result: MultiAnalysisResult, output_path: Path):
    """Write the self-contained UpsideFuzz.Coverage hook assembly (zero-edit mode).

    Produces coverage_hook_src/{UpsideFuzz.Coverage.cs, UpsideFuzz.Coverage.csproj}.
    The Docker build (hook mode) compiles this and drops the DLL + SharpFuzz.Common.dll
    into /coverage in the runtime image, wired via DOTNET_STARTUP_HOOKS +
    ASPNETCORE_HOSTINGSTARTUPASSEMBLIES. The target application is never modified.
    """
    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])
    tfm = main_proj.target_framework or "net8.0"
    sharpfuzz_version = "2.1.1"

    hook_dir = output_path / "coverage_hook_src"
    hook_dir.mkdir(parents=True, exist_ok=True)

    (hook_dir / "UpsideFuzz.Coverage.cs").write_text(_COVERAGE_HOOK_CS, encoding="utf-8")

    csproj = f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>{tfm}</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <AssemblyName>UpsideFuzz.Coverage</AssemblyName>
    <RootNamespace>UpsideFuzz.Coverage</RootNamespace>
    <IsPackable>false</IsPackable>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
  <ItemGroup>
    <!-- Pulls SharpFuzz.Common.dll into the build output so the instrumented
         app's probes resolve it at runtime (we reference it by reflection only). -->
    <PackageReference Include="SharpFuzz" Version="{sharpfuzz_version}" />
  </ItemGroup>
</Project>
"""
    (hook_dir / "UpsideFuzz.Coverage.csproj").write_text(csproj, encoding="utf-8")
    print(f"  Generated zero-edit coverage hook assembly in {hook_dir.name}/ (TFM {tfm})")


# ============================================================================
# .csproj patching
# ============================================================================

def patch_all_csprojs(output_path: Path):
    """Apply AllowUnsafeBlocks and SharpFuzz reference to main project csprojs.

    Skips test projects and instrumentor projects.
    Handles Central Package Management (Directory.Packages.props) if present.
    """
    cpvm_file = output_path / "Directory.Packages.props"
    has_cpvm = cpvm_file.exists()
    sharpfuzz_version = "2.1.1"

    if has_cpvm:
        print(f"  Detected Central Package Management: {cpvm_file.name}")
        content = cpvm_file.read_text()
        if 'Include="SharpFuzz"' not in content:
            if '</ItemGroup>' in content:
                content = content.replace(
                    '</ItemGroup>',
                    f'  <PackageVersion Include="SharpFuzz" Version="{sharpfuzz_version}" />\n  </ItemGroup>',
                    1
                )
            else:
                content = content.replace(
                    '</Project>',
                    f'  <ItemGroup>\n    <PackageVersion Include="SharpFuzz" Version="{sharpfuzz_version}" />\n  </ItemGroup>\n</Project>'
                )
            cpvm_file.write_text(content)
            print("  Added SharpFuzz version to Directory.Packages.props")

    for csproj in output_path.rglob('*.csproj'):
        csproj_str = str(csproj).lower()
        if 'instrumentor' in csproj_str:
            continue
        if 'test' in csproj.name.lower() or '/test/' in csproj_str or '\\test\\' in csproj_str:
            print(f"  Skipped test project: {csproj.name}")
            continue

        content = csproj.read_text()

        if '<AllowUnsafeBlocks>true</AllowUnsafeBlocks>' not in content:
            content = content.replace(
                '<PropertyGroup>',
                '<PropertyGroup>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>',
                1
            )

        if 'Include="SharpFuzz"' not in content:
            ref_line = (
                '<PackageReference Include="SharpFuzz" />'
                if has_cpvm
                else f'<PackageReference Include="SharpFuzz" Version="{sharpfuzz_version}" />'
            )

            if '</ItemGroup>' in content:
                content = content.replace('</ItemGroup>', f'  {ref_line}\n  </ItemGroup>', 1)
            else:
                content = content.replace(
                    '</Project>',
                    f'  <ItemGroup>\n    {ref_line}\n  </ItemGroup>\n</Project>'
                )

        csproj.write_text(content)
        print(f"  Patched {csproj.name}")


# ============================================================================
# CoverageExtensions.cs generation
# ============================================================================

def generate_multi_coverage_helper(result: MultiAnalysisResult, output_path: Path):
    """Generate CoverageExtensions.cs in the main project"""
    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])

    # Use RootNamespace if detected, otherwise fall back to project name
    ns_prefix = main_proj.root_namespace or result.main_project

    # Determine target subdirectory: prefer Utilities/ (standard ASP.NET convention), fall back to Helpers/
    utilities_dir = output_path / main_proj.path / "Utilities"
    helpers_dir = output_path / main_proj.path / "Helpers"
    subdir_name = "Utilities" if utilities_dir.exists() else "Helpers"

    code = f"""// AUTO-GENERATED by fuzz-prep-multi.py
#nullable disable
#pragma warning disable
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace {ns_prefix}.{subdir_name}
{{
    public class CoverageSnapshot
    {{
        public string TraceId {{ get; set; }}
        public string Endpoint {{ get; set; }}
        public int CoverageBefore {{ get; set; }}
        public int CoverageAfter {{ get; set; }}
        public int CoverageDelta {{ get; set; }}
        public DateTime Timestamp {{ get; set; }}
    }}

    public static class CoverageExtensions
    {{
        private const string SHM_PATH = "/coverage_shm/bitmap";
        private const int DEFAULT_SHM_SIZE = 262144;
        private const int MIN_SHM_SIZE = 65536;
        private const int MAX_SHM_SIZE = 8 * 1024 * 1024;
        // Top-20 #17: real instrumented-type count captured at build time by
        // instrumentor/Program.cs, used both to auto-size SHM_SIZE below (when the
        // env var isn't explicitly set) and reported via /shm/health for transparency.
        private static readonly int InstrumentedTypeCount = ResolveInstrumentedTypeCount();
        private static readonly int SHM_SIZE = ResolveShmSize();

        private static IntPtr globalShmAddr = IntPtr.Zero;
        private static bool isSynced = false;
        private static bool isFileBacked = false;
        private static MemoryMappedFile mmf;
        private static MemoryMappedViewAccessor accessor;
        private static ConcurrentDictionary<string, CoverageSnapshot> traceCoverage = new ConcurrentDictionary<string, CoverageSnapshot>();

        // ── AFL-style hit-count buckets + bucketed virgin map ──────────────────
        // Each edge's raw 8-bit hit count is classified into a log-scale bucket
        // (1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+). seenBuckets[i] holds the OR
        // of every bucket bit ever observed for edge i. A bucket bit that is new
        // for an edge is new coverage — so an edge run once is distinguished from
        // the same edge run 50 or 5000 times, letting the fuzzer keep making
        // progress inside loops/pagination/state machines instead of plateauing
        // the instant every edge has been touched at least once.
        private static readonly byte[] CountClass = BuildCountClass();
        private static byte[] seenBuckets;      // bucketed virgin map (size SHM_SIZE)
        private static int totalClasses = 0;    // running count of distinct (edge, bucket) classes discovered
        private static readonly object covLock = new object();

        private static byte[] BuildCountClass()
        {{
            var t = new byte[256];
            for (int i = 0; i < 256; i++)
            {{
                byte c = (byte)i;
                byte v;
                if (c == 0) v = 0;
                else if (c == 1) v = 1;
                else if (c == 2) v = 2;
                else if (c == 3) v = 4;
                else if (c <= 7) v = 8;
                else if (c <= 15) v = 16;
                else if (c <= 31) v = 32;
                else if (c <= 127) v = 64;
                else v = 128;
                t[i] = v;
            }}
            return t;
        }}

        // MergeAndCountNovel folds the live coverage bitmap into the persistent
        // bucketed virgin map and returns how many NEW (edge, bucket) classes the
        // just-completed request discovered. Novelty is measured against the shared
        // virgin map (first-observer-wins): when two concurrent requests both reach
        // new code the credit is claimed once, not smeared across both — which is
        // the concurrency-attribution bug the old global before/after delta had.
        // A single pass (with an all-zero 8-byte word fast path) replaces the two
        // full 256KB bitmap scans the middleware previously did per request.
        private static int MergeAndCountNovel()
        {{
            if (globalShmAddr == IntPtr.Zero || seenBuckets == null) return 0;
            int novel = 0;
            lock (covLock)
            {{
                unsafe
                {{
                    byte* b = (byte*)globalShmAddr;
                    int n = SHM_SIZE;
                    int i = 0;
                    for (; i + 8 <= n; i += 8)
                    {{
                        if (*(ulong*)(b + i) == 0UL) continue;
                        for (int j = 0; j < 8; j++)
                        {{
                            byte c = b[i + j];
                            if (c == 0) continue;
                            byte bucket = CountClass[c];
                            if ((seenBuckets[i + j] & bucket) == 0)
                            {{
                                seenBuckets[i + j] |= bucket;
                                novel++;
                            }}
                        }}
                    }}
                    for (; i < n; i++)
                    {{
                        byte c = b[i];
                        if (c == 0) continue;
                        byte bucket = CountClass[c];
                        if ((seenBuckets[i] & bucket) == 0)
                        {{
                            seenBuckets[i] |= bucket;
                            novel++;
                        }}
                    }}
                }}
                totalClasses += novel;
            }}
            return novel;
        }}

        // ResolveInstrumentedTypeCount reads the JSONL meta file instrumentor/Program.cs
        // appends next to the app's DLLs (one line per instrumented assembly) and sums
        // instrumented_types across them. Returns 0 if the file is absent (e.g. a build
        // predating this feature) -- callers must treat 0 as "unknown", not "zero types".
        private static int ResolveInstrumentedTypeCount()
        {{
            try
            {{
                var metaPath = Path.Combine(AppContext.BaseDirectory, ".upsidefuzz_instrumented.jsonl");
                if (!File.Exists(metaPath)) return 0;
                int total = 0;
                const string key = "\\"instrumented_types\\":";
                foreach (var line in File.ReadAllLines(metaPath))
                {{
                    var idx = line.IndexOf(key, StringComparison.Ordinal);
                    if (idx < 0) continue;
                    int start = idx + key.Length;
                    int end = start;
                    while (end < line.Length && char.IsDigit(line[end])) end++;
                    if (end > start && int.TryParse(line.Substring(start, end - start), out var n))
                        total += n;
                }}
                return total;
            }}
            catch {{ return 0; }}
        }}

        private static int ResolveShmSize()
        {{
            try
            {{
                var raw = Environment.GetEnvironmentVariable("SHM_SIZE");
                if (int.TryParse(raw, out var parsed))
                {{
                    if (parsed < MIN_SHM_SIZE) return MIN_SHM_SIZE;
                    return parsed;
                }}
            }}
            catch {{ }}
            // Top-20 #17: size the bitmap from the real instrumented-type count instead
            // of a fixed 256KB guess, when SHM_SIZE isn't pinned explicitly. SharpFuzz
            // exposes no public branch/edge count, so instrumented TYPE count is used as
            // a proxy -- budget ~512 bitmap bytes per instrumented type, rounded up to a
            // power of two and clamped to [MIN_SHM_SIZE, MAX_SHM_SIZE].
            try
            {{
                if (InstrumentedTypeCount > 0)
                {{
                    long estimate = (long)InstrumentedTypeCount * 512;
                    int size = MIN_SHM_SIZE;
                    while (size < estimate && size < MAX_SHM_SIZE) size <<= 1;
                    return size;
                }}
            }}
            catch {{ }}
            return DEFAULT_SHM_SIZE;
        }}

        public static void Initialize()
        {{
            if (globalShmAddr != IntPtr.Zero) return;

            if (Directory.Exists(Path.GetDirectoryName(SHM_PATH)))
            {{
                try {{
                    var fs = new FileStream(SHM_PATH, FileMode.OpenOrCreate,
                        FileAccess.ReadWrite, FileShare.ReadWrite);
                    fs.SetLength(SHM_SIZE);
                    mmf = MemoryMappedFile.CreateFromFile(fs, null, SHM_SIZE,
                        MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, false);
                    accessor = mmf.CreateViewAccessor(0, SHM_SIZE);
                    unsafe {{
                        byte* ptr = null;
                        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
                        globalShmAddr = (IntPtr)ptr;
                    }}
                    isFileBacked = true;
                }} catch {{
                    globalShmAddr = Marshal.AllocHGlobal(SHM_SIZE);
                }}
            }}
            else
            {{
                globalShmAddr = Marshal.AllocHGlobal(SHM_SIZE);
            }}

            unsafe {{ byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }}
            seenBuckets = new byte[SHM_SIZE];
            totalClasses = 0;
            SyncSharpFuzz();
        }}

        // SanitizeHeader makes an arbitrary exception string safe as an HTTP header
        // value: strips CR/LF/control chars and truncates. Exception messages routinely
        // contain newlines and non-ASCII, which would throw when assigned to a header.
        private static string SanitizeHeader(string s)
        {{
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new System.Text.StringBuilder(Math.Min(s.Length, 1024));
            foreach (var c in s)
            {{
                if (sb.Length >= 1024) break;
                if (c == '\\r' || c == '\\n' || c == '\\t') {{ sb.Append(' '); continue; }}
                if (c >= 32 && c < 127) sb.Append(c);
            }}
            return sb.ToString();
        }}

        public static IApplicationBuilder UseCoverageMiddleware(this IApplicationBuilder app)
        {{
            Initialize();

            return app.Use(async (context, next) =>
            {{
                if (globalShmAddr != IntPtr.Zero && !isSynced) {{ SyncSharpFuzz(); }}

                // Use X-Fuzz-Request-Id header for per-request coverage attribution.
                // The fuzzer sends this header; we return X-Coverage-Delta in the response.
                var requestId = context.Request.Headers["X-Fuzz-Request-Id"].ToString();
                if (string.IsNullOrEmpty(requestId))
                    requestId = "default-" + Guid.NewGuid().ToString("N").Substring(0, 8);

                string exceptionTypeName = null;
                string exceptionMessage = null;
                bool isFuzzRequest = !string.IsNullOrEmpty(context.Request.Headers["X-Fuzz-Request-Id"]);
                // Per-request novelty is computed ONCE, after the pipeline runs, by
                // merging the live bitmap into the shared bucketed virgin map. This
                // replaces the old global before/after double full-scan (two 256KB
                // passes per request) and its concurrency smearing: the delta is now
                // the count of buckets THIS request was first to discover.
                int coverageDelta = -1;
                try {{
                    await next();
                }} catch (Exception ex) {{
                    exceptionTypeName = ex.GetType().FullName;
                    exceptionMessage = ex.Message;
                    // PRODUCTION-MODE FIX: in non-Development mode the app's exception handler
                    // starts the response (Response.HasStarted = true) and clears headers before
                    // our finally block runs — losing X-Exception-Type on ~all prod 500s. For
                    // FUZZ requests only, short-circuit here and emit our own 500 carrying the
                    // exception type + message. Real traffic (no X-Fuzz-Request-Id) is untouched:
                    // we re-throw so the app's normal error handling still runs for it.
                    if (isFuzzRequest && !context.Response.HasStarted) {{
                        try {{
                            context.Response.Clear();
                            context.Response.StatusCode = 500;
                            coverageDelta = MergeAndCountNovel();
                            context.Response.Headers["X-Coverage-Delta"] = coverageDelta.ToString();
                            context.Response.Headers["X-Coverage-Edges"] = totalClasses.ToString();
                            context.Response.Headers["X-Exception-Type"] = SanitizeHeader(exceptionTypeName);
                            context.Response.Headers["X-Exception-Message"] = SanitizeHeader(exceptionMessage);
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync("{{\\"error\\":\\"unhandled_exception\\"}}");
                        }} catch {{ }}
                        return;
                    }}
                    throw;
                }} finally {{
                    // Single-pass novelty merge (skipped if the short-circuit branch already did it).
                    if (coverageDelta < 0) coverageDelta = MergeAndCountNovel();
                    // Inject per-request coverage into response headers — the fuzzer reads
                    // X-Coverage-Delta directly from the response, no extra round trip.
                    try {{
                        if (!context.Response.HasStarted) {{
                            context.Response.Headers["X-Coverage-Delta"] = coverageDelta.ToString();
                            context.Response.Headers["X-Coverage-Edges"] = totalClasses.ToString();
                            if (exceptionTypeName != null)
                                context.Response.Headers["X-Exception-Type"] = SanitizeHeader(exceptionTypeName);
                            if (exceptionMessage != null)
                                context.Response.Headers["X-Exception-Message"] = SanitizeHeader(exceptionMessage);
                        }}
                    }} catch {{ }}
                    // Bounded cleanup to prevent unbounded memory growth under sustained fuzzing.
                    if (traceCoverage.Count > 5000) {{
                        var oldestKeys = traceCoverage.Keys.Take(1000).ToArray();
                        foreach (var k in oldestKeys) traceCoverage.TryRemove(k, out _);
                    }}
                    traceCoverage[requestId] = new CoverageSnapshot
                    {{
                        TraceId = requestId,
                        Endpoint = context.Request.Path,
                        CoverageBefore = 0,
                        CoverageAfter = totalClasses,
                        CoverageDelta = coverageDelta,
                        Timestamp = DateTime.UtcNow
                    }};
                }}
            }});
        }}

        private static string syncError = "None";
        private static string lastAttempt = "None";

        // Self-verifying, fail-closed instrumentation (Top-20 #4): track which
        // assemblies are "app" code (not framework/SharpFuzz itself) so /shm/health
        // can report whether instrumentation actually reached the target's own
        // code, not just that the SharpFuzz runtime loaded. Mirrors
        // instrumentor/Program.cs's `frameworkPrefixes` — kept in sync manually.
        private static readonly string[] frameworkPrefixes = {{
            "System.", "Microsoft.", "SharpFuzz.", "Mono.", "Internal.",
            "Newtonsoft.", "Swashbuckle.", "NSwag.", "FluentValidation.",
            "Serilog.", "MediatR.", "AutoMapper.", "Dapper.",
            "Npgsql.", "MySqlConnector.", "StackExchange.",
            "Polly.", "Grpc.", "Google.Protobuf.",
        }};
        // linked_app_assemblies is deliberately NOT tracked per-assembly: SharpFuzz's
        // Trace.SharedMem type lives only in SharpFuzz.Common.dll, never in the app's
        // own IL-rewritten assemblies, so "does this app assembly define the Trace
        // type" is always false and would be a false-negative fail-closed signal.
        // The only architecturally honest way to verify instrumentation reached app
        // code is to check whether the shared bitmap actually moves after real
        // traffic — done engine-side (void/go/coverage.go::checkCoverageHealth) via a
        // warm-up probe. This list is purely informational: which app assemblies the
        // runtime has observed loaded, for diagnostics when that probe fails.
        private static readonly ConcurrentDictionary<string, byte> seenAppAssemblies = new ConcurrentDictionary<string, byte>();

        private static bool IsAppAssembly(string name)
        {{
            if (string.IsNullOrEmpty(name)) return false;
            foreach (var prefix in frameworkPrefixes)
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }}

        private static void SyncSharpFuzz()
        {{
            try {{
                string[] candidates = {{ "SharpFuzz.Common", "SharpFuzz" }};
                foreach (var name in candidates) {{ try {{ Assembly.Load(name); }} catch {{ }} }}

                foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) {{
                    string asmName = a.GetName().Name ?? a.FullName;
                    bool isApp = IsAppAssembly(asmName);
                    if (isApp) seenAppAssemblies.TryAdd(asmName, 1);

                    string[] types = {{ "SharpFuzz.Common.Trace", "SharpFuzz.Common.Instrumenter", "SharpFuzz.Trace", "SharpFuzz.Instrumenter" }};
                    foreach (var typeName in types) {{
                        Type t = a.GetType(typeName);
                        if (t == null) continue;

                        lastAttempt = $"Matched {{t.FullName}} in {{a.GetName().Name}}";

                        string[] members = {{ "SharedMem", "SharedMemory", "sharedMemory", "_sharedMemory" }};
                        foreach (var m in members) {{
                            var p = t.GetProperty(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                            if (p != null) {{
                                unsafe {{
                                    var boxedPtr = System.Reflection.Pointer.Box(globalShmAddr.ToPointer(), typeof(byte*));
                                    p.SetValue(null, boxedPtr);
                                }}
                                isSynced = true;
                                lastAttempt = $"Synced {{t.FullName}}.{{m}} (Property)";
                            }}

                            var f = t.GetField(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                            if (f != null) {{
                                f.SetValue(null, globalShmAddr);
                                isSynced = true;
                                lastAttempt = $"Synced {{t.FullName}}.{{m}} (Field)";
                            }}
                        }}
                    }}
                }}
                if (!isSynced) syncError = "SharpFuzz coverage type NOT found or members missing.";
                else syncError = "None";
            }} catch (Exception ex) {{ syncError = ex.Message; }}
        }}

        public static void AddCoverageEndpoints(this IEndpointRouteBuilder endpoints)
        {{
            endpoints.MapPost("/shm/create", () =>
            {{
                if (globalShmAddr == IntPtr.Zero) {{ Initialize(); }}
                else {{ SyncSharpFuzz(); }}
                return Results.Ok(new {{
                    mode = isFileBacked ? "file-backed-mmap" : "heap",
                    size = SHM_SIZE,
                    status = isSynced ? "synced" : "pending",
                    lastAttempt = lastAttempt,
                    error = syncError
                }});
            }});

            endpoints.MapPost("/shm/reset", () =>
            {{
                if (globalShmAddr != IntPtr.Zero)
                {{
                    lock (covLock)
                    {{
                        unsafe {{ byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }}
                        if (seenBuckets != null) Array.Clear(seenBuckets, 0, seenBuckets.Length);
                        totalClasses = 0;
                    }}
                    return Results.Ok("SHM Reset");
                }}
                return Results.Problem("SHM not initialized");
            }});

            endpoints.MapGet("/shm/coverage", () => {{
                // "edges" is the number of distinct (edge, hit-count-bucket) classes
                // discovered so far — the same bucketed novelty the per-request
                // X-Coverage-Delta header reports. "hits" remains the raw sum of the
                // live bitmap (recomputed here since this endpoint is polled rarely).
                var s = GetCoverageStats();
                return Results.Json(new {{ edges = totalClasses, hits = s.hits, size = SHM_SIZE }});
            }});

            endpoints.MapGet("/shm/health", () => {{
                // Reports facts only, not a verdict: SharpFuzz's Trace type lives in
                // SharpFuzz.Common.dll, never in the app's own rewritten assemblies, so
                // per-assembly "linked" status can't be measured by type reflection here.
                // The fail-closed ok/degraded decision is made engine-side (Go), which can
                // send real warm-up traffic and check whether the bitmap actually moves —
                // see void/go/coverage.go::checkCoverageHealth. app_assemblies below is
                // purely diagnostic context for that decision.
                bool shmBound = globalShmAddr != IntPtr.Zero;
                return Results.Json(new {{
                    shm_bound = shmBound,
                    mode = isFileBacked ? "file-backed-mmap" : "heap",
                    total_classes = totalClasses,
                    linked_assemblies = isSynced ? 1 : 0,
                    instrumented_types = InstrumentedTypeCount,
                    app_assemblies = seenAppAssemblies.Keys.ToArray()
                }});
            }});

            endpoints.MapGet("/shm/coverage/traces", () => {{
                return Results.Json(new {{ traces = traceCoverage.Values.OrderByDescending(s => s.Timestamp) }});
            }});

            // Per-request trace lookup (reads and removes the snapshot — consumed once by the fuzzer).
            endpoints.MapGet("/shm/coverage/trace/{{requestId}}", (string requestId) => {{
                if (traceCoverage.TryGetValue(requestId, out var snap)) {{
                    traceCoverage.TryRemove(requestId, out _);
                    return Results.Json(snap);
                }}
                return Results.NotFound(new {{ error = "trace not found" }});
            }});
        }}

        public static (int edges, long hits) GetCoverageStats()
        {{
            if (globalShmAddr == IntPtr.Zero) return (0, 0);
            unsafe {{
                byte* b = (byte*)globalShmAddr;
                int edges = 0; long hits = 0;
                for (int i = 0; i < SHM_SIZE; i++) {{ if (b[i] > 0) {{ edges++; hits += b[i]; }} }}
                return (edges, hits);
            }}
        }}
    }}
}}
"""
    # Prefer Utilities/ (most ASP.NET projects use this convention); fall back to Helpers/.
    utilities_dir = output_path / main_proj.path / "Utilities"
    helpers_dir = output_path / main_proj.path / "Helpers"
    if utilities_dir.exists():
        target_dir = utilities_dir
    else:
        target_dir = helpers_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "CoverageExtensions.cs").write_text(code)
    print(f"  Generated Coverage Extensions in {main_proj.name}/{target_dir.name}/")


# ============================================================================
# Program.cs injection
# ============================================================================

def _detect_builder_name(content: str) -> str:
    """Detect the WebApplication builder variable name"""
    m = re.search(r'var\s+(\w+)\s*=\s*WebApplication\.CreateBuilder', content)
    if m:
        return m.group(1)
    m = re.search(r'(\w+)\s*=\s*WebApplication\.CreateBuilder', content)
    if m:
        return m.group(1)
    return "builder"


def _detect_app_name(content: str, builder_name: str) -> str:
    """Detect the WebApplication variable name"""
    m = re.search(rf'var\s+(\w+)\s*=\s*{re.escape(builder_name)}\.Build\(\)', content)
    if m:
        return m.group(1)
    m = re.search(rf'(\w+)\s*=\s*{re.escape(builder_name)}\.Build\(\)', content)
    if m:
        return m.group(1)
    return "app"


def _inject_into_startup_cs(startup_cs: Path, ns_prefix: str) -> bool:
    """Inject coverage middleware into Startup.cs (Bitwarden-pattern apps that use UseStartup<T>()).
    Returns True if injection was performed."""
    if not startup_cs.exists():
        return False

    content = startup_cs.read_text(encoding='utf-8-sig')

    # Only proceed if this is a real Startup class with Configure/ConfigureServices
    if 'public void Configure(' not in content and 'public void ConfigureServices(' not in content:
        return False

    modified = False

    # Inject UseCoverageMiddleware() after app.UseRouting()
    if 'UseCoverageMiddleware()' not in content:
        if 'app.UseRouting()' in content:
            content = content.replace(
                'app.UseRouting();',
                'app.UseRouting();\n\n        // UpsideFuzz: Coverage middleware\n        app.UseCoverageMiddleware();'
            )
            modified = True
        elif 'app.UseAuthentication()' in content:
            # Fallback: before UseAuthentication
            content = content.replace(
                'app.UseAuthentication();',
                '// UpsideFuzz: Coverage middleware\n        app.UseCoverageMiddleware();\n\n        app.UseAuthentication();'
            )
            modified = True

    # Inject AddCoverageEndpoints() inside UseEndpoints if present
    if 'AddCoverageEndpoints()' not in content:
        if 'endpoints.MapDefaultControllerRoute()' in content:
            content = content.replace(
                'endpoints.MapDefaultControllerRoute();',
                'endpoints.MapDefaultControllerRoute();\n\n            // UpsideFuzz: SHM coverage endpoints\n            endpoints.AddCoverageEndpoints();'
            )
            modified = True
        elif 'endpoints.MapControllers()' in content:
            content = content.replace(
                'endpoints.MapControllers();',
                'endpoints.MapControllers();\n\n            // UpsideFuzz: SHM coverage endpoints\n            endpoints.AddCoverageEndpoints();'
            )
            modified = True

    if modified:
        startup_cs.write_text(content, encoding='utf-8')
        print(f"  Injected SHM into Startup.cs")
    return modified


def inject_multi_shm_endpoints(result: MultiAnalysisResult, output_path: Path):
    """Inject SHM endpoints into the main project's Program.cs (or Startup.cs as fallback)."""
    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])
    program_cs = output_path / main_proj.path / "Program.cs"
    startup_cs = output_path / main_proj.path / "Startup.cs"

    # Determine namespace prefix for the using directive
    ns_prefix = main_proj.root_namespace or result.main_project

    # First try Startup.cs (Bitwarden / legacy ASP.NET pattern)
    if startup_cs.exists():
        startup_content = startup_cs.read_text(encoding='utf-8-sig')
        if 'public void Configure(' in startup_content:
            _inject_into_startup_cs(startup_cs, ns_prefix)
            # Also patch Program.cs below for the using/Initialize call if needed

    if not program_cs.exists():
        return

    content = program_cs.read_text(encoding='utf-8-sig')
    # Match the subdir used by generate_multi_coverage_helper: Utilities/ if it exists, else Helpers/
    utilities_dir = output_path / main_proj.path / "Utilities"
    subdir_name = "Utilities" if utilities_dir.exists() else "Helpers"
    using_line = f"using {ns_prefix}.{subdir_name};"

    # Detect variable names dynamically
    builder_name = _detect_builder_name(content)
    app_name = _detect_app_name(content, builder_name)

    # Ensure using directive is present without altering nullable/pragma directives.
    if using_line not in content:
        lines = content.splitlines(keepends=True)
        insert_at = 0
        using_regex = re.compile(r'^\s*using\s+')
        for i, line in enumerate(lines):
            stripped = line.strip().lstrip('\ufeff')
            if not stripped:
                continue
            if stripped.startswith("//") or stripped.startswith("#"):
                insert_at = i + 1
                continue
            if using_regex.match(stripped):
                insert_at = i + 1
                continue
            break
        lines.insert(insert_at, using_line + "\n")
        content = "".join(lines)

    # Insert initialization call near builder creation (safe for file-scoped namespace).
    init_call = "CoverageExtensions.Initialize();"
    if init_call not in content:
        builder_stmt_re = re.compile(
            rf'(?m)^([ \t]*(?:var\s+)?{re.escape(builder_name)}\s*=\s*WebApplication\.CreateBuilder\(.*?\);\s*)$'
        )
        m = builder_stmt_re.search(content)
        if m:
            indent_match = re.match(r'^([ \t]*)', m.group(1))
            indent = indent_match.group(1) if indent_match else ""
            insert = f"{m.group(1)}\n{indent}{init_call}"
            content = content[:m.start()] + insert + content[m.end():]
        else:
            build_stmt_re = re.compile(
                rf'(?m)^([ \t]*(?:var\s+)?{re.escape(app_name)}\s*=\s*{re.escape(builder_name)}\.Build\(\);\s*)$'
            )
            m2 = build_stmt_re.search(content)
            if m2:
                indent_match = re.match(r'^([ \t]*)', m2.group(1))
                indent = indent_match.group(1) if indent_match else ""
                insert = f"{m2.group(1)}\n{indent}{init_call}"
                content = content[:m2.start()] + insert + content[m2.end():]

    # Only inject AddControllers if the project uses controller-based routing
    # Detect: has *Controller.cs files, or already references Controllers
    has_controllers = any(
        'Controller.cs' in f for p in result.projects for f in p.business_logic_files
    )

    if has_controllers and f"{builder_name}.Services.AddControllers()" not in content:
        if 'AddControllers' not in content:
            # Try to inject after a known service registration
            anchors = [
                rf'({re.escape(builder_name)}\.Services\.\w+\(.*?\);)',
                rf'(var\s+{re.escape(builder_name)}\s*=.*?;)',
            ]
            injected = False
            for anchor in anchors:
                m = re.search(anchor, content)
                if m:
                    content = content[:m.end()] + f"\n{builder_name}.Services.AddControllers();" + content[m.end():]
                    injected = True
                    break
            if not injected:
                content = content.replace(
                    f"var {builder_name} =",
                    f"var {builder_name} =",
                )

    # Middleware: inject UseCoverageMiddleware AFTER the exception-handler middleware is registered.
    # In ASP.NET Core, middleware registered first wraps everything inside it. If CoverageMiddleware
    # is registered BEFORE the exception handler (e.g. ConfigureRequestPipeline), then when a
    # controller throws an exception, the exception handler writes the 500 response first
    # (Response.HasStarted = true) before our finally block can inject X-Exception-Type headers.
    # By injecting AFTER ConfigureRequestPipeline / BEFORE MapControllers, our middleware sits
    # INSIDE the exception handler — so we see HasStarted=false and can set the header correctly.
    if "UseCoverageMiddleware()" not in content:
        injected = False
        # Preferred: inject after ConfigureRequestPipeline() call (nopCommerce, Umbraco, etc.)
        configure_pattern = rf'({re.escape(app_name)}\.ConfigureRequestPipeline\(\);)'
        m = re.search(configure_pattern, content)
        if m:
            content = content[:m.end()] + f"\n{app_name}.UseCoverageMiddleware();" + content[m.end():]
            injected = True
        # Fallback: inject before MapControllers() so we still wrap endpoint execution
        if not injected:
            map_controllers_pattern = rf'({re.escape(app_name)}\.MapControllers\(\);)'
            m = re.search(map_controllers_pattern, content)
            if m:
                content = content[:m.start()] + f"{app_name}.UseCoverageMiddleware();\n" + content[m.start():]
                injected = True
        # Last resort: inject immediately after Build()
        if not injected:
            build_pattern = rf'(var\s+{re.escape(app_name)}\s*=\s*{re.escape(builder_name)}\.Build\(\);)'
            m = re.search(build_pattern, content)
            if m:
                content = content[:m.end()] + f"\n{app_name}.UseCoverageMiddleware();" + content[m.end():]

    # Coverage Endpoints: inject before Run()/RunAsync()
    run_pattern = rf'(await\s+)?{re.escape(app_name)}\.(Run|RunAsync)\(\);'

    if has_controllers and "MapControllers()" not in content:
        content = re.sub(
            run_pattern,
            rf'{app_name}.MapControllers();\n\1{app_name}.\2();',
            content, count=1
        )

    if "AddCoverageEndpoints()" not in content:
        content = re.sub(
            run_pattern,
            rf'{app_name}.AddCoverageEndpoints();\n\1{app_name}.\2();',
            content, count=1
        )

    program_cs.write_text(content, encoding='utf-8')
    print(f"  Injected SHM into {main_proj.name}/Program.cs")


def generate_coverage_smoke_test(result: MultiAnalysisResult, output_path: Path):
    """Write verify_coverage.sh — a runtime check that instrumentation actually
    records edges. Run it AFTER the stand is up; it fails loudly if the coverage
    middleware/SHM is not active, catching the entire class of silently-broken
    coverage that a build-time script cannot see."""
    script = r"""#!/usr/bin/env bash
# AUTO-GENERATED by fuzz-prep-multi.py — coverage smoke test.
# Primary check is /shm/coverage (reliable). The per-response X-Coverage-* header is
# best-effort only and is often absent on fast endpoints (ASP.NET starts the response
# before our middleware's finally runs), so its absence does NOT mean coverage is broken.
# Usage: ./verify_coverage.sh [BASE_URL] [WARMUP_ENDPOINT]
set -euo pipefail

BASE="${1:-http://localhost:4000}"
WARM="${2:-/alive}"

echo "1) Ensuring SHM is synced ..."
curl -fsS -X POST "${BASE}/shm/create" >/dev/null 2>&1 || true

echo "2) Warming up ${BASE}${WARM} ..."
for i in 1 2 3; do
  curl -fsS -H "X-Fuzz-Request-Id: coverage-smoke-$(date +%s)-$i" "${BASE}${WARM}" >/dev/null 2>&1 || true
done

echo "3) Reading /shm/coverage ..."
COV="$(curl -fsS "${BASE}/shm/coverage" || true)"
echo "   ${COV:-<no response>}"

EDGES="$(printf '%s' "$COV" | grep -oE '"edges"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1 || true)"

if [ -z "${EDGES:-}" ]; then
  echo "FAIL: /shm/coverage returned no edges count — SHM endpoints not wired or wrong image."
  exit 1
fi
if [ "${EDGES}" -le 0 ]; then
  echo "FAIL: edges=0 — instrumentation ran as a no-op (check build log for '[instrumentor] Done: instrumented=0')."
  exit 1
fi
echo "OK: coverage is active (edges=${EDGES}). Instrumentation verified."
"""
    dest = output_path / "verify_coverage.sh"
    dest.write_text(script, encoding="utf-8")
    try:
        dest.chmod(0o755)
    except Exception:
        pass
    print(f"  Wrote coverage smoke test: {dest.name} (run after the stand is up)")


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description='Multi-Project .NET Fuzz Prep (.NET 8+)')
    parser.add_argument('--src', required=True, help='Path to the source .NET project/solution')
    parser.add_argument('--out', required=True, help='Path for the instrumented output copy')
    parser.add_argument('--main', help='Force the main web API project name (e.g. PublicApi)', default=None)
    parser.add_argument('--exclude-namespaces', help='Comma-separated list of namespaces to EXCLUDE from instrumentation (e.g. Bit.Core.Utilities)', default="")
    parser.add_argument(
        '--inject-mode',
        choices=['hook', 'source'],
        default='hook',
        help=(
            "Coverage injection strategy. "
            "'hook' (default, recommended): ZERO-EDIT — uses DOTNET_STARTUP_HOOKS + an ASP.NET "
            "hosting startup assembly; the target's Program.cs/Startup.cs/*.csproj are never modified, "
            "and coverage is linked at load time (including lazily/dynamically loaded modules). "
            "'source' (legacy): edits Program.cs/Startup.cs to add middleware/endpoints (previous behavior)."
        ),
    )
    args = parser.parse_args()

    try:
        analyzer = MultiProjectAnalyzer(args.src)
        if args.exclude_namespaces:
            analyzer.exclude_namespaces = [ns.strip() for ns in args.exclude_namespaces.split(",") if ns.strip()]
        result = analyzer.analyze_solution(manual_main=args.main)

        out_path = Path(args.out)
        if out_path.exists():
            shutil.rmtree(out_path)
        shutil.copytree(args.src, args.out, ignore=shutil.ignore_patterns('bin', 'obj', '.git', '.idea', '.vs'))

        if args.inject_mode == 'source':
            # Legacy path: edit the target's Program.cs/Startup.cs and app csprojs.
            patch_all_csprojs(out_path)
            generate_unified_instrumentor(result, out_path)
            generate_multi_docker_configs(result, out_path, inject_mode='source')
            generate_multi_coverage_helper(result, out_path)
            inject_multi_shm_endpoints(result, out_path)
        else:
            # Zero-edit path (default): DOTNET_STARTUP_HOOKS + ASP.NET hosting startup.
            # The target's own source and csprojs are left completely untouched; the
            # coverage runtime lives in a separate UpsideFuzz.Coverage assembly that is
            # loaded at process start and links SharpFuzz coverage (including lazily
            # loaded assemblies) via an AppDomain.AssemblyLoad handler.
            generate_unified_instrumentor(result, out_path)
            generate_multi_docker_configs(result, out_path, inject_mode='hook')
            generate_startup_hook_assembly(result, out_path)
        generate_coverage_smoke_test(result, out_path)

        print(f"\n  Multi-Project Preparation Complete for Solution: {result.solution_name}")
        print(f"  Injection mode: {args.inject_mode}" + (
            "  (zero-edit: DOTNET_STARTUP_HOOKS + hosting startup)" if args.inject_mode == 'hook'
            else "  (legacy source editing)"))
        print(f"  Instrumented Projects: {result.instrumented_projects}")
        print(f"  Main Project: {result.main_project}")
        if result.instrument_all_safe:
            print(f"  Instrumentation scope: --instrument-all-user-code (root namespaces don't "
                  f"collide with the framework denylist — every non-framework/generated type is "
                  f"instrumented, not just the {len(result.all_namespaces)} auto-collected namespaces below)")
        else:
            print(f"  Instrumentation scope: namespace allowlist ({len(result.all_namespaces)} entries)")
        print(f"  Namespaces: {', '.join(result.all_namespaces)}")
        return 0
    except Exception as e:
        print(f"\n[!] Error during preparation: {e}", file=sys.stderr)
        # Uncomment for full tracebacks during development
        # traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

