"""Solution analysis: scans a .NET solution's .csproj files, classifies
business-logic vs. framework/test code, and produces a MultiAnalysisResult
for the generation modules (docker_gen/instrumentor_gen/coverage_helper_gen)
to consume.
"""

import re
import json
from pathlib import Path
from typing import List, Optional

from .models import ProjectInfo, MultiAnalysisResult, _collides_with_framework_denylist


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
        # Set by cli.py from --exclude-namespaces when provided; declared here (rather
        # than only monkey-patched from outside via `analyzer.exclude_namespaces = [...]`)
        # so the attribute is discoverable/typed instead of needing a defensive getattr
        # fallback wherever it's read.
        self.exclude_namespaces: List[str] = []

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
                except Exception as e:
                    # A read/decode failure here silently dropped the file from
                    # business_files with zero diagnostic output -- inconsistent with
                    # this module's own habit of logging every other detection edge
                    # case it hits (see the comment above about the Bitwarden
                    # namespace-detection bug this same try/except guards against).
                    self.log(f"  ! Could not read {cs}: {e}")
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

        exclude_namespaces = self.exclude_namespaces

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

