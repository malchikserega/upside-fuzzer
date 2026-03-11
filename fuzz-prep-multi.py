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
            is_web = 'Sdk="Microsoft.NET.Sdk.Web"' in content
            root_ns = self._extract_root_namespace(content, csproj.stem)

            if manual_main and csproj.stem.lower() == manual_main.lower():
                main_project_name = csproj.stem
                is_web = True
                self.log(f"  * Forced Main Project: {main_project_name}")
            elif not manual_main and is_web and not main_project_name:
                main_project_name = csproj.stem

            # Handle both <TargetFramework> and <TargetFrameworks>
            framework = "net8.0"
            fw_match = re.search(r'<TargetFrameworks?>(.*?)</TargetFrameworks?>', content)
            if fw_match:
                fw_value = fw_match.group(1)
                if ';' in fw_value:
                    frameworks = [f.strip() for f in fw_value.split(';')]
                    net_versions = [f for f in frameworks if f.startswith('net') and not f.startswith('netstandard')]
                    framework = sorted(net_versions, reverse=True)[0] if net_versions else frameworks[0]
                    self.log(f"  Multi-targeting detected, using: {framework}")
                else:
                    framework = fw_value

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
                    m = re.search(r'namespace\s+([\w\.]+)', txt)
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

        return MultiAnalysisResult(
            solution_name=self.src_path.name,
            projects=projects,
            main_project=main_project_name,
            all_namespaces=sorted(list(all_namespaces)),
            total_files=total_files_count,
            instrumented_projects=len(projects),
            sdk_version=sdk_version,
        )


# ============================================================================
# Dockerfile & Compose generation
# ============================================================================

def _detect_last_stage(content: str) -> Optional[str]:
    """Find the name of the last named stage (the runtime/final stage)"""
    stages = re.findall(r'FROM\s+\S+\s+AS\s+(\w+)', content, re.IGNORECASE)
    return stages[-1] if stages else None


def _detect_publish_dir(content: str) -> str:
    """Extract publish output directory from Dockerfile"""
    m = re.search(r'dotnet\s+publish\s+.*?(?:-o|--output)\s+(\S+)', content)
    return m.group(1) if m else "/app/publish"


def _detect_source_stage(content: str) -> str:
    """Find the build stage that the runtime stage copies from"""
    copy_matches = list(re.finditer(r'COPY\s+--from=(\S+)', content))
    return copy_matches[-1].group(1) if copy_matches else "builder"


def generate_multi_docker_configs(result: MultiAnalysisResult, output_path: Path):
    """Adapt original Dockerfile if present, or generate from scratch"""

    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])
    framework = main_proj.target_framework
    fw_tag = framework.replace('net', '')

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

        publish_dir = _detect_publish_dir(content)
        source_stage = _detect_source_stage(content)
        runtime_stage = _detect_last_stage(content)

        print(f"  Detected build stage: {source_stage}, runtime stage: {runtime_stage or '(unnamed)'}")

        # Deduplicate to prevent "already instrumented" errors
        unique_dlls = sorted(list(set(dll_names)))
        instrument_cmds = "\n".join([
            f'RUN if [ -f {publish_dir}/{dll} ]; then '
            f'echo "Instrumenting {dll}"; '
            f'DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll {publish_dir}/{dll}; '
            f'else echo "Skipping {dll} (not found)"; fi'
            for dll in unique_dlls
        ])

        injected_stages = f"""
# ---- INJECTED BY fuzz-prep-multi.py ----
# Stage: Build the SharpFuzz instrumentor
FROM mcr.microsoft.com/dotnet/sdk:{sdk_tag} AS instrumentor-build
WORKDIR /instrumentor
RUN dotnet new console -n instrumentor -o . --force
COPY instrumentor_src/Program.cs ./
RUN dotnet add package SharpFuzz
RUN dotnet build -c Release -o /instrumentor/bin

# Stage: Apply instrumentation to published DLLs
FROM {source_stage} AS instrumentation
COPY --from=instrumentor-build /instrumentor/bin /instrumentor/bin
{instrument_cmds}
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
        instrument_commands = "\n".join(
            [f"RUN DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll {dll}" for dll in dll_list]
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
RUN dotnet add package SharpFuzz
RUN dotnet build -c Release -o /instrumentor/bin

FROM build AS instrumentation
COPY --from=instrumentor-build /instrumentor/bin /instrumentor/bin
{instrument_commands}

FROM mcr.microsoft.com/dotnet/aspnet:{fw_tag}
WORKDIR /app
COPY --from=instrumentation /src/{main_proj.path}/bin/Release/{main_proj.target_framework}/ .
EXPOSE 8080
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
                    "  #     context: ../smart_fuzzer\n"
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
  #     context: ../smart_fuzzer
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
    """Generate instrumentor that supports a unified filter for all projects"""

    ns_patterns = [f'fullName.Contains("{ns}")' for ns in result.all_namespaces]
    filter_code = f"({' || '.join(ns_patterns)})" if ns_patterns else "false"

    code = f"""// AUTO-GENERATED by fuzz-prep-multi.py
using System;
using SharpFuzz;

namespace instrumentor
{{
    class Program
    {{
        static int Main(string[] args)
        {{
            if (args.Length == 0) {{
                Console.WriteLine("Usage: instrumentor <path-to-dll>");
                return 1;
            }}

            string dllPath = args[0];
            Console.WriteLine($"Instrumenting DLL: {{dllPath}}");

            bool ShouldInstrument(string fullName)
            {{
                // Skip compiler-generated classes which cause AccessViolationException in SharpFuzz
                if (fullName.Contains("<PrivateImplementationDetails>") || 
                    fullName.Contains("<Module>") || 
                    fullName.Contains("<<") ||
                    fullName.Contains("c__DisplayClass") ||
                    fullName.Contains("d__"))
                    return false;

                // Aggressively skip DTOs, records, view models and specs (frequent source of CVE/AV in SharpFuzz)
                if (fullName.EndsWith("SpecificationProvider") ||
                    fullName.EndsWith("Specification") ||
                    fullName.EndsWith("Dto") || 
                    fullName.EndsWith("ViewModel") ||
                    fullName.EndsWith("Request") ||
                    fullName.EndsWith("Response") ||
                    fullName.Contains("Models") && !fullName.Contains("Service"))
                    return false;

                // Skip entry points and infrastructure (but NOT business extension methods)
                if (fullName.Contains("Program") || fullName.Contains("Startup") ||
                    fullName.Contains("Migration") || fullName.Contains("CoverageExtensions") ||
                    fullName.Contains("DesignTimeDbContext") || fullName.Contains(".g.") ||
                    fullName.Contains("Infrastructure") || fullName.Contains("Swagger") ||
                    fullName.Contains("CustomExceptionHandler") || fullName.Contains("DependencyInjection") ||
                    fullName.Contains("Filters") || fullName.Contains("Exception") ||
                    fullName.Contains("Middleware") || fullName.Contains("Mapping") || 
                    fullName.Contains("Swashbuckle") || fullName.Contains("Microsoft.Extensions") ||
                    fullName.Contains("MicroElements") || fullName.Contains("FluentValidation") ||
                    fullName.Contains("Validator"))
                    return false;

                if ({filter_code})
                {{
                    Console.WriteLine($"  + {{fullName}}");
                    return true;
                }}
                return false;
            }}

            try {{
                SharpFuzz.Fuzzer.Instrument(dllPath, ShouldInstrument, SharpFuzz.Options.Value);
                Console.WriteLine("Done!");
                return 0;
            }} catch (Exception ex) {{
                Console.WriteLine($"Failed: {{ex.Message}}");
                return 1;
            }}
        }}
    }}
}}
"""
    instr_dir = output_path / "instrumentor_src"
    instr_dir.mkdir(parents=True, exist_ok=True)
    (instr_dir / "Program.cs").write_text(code)
    print("  Generated Unified Instrumentor.")


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

namespace {ns_prefix}.Helpers
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
        private static readonly int SHM_SIZE = ResolveShmSize();

        private static IntPtr globalShmAddr = IntPtr.Zero;
        private static bool isSynced = false;
        private static bool isFileBacked = false;
        private static MemoryMappedFile mmf;
        private static MemoryMappedViewAccessor accessor;
        private static ConcurrentDictionary<string, CoverageSnapshot> traceCoverage = new ConcurrentDictionary<string, CoverageSnapshot>();

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
            SyncSharpFuzz();
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
                int before = GetCurrentEdgeCount();
                try {{
                    await next();
                }} catch (Exception ex) {{
                    exceptionTypeName = ex.GetType().Name;
                    throw;
                }} finally {{
                    int after = GetCurrentEdgeCount();
                    int delta = after - before;
                    // Inject per-request coverage into response headers — zero HTTP overhead.
                    // The fuzzer reads X-Coverage-Delta directly from the fuzz response.
                    try {{
                        if (!context.Response.HasStarted) {{
                            context.Response.Headers["X-Coverage-Delta"] = delta.ToString();
                            context.Response.Headers["X-Coverage-Edges"] = after.ToString();
                            if (exceptionTypeName != null)
                                context.Response.Headers["X-Exception-Type"] = exceptionTypeName;
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
                        CoverageBefore = before,
                        CoverageAfter = after,
                        CoverageDelta = delta,
                        Timestamp = DateTime.UtcNow
                    }};
                }}
            }});
        }}

        private static string syncError = "None";
        private static string lastAttempt = "None";

        private static void SyncSharpFuzz()
        {{
            try {{
                string[] candidates = {{ "SharpFuzz.Common", "SharpFuzz" }};
                foreach (var name in candidates) {{ try {{ Assembly.Load(name); }} catch {{ }} }}

                foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) {{
                    string[] types = {{ "SharpFuzz.Common.Trace", "SharpFuzz.Common.Instrumenter", "SharpFuzz.Trace", "SharpFuzz.Instrumenter" }};
                    foreach (var typeName in types) {{
                        Type t = a.GetType(typeName);
                        if (t == null) continue;

                        lastAttempt = $"Matched {{t.FullName}} in {{a.GetName().Name}}";

                        string[] members = {{ "SharedMem", "SharedMemory", "sharedMemory", "_sharedMemory" }};
                        foreach (var m in members) {{
                            var p = t.GetProperty(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                            if (p != null) {{
                                p.SetValue(null, globalShmAddr);
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
                    unsafe {{ byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }}
                    return Results.Ok("SHM Reset");
                }}
                return Results.Problem("SHM not initialized");
            }});

            endpoints.MapGet("/shm/coverage", () => {{
                var s = GetCoverageStats();
                return Results.Json(new {{ edges = s.edges, hits = s.hits }});
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

        private static int GetCurrentEdgeCount() => GetCoverageStats().edges;
    }}
}}
"""
    helpers_dir = output_path / main_proj.path / "Helpers"
    helpers_dir.mkdir(parents=True, exist_ok=True)
    (helpers_dir / "CoverageExtensions.cs").write_text(code)
    print(f"  Generated Coverage Extensions in {main_proj.name}")


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


def inject_multi_shm_endpoints(result: MultiAnalysisResult, output_path: Path):
    """Inject SHM endpoints into the main project's Program.cs"""
    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])
    program_cs = output_path / main_proj.path / "Program.cs"

    if not program_cs.exists():
        return

    content = program_cs.read_text(encoding='utf-8-sig')
    ns_prefix = main_proj.root_namespace or result.main_project
    using_line = f"using {ns_prefix}.Helpers;"

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


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description='Multi-Project .NET Fuzz Prep (.NET 8+)')
    parser.add_argument('--src', required=True, help='Path to the source .NET project/solution')
    parser.add_argument('--out', required=True, help='Path for the instrumented output copy')
    parser.add_argument('--main', help='Force the main web API project name (e.g. PublicApi)', default=None)
    args = parser.parse_args()

    try:
        analyzer = MultiProjectAnalyzer(args.src)
        result = analyzer.analyze_solution(manual_main=args.main)

        out_path = Path(args.out)
        if out_path.exists():
            shutil.rmtree(out_path)
        shutil.copytree(args.src, args.out, ignore=shutil.ignore_patterns('bin', 'obj', '.git', '.idea', '.vs'))

        patch_all_csprojs(out_path)
        generate_unified_instrumentor(result, out_path)
        generate_multi_docker_configs(result, out_path)
        generate_multi_coverage_helper(result, out_path)
        inject_multi_shm_endpoints(result, out_path)

        print(f"\n  Multi-Project Preparation Complete for Solution: {result.solution_name}")
        print(f"  Instrumented Projects: {result.instrumented_projects}")
        print(f"  Main Project: {result.main_project}")
        print(f"  Namespaces: {', '.join(result.all_namespaces)}")
        return 0
    except Exception as e:
        print(f"\n[!] Error during preparation: {e}", file=sys.stderr)
        # Uncomment for full tracebacks during development
        # traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

