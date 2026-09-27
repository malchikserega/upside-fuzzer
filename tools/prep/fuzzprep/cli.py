"""Command-line entry point: parses args, runs MultiProjectAnalyzer, and
dispatches to the docker/instrumentor/coverage-helper generation modules
based on --inject-mode. This is the only module the thin bin/fuzz-prep-multi.py
wrapper at the repo root calls into.
"""

import sys
import shutil
import argparse
from pathlib import Path

from .analysis import MultiProjectAnalyzer
from .docker_gen import generate_multi_docker_configs
from .instrumentor_gen import generate_unified_instrumentor, generate_startup_hook_assembly
from .coverage_helper_gen import (
    patch_all_csprojs,
    generate_multi_coverage_helper,
    inject_multi_shm_endpoints,
    generate_coverage_smoke_test,
)


def main() -> int:
    parser = argparse.ArgumentParser(description='Multi-Project .NET Fuzz Prep (.NET 8+)')
    parser.add_argument('--src', required=True, help='Path to the source .NET project/solution')
    parser.add_argument('--out', required=True, help='Path for the instrumented output copy')
    parser.add_argument('--main', help='Force the main web API project name (e.g. PublicApi)', default=None)
    parser.add_argument('--exclude-namespaces', help='Comma-separated list of namespaces to EXCLUDE from instrumentation (e.g. Bit.Core.Utilities)', default="")
    parser.add_argument(
        '--no-compose',
        action='store_true',
        help=(
            "When no original compose file exists in --src, skip generating "
            "docker-compose.instrumented.yml and write COMPOSE_REQUIREMENTS.md instead "
            "(what a hand-written compose file needs). Has no effect when --src already "
            "has a compose file -- that one is always adapted in place either way. Use "
            "this for multi-service targets (a DB, an auth server, ...) where the "
            "auto-generated single-service file would just get thrown away -- see "
            "docs/BITWARDEN_FUZZ_RUNBOOK.md for a worked example."
        ),
    )
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
            generate_multi_docker_configs(result, out_path, inject_mode='source', write_compose=not args.no_compose)
            generate_multi_coverage_helper(result, out_path)
            inject_multi_shm_endpoints(result, out_path)
        else:
            # Zero-edit path (default): DOTNET_STARTUP_HOOKS + ASP.NET hosting startup.
            # The target's own source and csprojs are left completely untouched; the
            # coverage runtime lives in a separate UpsideFuzz.Coverage assembly that is
            # loaded at process start and links SharpFuzz coverage (including lazily
            # loaded assemblies) via an AppDomain.AssemblyLoad handler.
            generate_unified_instrumentor(result, out_path)
            generate_multi_docker_configs(result, out_path, inject_mode='hook', write_compose=not args.no_compose)
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
