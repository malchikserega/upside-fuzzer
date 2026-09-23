"""Dockerfile + docker-compose generation: either adapts an existing
Dockerfile/compose file in place (detecting build/runtime stages and the
publish directory via detect.py's regex helpers), or generates a fresh
multi-stage Dockerfile from scratch when the target has neither.
"""

import re
import json
from pathlib import Path

from .models import MultiAnalysisResult
from .detect import _detect_last_stage, _detect_publish_dir, _detect_source_stage, _strip_publish_single_file


def generate_multi_docker_configs(
    result: MultiAnalysisResult,
    output_path: Path,
    inject_mode: str = "hook",
    write_compose: bool = True,
):
    """Adapt original Dockerfile if present, or generate from scratch.

    inject_mode:
      'hook'   — zero-edit: build the UpsideFuzz.Coverage assembly in a dedicated
                 stage, drop it (and SharpFuzz.Common.dll) into /coverage in the
                 runtime image, and wire DOTNET_STARTUP_HOOKS +
                 ASPNETCORE_HOSTINGSTARTUPASSEMBLIES via ENV. No app source edits.
      'source' — legacy: coverage lives in CoverageExtensions.cs injected into the app.

    write_compose:
      When an original compose file exists in the target, it is always adapted in
      place regardless of this flag (that path is reliable for any service count).
      This flag only gates the OTHER case: no original compose file was found at
      all. True (default) writes a single-service docker-compose.instrumented.yml,
      which is only ever correct for a genuinely single-service target -- multi-
      service targets (a DB, an auth server, ...) need a hand-written compose file
      anyway, so generating one here is often just a file that gets thrown away
      (see docs/BITWARDEN_FUZZ_RUNBOOK.md for a worked example). False skips writing
      it and instead writes COMPOSE_REQUIREMENTS.md, documenting exactly what a
      hand-written compose file must include.
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

    dll_names = [p.dll_name for p in result.projects]

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
# ---- INJECTED BY bin/fuzz-prep-multi.py ----
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
        dll_list = [f"/src/{p.path}/bin/Release/{p.target_framework}/{p.dll_name}" for p in result.projects]
        instrument_flag = "--instrument-all-user-code" if result.instrument_all_safe else "--config /instrumentor/bin/namespaces.json"
        # Top-20+ #21: see the matching comment in the "adapt original Dockerfile"
        # branch above -- CmpLog only makes sense (and only gets wired) in hook mode.
        if inject_mode == "hook":
            instrument_flag += " --cmplog"
        instrument_commands = "\n".join(
            [f"RUN DOTNET_ROLL_FORWARD=Major dotnet /instrumentor/bin/instrumentor.dll {dll} {instrument_flag}" for dll in dll_list]
        )

        # `dotnet build` on a multi-project solution leaves each project with its own
        # bin/ folder, and MSBuild's copy-local mechanism already placed a copy of
        # every OTHER referenced project's DLL inside EACH project's own folder
        # BEFORE any instrumentation runs above. Each RUN instruments the copy sitting
        # in that DLL's OWN project folder -- so for any non-main project, the freshly
        # instrumented bytes never reach main_proj's folder, and the final
        # `COPY --from=instrumentation .../{{main_proj}}/bin/...` below would silently
        # ship the stale, pre-instrumentation copy of every dependency DLL instead
        # (confirmed empirically on fixtures/demo-app/: TeamFlow.Infrastructure.dll -- which
        # holds nearly all of the app's business logic -- shipped with zero SharpFuzz/
        # CmpLog instrumentation despite the build log claiming otherwise). Sync the
        # real instrumented copy of every non-main project's DLL back into main_proj's
        # own folder so the final COPY actually picks up what was just instrumented.
        sync_commands = "\n".join(
            f"RUN cp /src/{p.path}/bin/Release/{p.target_framework}/{p.dll_name} "
            f"/src/{main_proj.path}/bin/Release/{main_proj.target_framework}/{p.dll_name}"
            for p in result.projects if p.name != main_proj.name
        )

        # The instrumentor also writes .upsidefuzz_constants.jsonl / _instrumented.jsonl
        # next to each DLL it processes (same per-project-folder split as above), and
        # UpsideFuzz.Coverage's StartupHook reads both by scanning AppContext.BaseDirectory
        # (== main_proj's shipped folder, i.e. /app in the runtime image) at startup --
        # so a non-main project's own metadata file needs to land there too. Both are
        # JSONL (one JSON object appended per instrumented DLL), so appending is correct;
        # `[ -f ... ]` guards handle projects ConstantExtractor found nothing in (it skips
        # writing the file entirely when there's nothing to extract).
        meta_sync_commands = "\n".join(
            f"RUN for f in .upsidefuzz_constants.jsonl .upsidefuzz_instrumented.jsonl; do "
            f"if [ -f /src/{p.path}/bin/Release/{p.target_framework}/$f ]; then "
            f"cat /src/{p.path}/bin/Release/{p.target_framework}/$f "
            f">> /src/{main_proj.path}/bin/Release/{main_proj.target_framework}/$f; fi; done"
            for p in result.projects if p.name != main_proj.name
        )

        dockerfile_content = f"""# AUTO-GENERATED by bin/fuzz-prep-multi.py
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
{sync_commands}
{meta_sync_commands}
{coverage_hook_stage}
FROM mcr.microsoft.com/dotnet/aspnet:{fw_tag}
WORKDIR /app
COPY --from=instrumentation /src/{main_proj.path}/bin/Release/{main_proj.target_framework}/ .
{_hook_runtime_block() if inject_mode == "hook" else ""}EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "{main_proj.dll_name}"]
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
                    "  #     context: ..\n"
                    "  #     dockerfile: deployments/docker/Dockerfile.void\n"
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
        # This branch used to hardcode `dockerfile: Dockerfile`, assuming the build's
        # Dockerfile always lives at the context root. That's only true when NO
        # original Dockerfile was found either (the "generate from scratch" branch
        # above then writes a fresh one to output_path/Dockerfile). When an original
        # Dockerfile WAS found, it's adapted **in place** at its real location (e.g.
        # src/Api/Dockerfile) -- never moved to root -- so a compose file generated
        # here (no original compose existed) must reference that same real,
        # possibly-nested path, not assume root. Fixed 2026-07-25.
        compose_dockerfile_path = (
            str(original_dockerfile.relative_to(output_path)) if original_dockerfile else "Dockerfile"
        )

        if write_compose:
            docker_compose_content = f"""services:
  instrumented:
    build:
      context: .
      dockerfile: {compose_dockerfile_path}
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
  #     context: ..
  #     dockerfile: deployments/docker/Dockerfile.void
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
        else:
            requirements_content = f"""# Compose requirements for this target

No original compose file was found in `--src`, and `--no-compose` was passed, so
`bin/fuzz-prep-multi.py` did **not** generate `docker-compose.instrumented.yml`. Write your
own compose file (any name `docker compose` auto-discovers: `docker-compose.yml` or
`compose.yaml`) covering whatever this target actually needs (a database, an auth
server, a data-seeding tool, ...) and give the **one service that runs the instrumented
Dockerfile below** exactly these four things. Nothing else here is generated or
required for any other service in your stack.

## 1. Point `build` at the adapted Dockerfile

The Dockerfile below was adapted **in place** at its original location -- never moved to
the compose-file's own directory root:

```yaml
    build:
      context: .
      dockerfile: {compose_dockerfile_path}
```

## 2. Mount the coverage shared-memory volume

Both mounts are required. `/dev/shm` is where SharpFuzz's own SHM primitives live;
`coverage_shm` is the bitmap the fuzzer engine reads from (HTTP polling or a
direct-mmap sidecar, see `void/README.md`):

```yaml
    volumes:
      - /dev/shm:/dev/shm
      - coverage_shm:/coverage_shm
```

...and define the named volume once, top-level, in the same compose file:

```yaml
volumes:
  coverage_shm:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=4m
```

## 3. Recommended: ASPNETCORE_ENVIRONMENT=Development

Not strictly required for coverage to work, but recommended -- Development mode is
what makes ASP.NET Core return full exception detail (type, message, stack trace) in
5xx response bodies instead of a generic error page, which is what the crash triage/
clustering pipeline uses to produce a real bug label instead of just a status code:

```yaml
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
```

## 4. Optional: a `void` sidecar for direct-shm mode

Only needed if you want the fuzzer to read the coverage bitmap via a direct mmap of
the `coverage_shm` volume (faster than HTTP polling) instead of running `void` on the
host. See Mode B in `docs/QUICKSTART_BITWARDEN.md` for a complete, working example --
copy its `smartfuzzer`/`seeder`-style service block rather than re-deriving it.

## Multi-service targets: nothing above applies to your other services

The four items above apply **only** to the one service built from the Dockerfile this
tool adapted. A database, auth/identity server, migration job, or data-seeding tool
needs none of this -- configure them exactly as the target's own real deployment
requires. `docs/BITWARDEN_FUZZ_RUNBOOK.md` Step 2 is a complete, real, verified
multi-service compose file (mssql + migrator + api + identity + a data seeder) built
from exactly this template -- read it end-to-end before writing your own from scratch,
even for a different target; the shape (one instrumented service, N supporting
services with ordinary `depends_on`/healthcheck wiring) generalizes directly.
"""
            (output_path / "COMPOSE_REQUIREMENTS.md").write_text(requirements_content)
            print("  --no-compose: skipped generating docker-compose.instrumented.yml.")
            print(f"  Wrote {output_path / 'COMPOSE_REQUIREMENTS.md'} -- see it for what your own compose file needs.")

