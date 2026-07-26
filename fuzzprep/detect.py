"""Pure regex-based detection helpers over Dockerfile/C# source text.

No I/O beyond what's handed in as a string, no side effects -- these are the
functions most directly responsible for the "adapt an existing Dockerfile/
Program.cs" path's correctness, and the ones most worth unit-testing in
isolation (see test_fuzz_prep_multi.py). Three real bugs across this exact
group of functions were found and fixed in one week; keeping them in their
own small module with dedicated tests is meant to make the next one cheaper
to find.
"""

import re
from typing import Optional


def _detect_last_stage(content: str) -> Optional[str]:
    """Find the name of the last named stage (the runtime/final stage).

    Must return None -- not an earlier stage's name -- when the Dockerfile's
    actual final FROM is unnamed. The previous implementation searched for
    `FROM ... AS X` and took the last match found ANYWHERE in the file, so on
    the extremely common pattern of an unnamed final runtime stage (no later
    stage ever needs to reference it by name -- confirmed on demo_app's own
    Dockerfile, and on both btcpayserver/Dockerfile and simplcommerce/Dockerfile
    in this repo's own fixture set) it silently returned an EARLIER stage's
    name (typically the SDK/build stage) as if it were the runtime stage. The
    caller then inserted the instrumentation stages (which reference that
    build stage via `FROM {source_stage} AS instrumentation`) BEFORE the build
    stage's own definition -- an invalid, unbuildable Dockerfile ("no build
    stage named X"/an image pull for a stage name from Docker Hub) that only
    surfaces at `docker build` time, not at generation time.
    """
    # `(?:--\S+\s+)*` skips BuildKit flags like `--platform=$BUILDPLATFORM` that can
    # precede the image ref (seen on btcpayserver/Dockerfile in this repo's own
    # fixture set) -- without it, the flag itself gets consumed by `\S+` and the
    # following `AS <name>` never matches, silently losing a real stage name.
    from_stage_names = re.findall(
        r'^FROM\s+(?:--\S+\s+)*\S+(?:\s+AS\s+(\S+))?', content, re.IGNORECASE | re.MULTILINE
    )
    return from_stage_names[-1] if from_stage_names and from_stage_names[-1] else None


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
