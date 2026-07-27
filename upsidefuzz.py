#!/usr/bin/env python3
"""
upsidefuzz.py - Single CLI orchestrator for the UpsideFuzz pipeline (Top-20 #19).

Wraps the existing, unmodified pipeline (fuzz-prep-multi.py -> docker compose ->
verify-hook.sh -> compile-grammar.sh -> void) behind one command with sane
defaults, so the four-script-plus-Docker-incantations workflow becomes a few
subcommands. This is a thin orchestration layer only: every subcommand shells
out to the existing tool unchanged. Nothing about fuzz-prep-multi.py,
compile-grammar.sh, verify-hook.sh, or void/go/ is modified or bypassed -- the
manual, script-by-script workflow documented in docs/INSTRUCTIONS.md/QUICKSTART_*.md
keeps working exactly as before, this is purely additive.

Two ways to run it:
  1. Natively:  python3 upsidefuzz.py <subcommand> ...
     Needs whatever the subcommand itself needs (python3 always; docker for
     build/up/down/fuzz --direct-shm; .NET SDK 8+ only if you pass --src to
     `grammar`/`run`, for the Roslyn analyzer).
  2. Zero-install, via Docker: ./upsidefuzz <subcommand> ...
     The `upsidefuzz` launcher (repo root) runs this exact script inside the
     upsidefuzz-cli Docker image (see Dockerfile.cli), which bundles Python,
     the .NET SDK, and a prebuilt void binary -- so the only thing you need
     installed locally is Docker itself. See docs/CLI.md.

Run `python3 upsidefuzz.py <subcommand> --help` for per-subcommand options.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

ROOT_DIR = Path(__file__).resolve().parent


def _banner(msg: str) -> None:
    print(f"\n{'=' * 70}\n{msg}\n{'=' * 70}")


def _run(cmd: List[str], cwd: Optional[Path] = None, env: Optional[dict] = None, check: bool = True) -> int:
    print(f"  $ {' '.join(str(c) for c in cmd)}" + (f"   (cwd={cwd})" if cwd else ""))
    full_env = None
    if env:
        full_env = os.environ.copy()
        full_env.update(env)
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=full_env)
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result.returncode


def _compose_file(dir_: Path) -> Optional[str]:
    """fuzz-prep-multi.py always writes docker-compose.instrumented.yml, which
    `docker compose` does not auto-discover (only compose.y[a]ml/docker-compose.y[a]ml
    are). Prefer it explicitly if present; otherwise let docker compose auto-discover
    (e.g. a hand-written compose file in a non-generated directory)."""
    candidate = dir_ / "docker-compose.instrumented.yml"
    return candidate.name if candidate.is_file() else None


def _compose(dir_: Path, args: List[str], check: bool = True) -> int:
    cmd = ["docker", "compose"]
    compose_file = _compose_file(dir_)
    if compose_file:
        cmd += ["-f", compose_file]
    cmd += args
    return _run(cmd, cwd=dir_, check=check)


def _containerize_url(url: Optional[str]) -> Optional[str]:
    """When upsidefuzz.py itself runs inside the CLI Docker image (Dockerfile.cli,
    launched via the ./upsidefuzz wrapper), it and the target's instrumented
    containers are Docker *siblings*, not parent/child -- `localhost`/`127.0.0.1`
    inside this container refers to this container's own loopback, not the host's,
    so it can never reach a port the target publishes on the host. `host.docker.internal`
    is the portable fix (built into Docker Desktop; the launcher adds
    --add-host=host.docker.internal:host-gateway for Linux). No-op when running
    natively (UPSIDEFUZZ_IN_CONTAINER unset) -- native runs share the host network
    directly and localhost already means the right thing."""
    if not url or os.environ.get("UPSIDEFUZZ_IN_CONTAINER") != "1":
        return url
    return url.replace("://localhost", "://host.docker.internal").replace("://127.0.0.1", "://host.docker.internal")


def _download(url: str, dest: Path) -> Path:
    print(f"  Downloading {url} -> {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            dest.write_bytes(resp.read())
    except urllib.error.URLError as e:
        print(f"FAILED to download {url}: {e}", file=sys.stderr)
        sys.exit(1)
    return dest


def _resolve_swagger(swagger: str, workdir: Path) -> Path:
    if swagger.startswith("http://") or swagger.startswith("https://"):
        return _download(_containerize_url(swagger), workdir / "swagger.json")
    p = Path(swagger)
    if not p.is_file():
        print(f"Swagger file not found: {swagger}", file=sys.stderr)
        sys.exit(1)
    return p


def _wait_for_http(url: str, timeout: float) -> bool:
    """Polls url until the server responds with ANY HTTP status (even 404/500) --
    that's still proof something is listening and answering, which is all this
    needs to know. Only connection failures (nothing listening yet) keep retrying."""
    print(f"  Waiting up to {timeout:.0f}s for {url} to respond...")
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                print(f"  Target is up (HTTP {resp.status}).")
                return True
        except urllib.error.HTTPError as e:
            print(f"  Target is up (HTTP {e.code}).")
            return True
        except Exception as e:  # noqa: BLE001 - connection refused/reset/timeout, keep retrying
            last_err = e
        time.sleep(2)
    print(f"  Timed out waiting for {url} (last error: {last_err})", file=sys.stderr)
    return False


def _find_void_binary(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    native = ROOT_DIR / "void" / "go" / "void"
    if native.is_file() and os.access(native, os.X_OK):
        return str(native)
    on_path = shutil.which("void")
    if on_path:
        return on_path
    print(
        "Could not find a `void` binary.\n"
        "  - Native run: build it with `cd void/go && go build -o void .` (needs Go 1.22+), or\n"
        "  - Zero-install: use the Docker launcher `./upsidefuzz fuzz ...` instead, which bundles a prebuilt binary.\n"
        "See void/README.md 'Build for Any Platform' for details.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_instrument(args: argparse.Namespace) -> None:
    _banner(f"1. Instrumenting {args.src} -> {args.out}")
    cmd = [
        sys.executable, str(ROOT_DIR / "fuzz-prep-multi.py"),
        "--src", args.src, "--out", args.out,
        "--inject-mode", args.inject_mode,
    ]
    if args.main:
        cmd += ["--main", args.main]
    if args.exclude_namespaces:
        cmd += ["--exclude-namespaces", args.exclude_namespaces]
    if args.no_compose:
        cmd += ["--no-compose"]
    _run(cmd)


def cmd_build(args: argparse.Namespace) -> None:
    _banner(f"2. Building instrumented image in {args.dir}")
    compose_args = ["build"]
    if args.no_cache:
        compose_args.append("--no-cache")
    compose_args += getattr(args, "services", None) or []
    _compose(Path(args.dir), compose_args)


def cmd_up(args: argparse.Namespace) -> None:
    if not args.skip_build:
        cmd_build(args)
    _banner(f"3. Starting containers in {args.dir}")
    services = getattr(args, "services", None) or []
    _compose(Path(args.dir), ["up", "-d"] + services)
    if args.wait_url:
        wait_url = _containerize_url(args.wait_url)
        if not _wait_for_http(wait_url, args.wait_timeout):
            print(
                f"Containers started but {args.wait_url} never came up within {args.wait_timeout:.0f}s.\n"
                f"  Check logs: (cd {args.dir} && docker compose logs)",
                file=sys.stderr,
            )
            sys.exit(1)
    elif args.wait_secs > 0:
        print(f"  Waiting {args.wait_secs:.0f}s for startup (no --wait-url given, using a fixed sleep)...")
        time.sleep(args.wait_secs)


def cmd_down(args: argparse.Namespace) -> None:
    _banner(f"Tearing down containers in {args.dir}")
    compose_args = ["down"]
    if args.volumes:
        compose_args.append("-v")
    _compose(Path(args.dir), compose_args, check=False)


def cmd_verify(args: argparse.Namespace) -> None:
    _banner("4. Verifying zero-edit coverage hook (verify-hook.sh)")
    cmd = [str(ROOT_DIR / "verify-hook.sh")]
    if args.up:
        cmd.append("--up")
    if args.down:
        cmd.append("--down")
    if args.dir:
        cmd += ["--dir", args.dir]
    if args.probe:
        cmd += ["--probe", args.probe]
    if args.base:
        cmd += ["--base", _containerize_url(args.base)]
    env = {"WAIT_SECS": str(args.wait_secs)} if args.wait_secs is not None else None
    _run(cmd, env=env)


def cmd_grammar(args: argparse.Namespace) -> None:
    _banner("5. Compiling the grammar (compile-grammar.sh)")
    workdir = Path(args.out) if args.out else ROOT_DIR
    swagger_path = _resolve_swagger(args.swagger, workdir)
    cmd = [str(ROOT_DIR / "compile-grammar.sh"), str(swagger_path)]
    if args.dict:
        cmd += ["--dict", args.dict]
    if args.src:
        cmd += ["--src", args.src]
    if args.out:
        cmd += ["--out", args.out]
    _run(cmd)


def cmd_fuzz(args: argparse.Namespace) -> None:
    _banner("6. Running the fuzzer (void)")
    void_bin = _find_void_binary(args.void_bin)
    cmd = [
        void_bin,
        "-grammar", args.grammar,
        "-profile", args.profile,
        "-time-budget", str(args.time_budget),
    ]
    if args.direct_shm:
        cmd.append("-direct-shm")
        cmd += ["-shm-path", args.shm_path]
    if args.auth_file:
        cmd += ["-auth-file", args.auth_file]
    if args.no_ui:
        cmd.append("-no-ui")
    cmd += args.void_args

    target = _containerize_url(args.target)
    shm_host = _containerize_url(args.shm_host) or target
    env = {"TARGET_HOST": target, "SHM_HOST": shm_host}
    if args.auth_token:
        env["AUTH_TOKEN"] = args.auth_token
    _run(cmd, env=env)


def cmd_run(args: argparse.Namespace) -> None:
    """The all-in-one orchestrator: instrument -> build+up -> verify -> grammar -> fuzz."""
    out = args.out
    cmd_instrument(argparse.Namespace(
        src=args.src, out=out, main=args.main,
        inject_mode=args.inject_mode, exclude_namespaces=args.exclude_namespaces,
    ))
    cmd_up(argparse.Namespace(
        dir=out, skip_build=False, no_cache=args.no_cache, services=args.services,
        wait_url=args.target, wait_timeout=args.wait_timeout, wait_secs=0,
    ))
    if not args.skip_verify:
        cmd_verify(argparse.Namespace(
            up=False, down=False, dir=out, probe=args.probe, base=args.target,
            wait_secs=None,
        ))
    grammar_out = args.grammar_out or str(Path(out) / "grammar")
    cmd_grammar(argparse.Namespace(
        swagger=args.swagger, dict=args.dict,
        src=None if args.no_roslyn else args.src, out=grammar_out,
    ))
    cmd_fuzz(argparse.Namespace(
        grammar=grammar_out, target=args.target, shm_host=None,
        auth_token=args.auth_token, auth_file=args.auth_file,
        profile=args.profile, time_budget=args.time_budget,
        direct_shm=False, shm_path="/coverage_shm/bitmap",
        void_bin=args.void_bin, no_ui=args.no_ui, void_args=args.void_args,
    ))
    _banner(f"Done. Instrumented copy: {out}  Grammar: {grammar_out}")


def cmd_doctor(_args: argparse.Namespace) -> None:
    _banner("Environment check")
    checks = [
        ("python3", [sys.executable, "--version"], True),
        ("docker", ["docker", "--version"], True),
        ("dotnet", ["dotnet", "--version"], False),
        ("go", ["go", "version"], False),
    ]
    missing_required = []
    for name, cmd, required in checks:
        path = shutil.which(cmd[0])
        if path is None:
            status = "MISSING" if required else "missing (optional)"
            print(f"  [{'  ' if required else 'opt'}] {name:10s} {status}")
            if required:
                missing_required.append(name)
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip().splitlines()[0]
        except Exception:  # noqa: BLE001
            out = "(found, version check failed)"
        print(f"  [ok] {name:10s} {out}  ({path})")

    void_bin = ROOT_DIR / "void" / "go" / "void"
    if void_bin.is_file():
        print(f"  [ok] void binary   found at {void_bin}")
    elif shutil.which("void"):
        print(f"  [ok] void binary   found on PATH ({shutil.which('void')})")
    else:
        print("  [  ] void binary   not built yet -- `cd void/go && go build -o void .`, or use ./upsidefuzz (Docker)")

    print()
    if missing_required:
        print(f"Missing required tool(s): {', '.join(missing_required)}.")
        print("Recommendation: use the zero-install Docker launcher instead: ./upsidefuzz <subcommand> ...")
        print("(builds/uses the upsidefuzz-cli image, see Dockerfile.cli + docs/CLI.md)")
    else:
        print("All required tools found. `dotnet`/`go` are only needed for --src Roslyn analysis / native void builds.")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upsidefuzz",
        description="Single CLI orchestrator for the UpsideFuzz pipeline (Top-20 #19). "
                     "Every subcommand wraps an existing, unmodified tool -- run them "
                     "individually, or use `run` for the full instrument->fuzz pipeline.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("instrument", help="Instrument a .NET solution (wraps fuzz-prep-multi.py)")
    sp.add_argument("--src", required=True, help="Path to the source .NET project/solution")
    sp.add_argument("--out", required=True, help="Path for the instrumented output copy")
    sp.add_argument("--main", help="Force the main web API project name")
    sp.add_argument("--exclude-namespaces", help="Comma-separated namespaces to exclude")
    sp.add_argument("--inject-mode", choices=["hook", "source"], default="hook")
    sp.add_argument(
        "--no-compose", action="store_true",
        help="Skip generating docker-compose.instrumented.yml when --src has no compose "
             "file of its own; writes COMPOSE_REQUIREMENTS.md instead. No effect when "
             "--src already has a compose file. Use for multi-service targets -- see "
             "docs/BITWARDEN_FUZZ_RUNBOOK.md.",
    )
    sp.set_defaults(func=cmd_instrument)

    sp = sub.add_parser("build", help="docker compose build the instrumented image")
    sp.add_argument("--dir", required=True, help="Instrumented output directory")
    sp.add_argument("--no-cache", action="store_true")
    sp.add_argument("--services", nargs="*", help="Build only these compose services (default: all)")
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("up", help="Build and start the instrumented containers")
    sp.add_argument("--dir", required=True)
    sp.add_argument("--no-cache", action="store_true")
    sp.add_argument("--skip-build", action="store_true", help="Skip `docker compose build`, just `up -d`")
    sp.add_argument("--services", nargs="*", help="Build/start only these compose services (default: all) -- "
                                                    "needed for multi-service targets where you don't want "
                                                    "every service (e.g. eShopOnWeb: sqlserver eshoppublicapi)")
    sp.add_argument("--wait-url", help="Poll this URL until it responds (e.g. http://localhost:8080/health)")
    sp.add_argument("--wait-timeout", type=float, default=180.0)
    sp.add_argument("--wait-secs", type=float, default=0.0, help="Fixed sleep fallback if --wait-url is not given")
    sp.set_defaults(func=cmd_up)

    sp = sub.add_parser("down", help="docker compose down the instrumented containers")
    sp.add_argument("--dir", required=True)
    sp.add_argument("--volumes", "-v", action="store_true", help="Also remove volumes (docker compose down -v)")
    sp.set_defaults(func=cmd_down)

    sp = sub.add_parser("verify", help="Verify the zero-edit coverage hook (wraps verify-hook.sh)")
    sp.add_argument("--base", help="Target base URL (default http://localhost:8080)")
    sp.add_argument("--probe", help="Real GET endpoint to probe for coverage growth")
    sp.add_argument("--dir", help="Instrumented output dir (for --up/--down)")
    sp.add_argument("--up", action="store_true", help="Build+start the compose stack first")
    sp.add_argument("--down", action="store_true", help="Tear the stack down afterwards")
    sp.add_argument("--wait-secs", type=int, default=None, help="Startup wait when --up is given (WAIT_SECS)")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("grammar", help="Compile a fuzzing grammar (wraps compile-grammar.sh)")
    sp.add_argument("swagger", help="Path or URL to the OpenAPI/Swagger JSON")
    sp.add_argument("--dict", help="Custom dictionary JSON")
    sp.add_argument("--src", help=".NET source tree for Roslyn constraint extraction")
    sp.add_argument("--out", help="Output directory (default: grammars/<swagger-basename>/)")
    sp.set_defaults(func=cmd_grammar)

    sp = sub.add_parser("fuzz", help="Run the fuzzer (wraps the void binary)")
    sp.add_argument("--grammar", required=True, help="Grammar directory (templates.export.json + dict.json)")
    sp.add_argument("--target", default="http://localhost:8080", help="TARGET_HOST")
    sp.add_argument("--shm-host", help="SHM_HOST (defaults to --target)")
    sp.add_argument("--auth-token", help="AUTH_TOKEN (bearer token)")
    sp.add_argument("--auth-file", help="Path to auth identities JSON (-auth-file)")
    sp.add_argument("--profile", default="security", choices=["fast", "deep", "security"])
    sp.add_argument("--time-budget", type=float, default=15.0, help="Minutes")
    sp.add_argument("--direct-shm", action="store_true", help="Docker sidecar mode: read SHM directly")
    sp.add_argument("--shm-path", default="/coverage_shm/bitmap")
    sp.add_argument("--void-bin", help="Explicit path to the void binary")
    sp.add_argument("--no-ui", action="store_true")
    sp.add_argument("void_args", nargs=argparse.REMAINDER, help="Extra flags passed through to void as-is")
    sp.set_defaults(func=cmd_fuzz)

    sp = sub.add_parser(
        "run",
        help="Full pipeline: instrument -> build+up -> verify -> grammar -> fuzz",
        description="Runs the entire pipeline end to end with sane defaults -- "
                     "the `upsidefuzz run --target ...` command from the roadmap. "
                     "For anything non-standard (multi-stage bring-up, custom auth, "
                     "direct-shm mode) use the individual subcommands instead.",
    )
    sp.add_argument("--src", required=True, help="Path to the source .NET project/solution")
    sp.add_argument("--out", required=True, help="Path for the instrumented output copy")
    sp.add_argument("--main", help="Force the main web API project name")
    sp.add_argument("--exclude-namespaces")
    sp.add_argument("--inject-mode", choices=["hook", "source"], default="hook")
    sp.add_argument("--no-cache", action="store_true")
    sp.add_argument("--services", nargs="*", help="Build/start only these compose services (default: all)")
    sp.add_argument("--target", default="http://localhost:8080", help="Where the instrumented app will be reachable")
    sp.add_argument("--wait-timeout", type=float, default=180.0)
    sp.add_argument("--probe", help="Real GET endpoint for verify-hook.sh's coverage-growth check")
    sp.add_argument("--skip-verify", action="store_true")
    sp.add_argument("--swagger", required=True, help="Path or URL to the running target's swagger.json")
    sp.add_argument("--dict", help="Custom dictionary JSON")
    sp.add_argument("--no-roslyn", action="store_true", help="Skip Roslyn constraint extraction even if --src is set")
    sp.add_argument("--grammar-out", help="Grammar output dir (default: <out>/grammar)")
    sp.add_argument("--auth-token", help="AUTH_TOKEN (bearer token) for the fuzz step")
    sp.add_argument("--auth-file", help="Path to auth identities JSON for the fuzz step")
    sp.add_argument("--profile", default="security", choices=["fast", "deep", "security"])
    sp.add_argument("--time-budget", type=float, default=15.0, help="Minutes")
    sp.add_argument("--void-bin", help="Explicit path to the void binary")
    sp.add_argument("--no-ui", action="store_true")
    sp.add_argument("void_args", nargs=argparse.REMAINDER, help="Extra flags passed through to void as-is")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("doctor", help="Check which local tools are available")
    sp.set_defaults(func=cmd_doctor)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
