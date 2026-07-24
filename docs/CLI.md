# upsidefuzz CLI (Top-20 #19)

A single orchestrator over the existing pipeline — `fuzz-prep-multi.py` → `docker compose` →
`verify-hook.sh` → `compile-grammar.sh` → `void` — so you don't have to remember four
tools' worth of flags and manual `cd`s. It changes **nothing** about how any of those
tools work: every subcommand just shells out to the real, unmodified tool. Running them
directly, exactly as documented in [INSTRUCTIONS.md](../INSTRUCTIONS.md) and the
`QUICKSTART_*.md` files, keeps working — this is purely additive.

Two ways to run it:

| Mode | Requires locally | Command |
|------|-------------------|---------|
| **Native** | Python 3 (always); Docker (build/up/down/fuzz `--direct-shm`); .NET SDK 8+ (only if you pass `--src` for Roslyn constraints) | `python3 upsidefuzz.py <subcommand> ...` |
| **Zero-install (Docker)** | Docker only | `./upsidefuzz <subcommand> ...` |

The zero-install mode runs `upsidefuzz.py` inside `Dockerfile.cli`, an image that bundles
Python, the .NET SDK, and a prebuilt `void` binary — so a machine with nothing but Docker
installed can run the entire pipeline, including the Roslyn analyzer step, without
installing anything else.

---

## Quick start

```bash
# Zero-install (only Docker needed):
./upsidefuzz doctor              # sanity-check what's available
./upsidefuzz run \
  --src ~/my-target/src --out ./my-target-fuzz --main MyProject.Api \
  --target http://localhost:8080 --swagger http://localhost:8080/swagger/v1/swagger.json \
  --time-budget 15

# Native (needs python3 + docker locally, + dotnet if using --src):
python3 upsidefuzz.py run --src ~/my-target/src --out ./my-target-fuzz --main MyProject.Api \
  --target http://localhost:8080 --swagger http://localhost:8080/swagger/v1/swagger.json \
  --time-budget 15
```

`run` is the all-in-one pipeline: **instrument → build+up → verify → grammar → fuzz**,
mirroring exactly what the `QUICKSTART_*.md` docs walk through by hand. For anything
non-standard — a multi-stage bring-up like Bitwarden's (mssql healthcheck → migrator →
api/identity), `-direct-shm` mode, custom auth — use the individual subcommands below, or
fall back to the manual pipeline (both remain fully documented and supported).

---

## Subcommands

Every subcommand has `--help` (e.g. `./upsidefuzz fuzz --help`). Summary:

| Subcommand | Wraps | Purpose |
|---|---|---|
| `instrument` | `fuzz-prep-multi.py` | Produce a zero-edit instrumented copy of a .NET solution |
| `build` | `docker compose build` | Build the instrumented image |
| `up` | `docker compose up -d` (+ optional health-wait) | Start the instrumented containers |
| `down` | `docker compose down [-v]` | Tear the containers down |
| `verify` | `verify-hook.sh` | Confirm the coverage hook is actually linked and producing edges |
| `grammar` | `compile-grammar.sh` | Compile `templates.export.json` + `dict.json` from a Swagger spec (+ optional Roslyn) |
| `fuzz` | the `void` binary | Run the fuzzer against a running target |
| `run` | all of the above | The full pipeline in one command |
| `doctor` | — | Report which local tools are available and what's missing |

### `instrument`

```bash
upsidefuzz instrument --src ./MyProject/src --out ./my-project-fuzz --main MyProject.Api
```

Same flags as `fuzz-prep-multi.py --help` (`--exclude-namespaces`, `--inject-mode
hook|source`). See [INSTRUCTIONS.md §3](../INSTRUCTIONS.md#3-step-1-instrument-the-project).

### `build` / `up` / `down`

```bash
upsidefuzz up --dir ./my-project-fuzz --wait-url http://localhost:8080/health --wait-timeout 120
upsidefuzz down --dir ./my-project-fuzz --volumes
```

Pass `--services name1 name2` to `build`/`up`/`run` to build/start only specific compose
services instead of the whole file — needed for multi-service targets where you don't want
every service up (e.g. eShopOnWeb's `sqlserver eshoppublicapi`, not its MVC frontend too).

`up` builds (unless `--skip-build`) then starts the stack, and — if `--wait-url` is given —
polls it until it responds (any HTTP status counts as "up"; only connection failures keep
retrying). Without `--wait-url`, pass `--wait-secs N` for a fixed sleep instead, matching
the "wait ~45–90s" convention the QUICKSTART docs use for targets with DB migrations. For
multi-stage bring-up (Bitwarden's mssql → migrator → api/identity choreography), use plain
`docker compose` commands as documented in
[QUICKSTART_BITWARDEN.md](../QUICKSTART_BITWARDEN.md) instead — `up` is for the common,
single-stage case.

### `verify`

```bash
upsidefuzz verify --base http://localhost:8080 --probe /api/catalog-items
```

Thin wrapper over `verify-hook.sh` — same `--up`/`--down`/`--dir`/`--probe`/`--base` flags,
same 5-check output (SHM create, `/shm/health`, per-request attribution, real-traffic
coverage growth, cumulative edges). See [ARCHITECTURE.md §5](../ARCHITECTURE.md).

### `grammar`

```bash
upsidefuzz grammar http://localhost:8080/swagger/v1/swagger.json --src ./MyProject/src --out ./my-project-fuzz/grammar
```

Same as `compile-grammar.sh`, plus one convenience: the swagger argument may be an
`http(s)://` URL (downloaded automatically) as well as a local file path.

### `fuzz`

```bash
upsidefuzz fuzz --grammar ./my-project-fuzz/grammar --target http://localhost:8080 \
  --profile security --time-budget 15 --auth-file auth-identities.json
```

Sets `TARGET_HOST`/`SHM_HOST`/`AUTH_TOKEN` and runs the `void` binary with `-grammar
-profile -time-budget [-direct-shm -shm-path] [-auth-file] [-no-ui]`. Anything after `--`
is passed straight through to `void` as additional raw flags — the full flag surface in
[void/README.md](../void/README.md) is always available, nothing is hidden.

The `void` binary itself is resolved in this order: `--void-bin` if given, then
`void/go/void` (the native build convention), then `void` on `PATH` (what the Docker image
provides). If none is found, native mode tells you to `cd void/go && go build -o void .`
or switch to `./upsidefuzz` (Docker).

### `doctor`

```bash
upsidefuzz doctor
```

Checks `python3`/`docker` (required) and `dotnet`/`go` (optional — only needed for `--src`
Roslyn analysis and native `void` builds respectively), and tells you whether to switch to
the Docker launcher if something required is missing.

---

## How the zero-install (`./upsidefuzz`) mode works

`Dockerfile.cli` builds an image containing:
- Python 3
- the .NET SDK (9.0 — the analyzer targets `net9.0`; the .NET 9 SDK can still build/run
  everything else in the pipeline that targets `net8.0`, SDKs build *down*)
- a `void` binary, built from `void/go/` in the same multi-stage build `void/Dockerfile.go`
  uses
- the Docker CLI + compose-v2 plugin (copied from the official `docker:27-cli` image), for
  issuing `docker compose` commands against your **host's** Docker daemon
- this repo's own tooling (`fuzz-prep-multi.py`, `compile-grammar.sh`, `verify-hook.sh`,
  `grammarc/`, `analyzer/`), baked in at `/upsidefuzz`

The `./upsidefuzz` launcher runs this image with:
- `-v /var/run/docker.sock:/var/run/docker.sock` — **Docker-outside-of-Docker**: `docker
  compose` commands issued *inside* the CLI container control containers on your actual
  host, not some nested Docker-in-Docker sandbox.
- `-v "$(pwd):$(pwd)" -w "$(pwd)"` — your current directory is bind-mounted at the **same
  absolute path** inside the container. This matters because the daemon that ultimately
  runs `docker compose build`/`up` is the *host* daemon — it resolves build contexts and
  volumes from the host filesystem, so relative paths in generated compose files only
  resolve correctly if the in-container path matches the host path exactly.

**Practical consequence:** run `./upsidefuzz` from a directory that's an ancestor of both
your target's source and your desired `--out`/output directory (the repo root itself is
usually the right place, exactly like running the scripts natively). A `--src` path
*outside* your current directory tree won't be visible inside the container.

### The `localhost` gotcha (and why `--target`/`--swagger`/`--wait-url` "just work" anyway)

The CLI container and your target's instrumented containers are Docker **siblings** — both
children of the host daemon — not parent/child. `localhost` inside the CLI container is
the CLI container's *own* loopback, which can never reach a port your target publishes on
the host. `host.docker.internal` is the portable fix (built into Docker Desktop; the
launcher also adds `--add-host=host.docker.internal:host-gateway` for native Linux Docker,
where it isn't automatic).

You don't need to think about this: when running inside the container,
`upsidefuzz.py`'s `_containerize_url` transparently rewrites any `localhost`/`127.0.0.1` in
`--target`/`--shm-host`/`--base`/`--wait-url`/a swagger URL to `host.docker.internal`
before using it — both for its own health-check polling *and* for the `TARGET_HOST`/
`SHM_HOST` environment variables passed to `void`, since `void` also runs inside this same
container. Native mode does nothing here (no rewrite needed — a natively-run process
already shares the host's actual network).

---

## Working with specific targets

Every target has its own quirks (multi-stage bring-up, basic-auth-protected Swagger,
malformed OpenAPI specs needing a patch script, cookie vs. bearer auth) that the CLI
doesn't try to abstract away — the individual subcommands are building blocks, and each
target's quickstart shows exactly how to combine them, with the target-specific manual
steps kept as manual steps:

| Target | CLI section |
|---|---|
| eShopOnWeb | [QUICKSTART_ESHOP.md § The same thing, via the upsidefuzz CLI](../QUICKSTART_ESHOP.md#the-same-thing-via-the-upsidefuzz-cli) — `run` works end to end, no non-standard steps |
| BTCPayServer | [QUICKSTART_BTCPAYSERVER.md § The same thing, via the upsidefuzz CLI](../QUICKSTART_BTCPAYSERVER.md#the-same-thing-via-the-upsidefuzz-cli) — basic-auth swagger download stays manual |
| SimplCommerce | [QUICKSTART_SIMPLCOMMERCE.md § The same thing, via the upsidefuzz CLI](../QUICKSTART_SIMPLCOMMERCE.md#the-same-thing-via-the-upsidefuzz-cli) — swagger sanitize + cookie login stay manual |
| Bitwarden (fresh) | [QUICKSTART_BITWARDEN.md § The same thing, via the upsidefuzz CLI](../QUICKSTART_BITWARDEN.md#the-same-thing-via-the-upsidefuzz-cli) — multi-stage bring-up (mssql → migrator → api/identity) stays manual |
| Bitwarden (already set up) | [BITWARDEN_FUZZ_RUNBOOK.md § 8](../BITWARDEN_FUZZ_RUNBOOK.md#8-the-same-thing-via-the-upsidefuzz-cli) |

The common pattern across all of them: whatever step is genuinely target-specific (a login
script, a swagger patch, a non-standard bring-up order) stays exactly as documented in the
manual walkthrough; everything else — `instrument`/`up`/`verify`/`grammar`/`fuzz`/`down` —
becomes one CLI call. `run` (the all-in-one) only fits targets with no non-standard steps
in between (eShopOnWeb, and most single-service targets you add yourself) — plug the
individual subcommands together for anything more involved, exactly like the tables above.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Could not find a void binary` | Native mode only: `cd void/go && go build -o void .`, or use `./upsidefuzz` instead |
| `run failed: coverage instrumentation degraded: ...` | The fail-closed startup check (Top-20 #4) caught real instrumentation breakage — see [ARCHITECTURE.md](../ARCHITECTURE.md)'s "Self-verifying, fail-closed instrumentation" section, don't just pass `-allow-degraded-coverage` |
| `Timed out waiting for http://...` during `up`/`run` | Check `(cd <out-dir> && docker compose logs)` — the container may be failing to start, or `--wait-timeout` may be too short for a target with DB migrations |
| Docker-mode `grammar`/`run` writes files that "disappear" | Fixed 2026-07-24 — `compile-grammar.sh` used to resolve relative `--out`/`--swagger` paths against its own script location rather than your cwd, which only happened to be harmless when they were the same directory. `git pull` if you still see this. |
| `docker: command not found` inside `./upsidefuzz` output | You're in native mode without Docker installed — either install Docker or don't use `build`/`up`/`down`/`fuzz --direct-shm` |

---

**→ [Back to docs index](INDEX.md)**
