# Repo Layout

This repo went through a structural cleanup on 2026-07-31: the root directory
used to mix source code (Go module files, a Python CLI package), entrypoint
scripts (`compile-grammar.sh`, `fuzz-prep-multi.py`, `upsidefuzz.py`, ...),
and local working state (`bitwarden_fresh/`, `crashes/`, `grammars/`, ...) all
at the same level. This page documents the result and exists so nobody has to
reverse-engineer the new layout from `git log`.

**Nothing about the fuzzer's behavior changed** — no CLI flag, no grammar
format, no report/checkpoint format, no oracle semantics. This was purely a
"where do files live" reorganization, executed with `git mv` so history is
preserved on every moved file.

## Top-level map

```
.
├── README.md, CHANGELOG.md, requirements.txt, Makefile   # the only loose files at root
├── upsidefuzz                  # the ONE public launcher (unchanged public interface)
├── .gitignore, .dockerignore, .cursorrules (symlink)
│
├── src/
│   ├── void/                   # self-contained Go module (go.mod lives here)
│   │   ├── go.mod, go.sum
│   │   ├── cmd/void/           # main.go, README.md (full CLI reference)
│   │   └── internal/
│   │       ├── config/         # flags.go, profiles.go
│   │       └── engine/         # the fuzzer itself (~40 files)
│   └── cli/upsidefuzz/         # the Python CLI package (cli.py + __main__.py)
│
├── bin/                        # entrypoint scripts, tracked in git despite the name
│   ├── compile-grammar.sh
│   ├── fuzz-prep-multi.py
│   ├── verify-hook.sh
│   └── compatibility/          # thin wrappers kept ONLY for old invocation paths
│       ├── upsidefuzz.py
│       ├── campaign.py
│       └── security_scenarios.py
│
├── tools/                      # unchanged: prep/, grammar/, campaign/, dotnet/
├── docs/                       # unchanged, plus:
│   ├── assets/pipeline-animation/     # was repo-root pipeline-animation/
│   └── research/design-notes/RCE_DISCOVERY_PLAN.md
├── deployments/, scripts/, tests/, fixtures/   # unchanged
│   └── (examples/ merged into docs/guides/examples/)
```

## Why `src/void/` is a *separate* Go module, not just a moved directory

`go.mod`/`go.sum` moved from the repo root to `src/void/go.mod`. This makes
`src/void/` a self-contained Go module — `go` commands run against it need
either `cd src/void` first or Go's `-C` flag:

```bash
go -C src/void build -o cmd/void/void ./cmd/void
go -C src/void test ./...
go -C src/void vet ./...
```

`make build`/`make test`/`make lint`/`make fmt` already do this for you —
prefer those unless you have a reason not to. CI (`.github/workflows/e2e.yml`)
uses `go -C src/void ...` directly plus `cache-dependency-path: src/void/go.sum`.

## Why `bin/` even though `.gitignore` has a bare `bin/` rule

`.gitignore` already ignored any directory literally named `bin` anywhere in
the tree (`tools/dotnet/*/bin/`, `fixtures/demo-app/src/*/bin/` — real .NET
build-output directories). The new top-level `bin/` is not a build-output
directory, it's tracked source (shell/Python entrypoints), so `.gitignore`
has an explicit `!/bin/` negation right where the `.NET build artifacts`
section is — don't remove it, or the tracked `bin/` silently stops being
seen by git.

## `bin/` vs. `bin/compatibility/`

- **`bin/compile-grammar.sh`, `bin/fuzz-prep-multi.py`, `bin/verify-hook.sh`**
  are the primary entrypoints. `fuzz-prep-multi.py` is itself a thin forward
  to `tools/prep/fuzzprep/`, but it's a *primary*, expected-to-be-used-directly
  entrypoint, not a legacy shim.
- **`bin/compatibility/upsidefuzz.py`, `campaign.py`, `security_scenarios.py`**
  are kept *specifically* for backward compatibility with older documented
  invocations (`python3 upsidefuzz.py ...`, `from campaign import Campaign`,
  etc.) that predate both this move and the earlier `cmd/`+`internal/`
  refactor. The public, still-recommended way to reach the same
  functionality is the `./upsidefuzz` launcher at the repo root — these
  wrapper scripts exist so nothing that already depends on the old direct
  invocation breaks, not because they're the preferred way to invoke
  anything going forward.

None of the six were deleted — every one of them still had live references
in docs, CI, or `tests/integration/compatibility/test_compat_wrappers.py`
(the smoke-test suite that exercises every wrapper listed above, plus the
`./upsidefuzz` launcher itself, as a real subprocess from the repo root —
run it with `make test-compat`).

## The one thing that didn't move: `./upsidefuzz`

The public launcher stays at the repo root with its exact existing
interface (`./upsidefuzz <subcommand> ...`, `./upsidefuzz --no-docker
<subcommand> ...`, `UPSIDEFUZZ_NO_DOCKER=1`, `UPSIDEFUZZ_IMAGE=...`) —
only its *internal* `--no-docker` target changed, from the old repo-root
`upsidefuzz.py` to `bin/compatibility/upsidefuzz.py`.

## `.work/` — local working state

See **[`.work/README.md`](../../.work/README.md)** for the full layout
(`targets/`, `grammars/`, `specs/`, `runs/`, `secrets/`) and a safe, opt-in
migration guide from the older loose root-level patterns
(`bitwarden_fresh/`, `crashes/`, `summaries/`, `grammars/`,
`auth.identities.json`, ...) — those old patterns are still in `.gitignore`
and still work unchanged; nothing moved automatically.

## Full old → new path reference

| Old | New |
|---|---|
| `go.mod`, `go.sum` | `src/void/go.mod`, `src/void/go.sum` |
| `cmd/void/` | `src/void/cmd/void/` |
| `internal/config/`, `internal/engine/` | `src/void/internal/config/`, `src/void/internal/engine/` |
| `cmd/upsidefuzz/` | `src/cli/upsidefuzz/` |
| `compile-grammar.sh` | `bin/compile-grammar.sh` |
| `fuzz-prep-multi.py` | `bin/fuzz-prep-multi.py` |
| `verify-hook.sh` | `bin/verify-hook.sh` |
| `upsidefuzz.py` | `bin/compatibility/upsidefuzz.py` |
| `campaign.py` | `bin/compatibility/campaign.py` |
| `security_scenarios.py` | `bin/compatibility/security_scenarios.py` |
| `upsidefuzz` (launcher) | `upsidefuzz` (unchanged, still at root) |
| `pipeline-animation/` | `docs/assets/pipeline-animation/` |
| `RCE_DISCOVERY_PLAN.md` | `docs/research/design-notes/RCE_DISCOVERY_PLAN.md` |
| `tools/`, `docs/` (otherwise), `deployments/`, `scripts/`, `tests/`, `fixtures/` | unchanged |
| `examples/` | merged into `docs/guides/examples/` |

See [`cmd/void/README.md`](../../src/void/cmd/void/README.md) (now at
`src/void/cmd/void/README.md`) for the Go fuzzer's own full CLI reference,
and [`Makefile`](../../Makefile) for every build/test/lint command in one
place, already updated for the new paths.
