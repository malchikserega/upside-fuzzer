# Installation / Prerequisites

Split out of the main runbook (now [quickstart.md](quickstart.md)) during the
repo-architecture refactor so "what do I need installed" has its own short
page instead of being section 1 of a much longer document.

**→ [Back to README](../../README.md) · [Quickstart](quickstart.md) · [Docs Index](../index.md)**

---

Install the following on any new system before running UpsideFuzz:

| Tool | Version | Purpose |
|------|---------|---------|
| **Docker** + **Docker Compose v2** | Docker 24+, Compose 2.x | Build & run instrumented containers (not needed for grammar compilation itself) |
| **Python** | 3.9+ | Run `bin/fuzz-prep-multi.py` and `tools/grammar/grammarc/` (stdlib-only, no `pip install` needed) |
| **.NET SDK** | 8+ | `tools/dotnet/analyzer/` — the Roslyn syntax-tree analyzer `bin/compile-grammar.sh` runs when `--src` is given |
| **Go** (optional) | 1.22+ | Only if you build the Go fuzzer binary locally |
| **sqlpackage** (optional) | Microsoft build | Import `.bacpac` into SQL Server from the host for targets that require manual SQL Server restores |

```bash
# Verify tooling
docker --version        # Docker version 24+
docker compose version  # Docker Compose version v2+
python3 --version       # Python 3.9+
dotnet --version        # 8.0+
```

> **Note:** The Go fuzzer runs as a Docker container, so Go itself is NOT required on the host unless you build locally.

> **Apple Silicon / ARM hosts:** SQL Server in Docker is usually `linux/amd64` and often runs under emulation unless the target compose file pins that platform explicitly. Expect slower first-time pulls and DB startup on SQL Server-backed targets.

---

**→ Next: [Quickstart](quickstart.md)**
