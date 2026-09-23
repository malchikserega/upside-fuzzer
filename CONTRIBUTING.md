# Contributing to UpsideFuzz

Thanks for considering a contribution. This project is Go + Python + a bit of
.NET (Roslyn analyzer / IL instrumentor), so a change can land in any of three
languages — pick the section below that matches.

## Before you start

- For anything beyond a small fix (a new oracle, a new target integration, a
  change to the grammar format or the coverage protocol), open an issue first
  describing what you want to do. It avoids wasted work if the direction
  needs adjusting.
- Read [docs/development/code-map.md](docs/development/code-map.md) — it
  lists the architectural invariants this project does not want reverted
  (e.g. why coverage attribution is single-scan, why sequence binding has a
  three-tier fallback), so you don't reintroduce something that was
  deliberately removed.

## Setup

```bash
git clone <your fork>
cd upside-fuzzer
pip install -r requirements.txt
```

Requires Go 1.22+, Python 3.9+ (stdlib only — no new runtime dependency
without a real reason), .NET SDK 8+, and Docker for the E2E gate.

## Making a change

1. Fork, branch off `main`.
2. Make your change. Keep it scoped — this repo prefers a few small, focused
   PRs over one large one.
3. Run the tests that cover what you touched, then the full suite before
   opening a PR:

   ```bash
   make test     # Go + Python + .NET + compat-wrapper suites
   make lint     # gofmt + go vet + python3 -m py_compile sweep
   make e2e      # full pipeline regression gate (needs Docker)
   ```

   `make test`/`make lint` run exactly what CI (`.github/workflows/e2e.yml`)
   runs, so a green `make test` locally means CI will pass too.
4. Update the relevant doc under `docs/` if you changed behavior — a PR that
   changes a flag, an oracle, or the grammar format without a doc update will
   get asked to add one.

## Commit / PR conventions

- Commit messages: short imperative summary line, wrapped body if needed
  (`feat(engine): ...`, `fix(grammar): ...`, `docs: ...` — see `git log` for
  the established style).
- PR description: what changed and why, plus how you tested it (unit tests,
  a real target run, etc.).
- Don't bundle unrelated refactoring into a bug-fix or feature PR.

## Adding a new fuzzing target

If you're adding a new example target (like `fixtures/demo-app` or the
target-specific quickstarts under `docs/guides/target-specific/`), see
[docs/guides/target-candidates.md](docs/guides/target-candidates.md) for
what makes a good candidate and the existing quickstart guides for the
expected structure/depth of a new one.

## Reporting bugs / vulnerabilities found *by* the fuzzer in third-party software

If a fuzzing run against a third-party target turns up a real vulnerability,
that's a disclosure matter between you and that project — please don't file
it here. Issues in this repo's tracker should be about UpsideFuzz itself
(the fuzzer, instrumentor, grammar compiler, or docs).

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE), the same license covering the rest of
the project.
