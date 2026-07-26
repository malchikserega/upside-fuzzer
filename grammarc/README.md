# grammarc

First-party OpenAPI 2.0/3.x → typed request-grammar compiler. Stdlib-only Python — no
`pip install` needed, matching the rest of the repo's zero-third-party-dependency
convention for this pipeline. Replaces RESTler's compiler entirely (retired, see
`docs/ARCHITECTURE_REVIEW.md`); optionally merges in real C# validation constraints from
`dotnet/analyzer/` when `--src` is given.

Not usually invoked directly — `compile-grammar.sh` at the repo root wraps
`python3 -m grammarc.cli` and is the documented entry point.

## Usage

```bash
python3 -m grammarc.cli <swagger.json> --out <output-dir> [--roslyn roslyn-constraints.json]
# or, from the repo root:
./compile-grammar.sh <swagger.json> [--src <source-dir>] --out <output-dir>
```

## Files

| File | Purpose |
|---|---|
| `cli.py` | Orchestration entry point — parses args, runs the parser → merge → serialize → emit pipeline below in order. |
| `oas.py` | OpenAPI 2/3 parser (`$ref`/`allOf`/`oneOf`/`anyOf` resolution) → typed IR, retaining each operation's full schema tree, `operationId`, and `$ref` component-schema names. |
| `roslyn_merge.py` | Merges `dotnet/analyzer/`'s `roslyn-constraints.json` (real, type/property-scoped C# validation constraints) over the OpenAPI-derived model — Roslyn wins per scoped field. |
| `dependencies.py` | Producer/consumer id inference by path/name convention (e.g. `POST /orders` produces `orderId`, `GET /orders/{orderId}` consumes it). |
| `boundary.py` | Boundary-value synthesis for a merged (OAS + Roslyn) field hint — the candidate-value pool for `dict.json` and `custom_payload` segments. |
| `multipart.py` | Multipart/form-data request template synthesis. |
| `body_serializer.py` | Recursively serializes a resolved schema into the static/fuzzable/custom_payload segment list `void/go/template.go` renders into request bytes. |
| `emit_templates.py` | Assembles full request templates (method + path + query + headers + body) and writes `templates.export.json`. |
| `emit_dict.py` | Writes `dict.json`; scaffolds and merges `dict.custom.json` (the durable, hand-curated fuzzing-value convention). |
| `common.py` | Small shared helpers (e.g. `canonical_key`). |
| `test_*.py` | Unit tests, stdlib `unittest` only — run with `python3 -m unittest grammarc.test_oas -v` (or any other `test_*` module). |

## Design note

Everything here was deliberately ported near-verbatim from the retired
`enhance-grammar.py` where that logic was already correct and target-agnostic
(`oas.py`, `boundary.py`, `multipart.py`); `dependencies.py` and `body_serializer.py` are
genuinely new, since RESTler's own compiler used to do that work and there was no prior
first-party equivalent to port.
