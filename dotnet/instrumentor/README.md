# instrumentor

Generic SharpFuzz IL instrumentor: rewrites a compiled .NET 8+ DLL to inject coverage
probes, plus two independent Cecil passes for comparison/constant harvesting. Not run
directly by a human in the normal pipeline — `fuzzprep/` bakes a copy of this project's
source into every generated Dockerfile's instrumentation stage, and it runs there during
`docker compose build`.

## Usage

```bash
instrumentor <path-to-dll>                            # uses namespaces.json next to the DLL
instrumentor <path-to-dll> --namespaces Ns1 Ns2        # explicit namespace allowlist
instrumentor <path-to-dll> --instrument-all-user-code  # instrument everything except framework/generated types (default, recommended)
instrumentor <path-to-dll> --config /path/to/ns.json   # explicit config file path
```

## Files

| File | Purpose |
|---|---|
| `Program.cs` | Everything: CLI parsing, `NamespaceMatcher`/`InstrumentationFilter` (type-selection logic), SharpFuzz's basic-block coverage rewrite, `CmpLogInstrumentor` (records live string/int comparison operands — CmpLog/RedQueen, see `docs/ARCHITECTURE.md` §"CmpLog/RedQueen"), and `ConstantExtractor` (read-only harvest of string/int literals at instrument time). |
| `Program.Generated.cs` | **Dead code, not used.** Left in place as a marker pointing back to `Program.cs`; nothing in the build references it. |
| `instrument.sh` | Standalone manual-run helper script (progress output around a single `instrumentor <dll>` invocation) — not part of the generated-Dockerfile pipeline. |

`instrumentor_gen.py`/`coverage_helper_gen.py` in `fuzzprep/` are what actually copy this
project's source into a target's Docker build context; see `fuzzprep/__init__.py`'s
module-map docstring if you're tracing that path instead of this tool's own logic.

## Build & test

```bash
dotnet build dotnet/instrumentor/instrumentor.csproj
dotnet test dotnet/instrumentor.Tests/instrumentor.Tests.csproj
```

`NamespaceMatcher`, `InstrumentationFilter`, and the `ConstantExtractor`/`CmpLogInstrumentor`
helpers are `internal`, exposed to `instrumentor.Tests` only via `InternalsVisibleTo` — not
part of this tool's public/CLI surface.
