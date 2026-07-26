# analyzer

Real Roslyn syntax-tree analyzer (`Microsoft.CodeAnalysis.CSharp`) that replaces the old
regex-based constraint extraction with actual C# parsing. Scoped to **syntax trees only**
— no `MSBuildWorkspace`/NuGet-restore semantic model — so it works on an arbitrary target
repo without needing that repo to restore or build first (see
`docs/ARCHITECTURE_REVIEW.md`'s Grammar Generation section for the tradeoff this buys).

Invoked by `compile-grammar.sh` whenever `--src` is given; not run directly in the normal
pipeline. Output is `roslyn-constraints.json`, the JSON contract `grammarc/roslyn_merge.py`
reads and merges over the OpenAPI-derived grammar (Roslyn wins per scoped field).

## Usage

```bash
dotnet run --project dotnet/analyzer -- --src <source-dir> --out roslyn-constraints.json [--verbose]
```

## Files

| File | Purpose |
|---|---|
| `Program.cs` | CLI entry point: parses args, runs the passes below in order, writes the output JSON. |
| `SourceIndex.cs` | Pass 1 — parses every `.cs` file under `--src` and builds shared lookup indexes, including resolving `partial class` declarations split across files into one logical type. |
| `ConstraintWalker.cs` | Pass 2 — per-type, per-property `DataAnnotations` constraint extraction (`[StringLength]`, `[Range]`, `[RegularExpression]`, enums). Keyed by `(fully-qualified type, property)`, never a bare property name. |
| `FluentValidationWalker.cs` | Walks `RuleFor(x => x.Prop).Chain1().Chain2()...` via real syntax nodes (invocation/member-access/lambda) — handles multi-line chains and `.When(...)` conditionals. |
| `RouteAuthWalker.cs` | Extracts route + `[Authorize]`/`[AllowAnonymous]` metadata in both classic-MVC-controller and minimal-API styles. |
| `RoslynUtil.cs` | Shared syntax-tree helpers used by every walker above. |
| `TypeResolver.cs` | Best-effort name → type-constraints lookup used by base-class merging and cross-file type matching (name-based, not symbol-based — documented, not silently wrong). |
| `Models.cs` | The output model serialized to `roslyn-constraints.json` — kept flat/acyclic since it crosses the C#→Python process boundary as plain JSON. |

## Build & test

```bash
dotnet build dotnet/analyzer/analyzer.csproj
dotnet test dotnet/analyzer.Tests/analyzer.Tests.csproj
```
