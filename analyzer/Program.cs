// UpsideFuzz Roslyn syntax-tree analyzer.
// Replaces enhance-grammar.py::SourceExtractor's regex-based constraint extraction with
// real Microsoft.CodeAnalysis.CSharp syntax parsing — scoped to syntax-tree analysis only
// (no MSBuildWorkspace/NuGet-restore semantic model; see docs/ARCHITECTURE_REVIEW.md #10).
//
// Usage:
//   analyzer --src <source-dir> --out <roslyn-constraints.json> [--verbose]

using System.Text.Json;
using UpsideFuzz.Analyzer;

string? srcDir = null;
string? outPath = null;
bool verbose = false;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--src" when i + 1 < args.Length: srcDir = args[++i]; break;
        case "--out" when i + 1 < args.Length: outPath = args[++i]; break;
        case "--verbose": verbose = true; break;
    }
}

if (srcDir is null || outPath is null)
{
    Console.Error.WriteLine("Usage: analyzer --src <source-dir> --out <roslyn-constraints.json> [--verbose]");
    Environment.Exit(1);
    return;
}

if (!Directory.Exists(srcDir))
{
    Console.Error.WriteLine($"[analyzer] ERROR: --src directory not found: {srcDir}");
    Environment.Exit(1);
    return;
}

Console.WriteLine($"[analyzer] Parsing source tree: {srcDir}");

var idx = new SourceIndex();
idx.Load(srcDir);
Console.WriteLine($"[analyzer] Parsed {idx.Diagnostics.FilesParsed} files ({idx.Diagnostics.FilesFailed} failed), " +
                   $"{idx.AllClasses.Count} classes, {idx.Validators.Count} FluentValidation validators, " +
                   $"{idx.ControllerCandidates.Count} controller candidates.");

var unmodeled = new List<UnmodeledValidation>();
var types = ConstraintWalker.Build(idx, unmodeled);
FluentValidationWalker.Apply(idx, types);
var endpoints = RouteAuthWalker.Build(idx);

var output = new AnalyzerOutput
{
    GeneratedAt = DateTime.UtcNow.ToString("o"),
    SourceRoot = Path.GetFullPath(srcDir),
    Types = types,
    UnmodeledValidation = unmodeled,
    Endpoints = endpoints,
    Diagnostics = idx.Diagnostics,
};

var jsonOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
};

var outDir = Path.GetDirectoryName(Path.GetFullPath(outPath));
if (!string.IsNullOrEmpty(outDir)) Directory.CreateDirectory(outDir);
File.WriteAllText(outPath, JsonSerializer.Serialize(output, jsonOptions));

Console.WriteLine($"[analyzer] Done: {types.Count} types, {endpoints.Count} endpoints, " +
                   $"{unmodeled.Count} unmodeled-validation notes -> {outPath}");

if (verbose)
{
    foreach (var ep in endpoints)
        Console.WriteLine($"[analyzer]   {ep.HttpMethod} {ep.RouteTemplate}  auth={ep.Authorize} style={ep.Style} params=[{string.Join(",", ep.ParameterTypes.Values)}]");
}
