// UpsideFuzz Generic Instrumentor
// Namespace-filtered SharpFuzz IL rewriting for any .NET 8+ project.
//
// Usage:
//   instrumentor <path-to-dll>                           -- uses namespaces.json next to DLL
//   instrumentor <path-to-dll> --namespaces Ns1 Ns2      -- explicit namespace allowlist
//   instrumentor <path-to-dll> --instrument-all-user-code -- instrument everything except framework/generated
//   instrumentor <path-to-dll> --config /path/to/ns.json  -- explicit config file path

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

// ── Parse CLI ──────────────────────────────────────────────────────────────
if (args.Length == 0)
{
    Console.Error.WriteLine("Usage: instrumentor <path-to-dll> [--namespaces Ns1 Ns2 ...] [--instrument-all-user-code] [--config path]");
    Environment.Exit(1);
}

string dllPath = args[0];
bool instrumentAll = false;
string? configPath = null;
var cliNamespaces = new List<string>();

for (int i = 1; i < args.Length; i++)
{
    if (args[i] == "--instrument-all-user-code")
    {
        instrumentAll = true;
    }
    else if (args[i] == "--config" && i + 1 < args.Length)
    {
        configPath = args[++i];
    }
    else if (args[i] == "--namespaces")
    {
        for (int j = i + 1; j < args.Length; j++)
        {
            if (args[j].StartsWith("--")) break;
            cliNamespaces.Add(args[j]);
            i = j;
        }
    }
}

// ── Load namespace allowlist ───────────────────────────────────────────────
var allowedNamespaces = new List<string>(cliNamespaces);

if (allowedNamespaces.Count == 0 && !instrumentAll)
{
    // Try config file: explicit path, or namespaces.json next to DLL, or in working dir
    var candidates = new List<string>();
    if (!string.IsNullOrEmpty(configPath))
        candidates.Add(configPath);
    candidates.Add(Path.Combine(Path.GetDirectoryName(dllPath) ?? ".", "namespaces.json"));
    candidates.Add(Path.Combine(Directory.GetCurrentDirectory(), "namespaces.json"));

    foreach (var candidate in candidates)
    {
        if (File.Exists(candidate))
        {
            try
            {
                string json = File.ReadAllText(candidate);
                var parsed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                if (parsed != null && parsed.TryGetValue("namespaces", out var nsArray) &&
                    nsArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in nsArray.EnumerateArray())
                    {
                        string? v = el.GetString();
                        if (!string.IsNullOrWhiteSpace(v))
                            allowedNamespaces.Add(v);
                    }
                }
                Console.WriteLine($"[instrumentor] Loaded {allowedNamespaces.Count} namespace(s) from {candidate}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[instrumentor] WARNING: Failed to parse {candidate}: {ex.Message}");
            }
            break;
        }
    }
}

// ── Validate ───────────────────────────────────────────────────────────────
if (allowedNamespaces.Count == 0 && !instrumentAll)
{
    Console.Error.WriteLine("[instrumentor] ERROR: No namespace allowlist provided and --instrument-all-user-code not set.");
    Console.Error.WriteLine("[instrumentor] Provide namespaces via:");
    Console.Error.WriteLine("  --namespaces MyApp.Controllers MyApp.Services");
    Console.Error.WriteLine("  --config /path/to/namespaces.json");
    Console.Error.WriteLine("  --instrument-all-user-code  (instruments all non-framework types)");
    Console.Error.WriteLine("");
    Console.Error.WriteLine("[instrumentor] namespaces.json format: {\"namespaces\": [\"MyApp.Controllers\", \"MyApp.Services\"]}");
    Environment.Exit(1);
}

if (!File.Exists(dllPath))
{
    Console.Error.WriteLine($"[instrumentor] ERROR: DLL not found: {dllPath}");
    Environment.Exit(1);
}

// ── Logging ────────────────────────────────────────────────────────────────
Console.WriteLine($"[instrumentor] DLL: {dllPath}");
if (instrumentAll)
    Console.WriteLine("[instrumentor] Mode: instrument-all-user-code (skip framework/generated only)");
else
    Console.WriteLine($"[instrumentor] Mode: namespace allowlist ({allowedNamespaces.Count} entries)");

foreach (var ns in allowedNamespaces)
    Console.WriteLine($"[instrumentor]   namespace: {ns}");

// ── Framework/system prefixes to always skip ───────────────────────────────
var frameworkPrefixes = new[]
{
    "System.", "Microsoft.", "SharpFuzz.", "Mono.", "Internal.",
    "Newtonsoft.", "Swashbuckle.", "NSwag.", "FluentValidation.",
    "Serilog.", "MediatR.", "AutoMapper.", "Dapper.",
    "Npgsql.", "MySqlConnector.", "StackExchange.",
    "Polly.", "Grpc.", "Google.Protobuf.",
};

int instrumentedCount = 0;
int skippedFramework = 0;
int skippedGenerated = 0;
int skippedInfra = 0;
int skippedNoMatch = 0;

bool ShouldInstrument(string fullName)
{
    // ── Always skip compiler-generated types ──
    if (fullName.Contains("<PrivateImplementationDetails>") ||
        fullName.Contains("<Module>") ||
        fullName.Contains("<<") ||
        fullName.Contains("c__DisplayClass") ||
        fullName.Contains("d__") ||
        fullName.Contains(".g."))
    {
        skippedGenerated++;
        return false;
    }

    // ── Always skip migrations, entry points, coverage infrastructure ──
    // Entry-point types AND their nested/generated closures (e.g. Program+<>c) are
    // excluded: their coverage probes can fire during type-initialization, BEFORE the
    // coverage middleware binds the SHM bitmap, causing System.AccessViolationException
    // at startup. This is why blanket --instrument-all-user-code previously crashed
    // Bitwarden in Bit.Api.Program+<>c..cctor.
    //
    // FIX (2026-07-22): top-level-statements projects (e.g. eShopOnWeb PublicApi) place
    // the generated Program class in the GLOBAL namespace, so fullName is just "Program"
    // (no dot-prefix). The previous check .EndsWith(".Program") missed this case and
    // caused the PublicApi container to crash with AccessViolationException on startup.
    if (fullName.Contains("Migration") ||
        fullName.Contains("DesignTimeDbContext") ||
        fullName.Contains("CoverageExtensions") ||
        fullName == "Program" ||               // global-namespace entry point (top-level statements)
        fullName.EndsWith(".Program") ||
        fullName.EndsWith(".Startup") ||
        fullName.StartsWith("Program+") || fullName.StartsWith("Program/") ||  // global-ns nested types
        fullName.Contains(".Program+") || fullName.Contains(".Program/") ||
        fullName.Contains(".Startup+") || fullName.Contains(".Startup/") ||
        fullName.Contains("+<>c") ||           // compiler lambda-cache classes (static-init)
        fullName.Contains("/<>c") ||           // slash-variant (global-ns closures: Program/<>c)
        fullName.Contains("<Main>") ||         // top-level-statements entry point
        fullName.Contains("__GeneratedModule"))
    {
        skippedInfra++;
        return false;
    }

    // ── Namespace allowlist check (takes precedence over framework prefix filter) ──
    // This allows explicitly requested namespaces like Microsoft.eShopWeb.* to be
    // instrumented even though they share the "Microsoft." prefix with framework code.
    if (!instrumentAll && allowedNamespaces.Count > 0)
    {
        foreach (var ns in allowedNamespaces)
        {
            if (fullName.Contains(ns))
            {
                instrumentedCount++;
                Console.WriteLine($"[instrumentor]   + {fullName}");
                return true;
            }
        }
        // Not in allowlist — check if it's framework code (for accurate counters)
        foreach (var prefix in frameworkPrefixes)
        {
            if (fullName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                skippedFramework++;
                return false;
            }
        }
        skippedNoMatch++;
        return false;
    }

    // ── instrument-all-user-code: skip framework, accept everything else ──
    foreach (var prefix in frameworkPrefixes)
    {
        if (fullName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            skippedFramework++;
            return false;
        }
    }
    instrumentedCount++;
    Console.WriteLine($"[instrumentor]   + {fullName}");
    return true;
}

// ── Run instrumentation ────────────────────────────────────────────────────
try
{
    SharpFuzz.Fuzzer.Instrument(dllPath, ShouldInstrument, SharpFuzz.Options.Value);
    Console.WriteLine($"[instrumentor] Done: instrumented={instrumentedCount} " +
                      $"skipped_framework={skippedFramework} skipped_generated={skippedGenerated} " +
                      $"skipped_infra={skippedInfra} skipped_no_match={skippedNoMatch}");
}
catch (SharpFuzz.InstrumentationException ex) when (ex.Message.Contains("already instrumented"))
{
    Console.WriteLine($"[instrumentor] Already instrumented, skipping: {dllPath}");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[instrumentor] FAILED: {ex.Message}");
    Environment.Exit(1);
}
