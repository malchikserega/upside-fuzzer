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
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

// ── Parse CLI ──────────────────────────────────────────────────────────────
if (args.Length == 0)
{
    Console.Error.WriteLine("Usage: instrumentor <path-to-dll> [--namespaces Ns1 Ns2 ...] [--instrument-all-user-code] [--config path] [--cmplog]");
    Environment.Exit(1);
}

string dllPath = args[0];
bool instrumentAll = false;
bool cmpLogEnabled = false;
string? configPath = null;
var cliNamespaces = new List<string>();

for (int i = 1; i < args.Length; i++)
{
    if (args[i] == "--instrument-all-user-code")
    {
        instrumentAll = true;
    }
    else if (args[i] == "--cmplog")
    {
        cmpLogEnabled = true;
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

    // Top-20 #17: persist the real instrumented-type count next to the DLL so the
    // runtime coverage hook can size the SHM bitmap from actual app surface instead
    // of a fixed 256KB guess (see fuzz-prep-multi.py::ResolveShmSize). SharpFuzz
    // doesn't expose a public branch/edge count, so instrumented TYPE count is used
    // as a proxy. Appended (not overwritten) because a multi-DLL app runs this
    // instrumentor once per assembly -- each RUN line contributes one line here.
    try
    {
        var metaPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(dllPath)) ?? ".", ".upsidefuzz_instrumented.jsonl");
        var line = "{\"assembly\":\"" + Path.GetFileName(dllPath).Replace("\"", "") +
                   "\",\"instrumented_types\":" + instrumentedCount + "}";
        File.AppendAllText(metaPath, line + "\n");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[instrumentor] WARNING: failed to write instrumentation meta file: {ex.Message}");
    }
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

// ── CmpLog/RedQueen via IL comparison instrumentation (Top-20+ #21) ─────────
// Independent of SharpFuzz's own coverage rewrite above (a separate Cecil pass,
// re-reading the DLL SharpFuzz just wrote). Hook-mode only: the recorder calls
// this pass injects target UpsideFuzz.Coverage.CmpLogProbe by assembly name, which
// only resolves at runtime when that assembly is actually loaded (DOTNET_STARTUP_HOOKS
// / ASPNETCORE_HOSTINGSTARTUPASSEMBLIES). --inject-mode source builds never load it,
// so fuzz-prep-multi.py only ever passes --cmplog for hook-mode builds.
//
// Best-effort and strictly non-fatal: a failure here must never fail the build or
// degrade the coverage instrumentation SharpFuzz already applied successfully above.
if (cmpLogEnabled)
{
    try
    {
        CmpLogInstrumentor.Run(dllPath, ShouldInstrument);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[instrumentor] WARNING: CmpLog instrumentation skipped ({ex.GetType().Name}): {ex.Message}");
    }
}

// ── CmpLog/RedQueen via IL comparison instrumentation ────────────────────────
//
// Rewrites two families of comparison sites so their operand(s) are recorded into
// UpsideFuzz.Coverage.CmpLogProbe immediately before the original comparison
// executes, leaving the target's own behavior completely unchanged:
//
//   1. String comparisons: calls to String.Equals/op_Equality (both the static
//      2-arg and instance 1-arg overloads)/StartsWith/EndsWith/Contains, restricted
//      to the plain (string[, string]) overloads -- overloads taking a
//      StringComparison/CultureInfo aren't touched, since this recorder only knows
//      how to safely pop/replay exactly two string-typed stack values.
//   2. Integer literal-vs-compare sites: an ldc.i4/ldc.i8 immediately followed
//      (skipping over any Nop) by ceq/beq/bne.un(.s) -- the single-instruction
//      lookback AFL++'s own CmpLog targets most heavily (immediate-vs-variable
//      compares), and the only numeric shape this pass attempts. General
//      arithmetic-relational compares (clt/cgt/ble/bge) and switch-statement case
//      values (both the sequential-Equals and hash-table-jump forms the C#
//      compiler emits) are NOT covered -- an acknowledged v1 scope limit, not a
//      silent gap: they'd need real stack-depth data-flow analysis to intercept
//      safely, which this pass deliberately does not attempt.
//
// Both transforms are pure "record a copy, then replay the original stack exactly
// as it was" -- they never remove, reorder, or alter any existing instruction, so
// existing branch targets and exception-handler regions stay valid without needing
// offset recalculation (Cecil resolves branches by Instruction object, not raw
// offset, until AssemblyDefinition.Write() runs).
public static class CmpLogInstrumentor
{
    public static void Run(string dllPath, Func<string, bool> shouldInstrument)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(dllPath)) ?? ".";
        var resolver = new DefaultAssemblyResolver();
        resolver.AddSearchDirectory(dir);
        var readParams = new ReaderParameters
        {
            ReadWrite = true,
            ReadSymbols = false,
            AssemblyResolver = resolver,
        };

        using var asm = AssemblyDefinition.ReadAssembly(dllPath, readParams);
        var module = asm.MainModule;

        // Reference-by-name only, exactly like the coverage hook's own probes resolve
        // SharpFuzz.Common.Trace at runtime (see fuzz-prep-multi.py's CoverageRuntime):
        // UpsideFuzz.Coverage.dll is not present at instrument time (built separately,
        // loaded into the process later), so this must never attempt .Resolve().
        var probeAsmRef = new AssemblyNameReference("UpsideFuzz.Coverage", new Version(1, 0, 0, 0));
        module.AssemblyReferences.Add(probeAsmRef);
        var probeTypeRef = new TypeReference("UpsideFuzz.Coverage", "CmpLogProbe", module, probeAsmRef, false);

        var voidRef = module.TypeSystem.Void;
        var stringRef = module.TypeSystem.String;
        var int64Ref = module.TypeSystem.Int64;

        var recordStringRef = new MethodReference("RecordString", voidRef, probeTypeRef) { HasThis = false };
        recordStringRef.Parameters.Add(new ParameterDefinition(stringRef));
        recordStringRef.Parameters.Add(new ParameterDefinition(stringRef));

        var recordIntRef = new MethodReference("RecordInt", voidRef, probeTypeRef) { HasThis = false };
        recordIntRef.Parameters.Add(new ParameterDefinition(int64Ref));

        int stringSites = 0, intSites = 0;

        foreach (var type in module.Types.SelectMany(FlattenNestedTypes))
        {
            if (!shouldInstrument(type.FullName)) continue;
            foreach (var method in type.Methods)
            {
                if (!method.HasBody) continue;
                try
                {
                    var body = method.Body;
                    body.SimplifyMacros();
                    var il = body.GetILProcessor();
                    stringSites += InstrumentStringComparisons(body, il, recordStringRef);
                    intSites += InstrumentIntComparisons(body, il, recordIntRef);
                    body.OptimizeMacros();
                }
                catch
                {
                    // Best-effort per method: one method's IL shape we didn't
                    // anticipate must not sacrifice CmpLog coverage for the rest.
                }
            }
        }

        if (stringSites > 0 || intSites > 0)
        {
            asm.Write();
            Console.WriteLine($"[instrumentor] CmpLog: {stringSites} string-comparison site(s), " +
                               $"{intSites} int-comparison site(s) in {Path.GetFileName(dllPath)}");
        }
        else
        {
            Console.WriteLine($"[instrumentor] CmpLog: no eligible comparison sites found in {Path.GetFileName(dllPath)}");
        }
    }

    static IEnumerable<TypeDefinition> FlattenNestedTypes(TypeDefinition t)
    {
        yield return t;
        foreach (var nested in t.NestedTypes)
            foreach (var n in FlattenNestedTypes(nested))
                yield return n;
    }

    static bool IsExceptionBoundary(MethodBody body, Instruction instr)
    {
        if (!body.HasExceptionHandlers) return false;
        foreach (var eh in body.ExceptionHandlers)
        {
            if (ReferenceEquals(eh.TryStart, instr) || ReferenceEquals(eh.TryEnd, instr) ||
                ReferenceEquals(eh.HandlerStart, instr) || ReferenceEquals(eh.HandlerEnd, instr) ||
                ReferenceEquals(eh.FilterStart, instr))
                return true;
        }
        return false;
    }

    // ── String comparisons ───────────────────────────────────────────────────
    static bool IsTargetStringComparisonMethod(MethodReference mref)
    {
        var name = mref.Name;
        if (name != "Equals" && name != "op_Equality" && name != "StartsWith" &&
            name != "EndsWith" && name != "Contains") return false;
        // HasThis/Parameters come straight off the reference's own signature blob --
        // no .Resolve() needed, so this works even when the declaring assembly
        // (System.Private.CoreLib) isn't resolvable in this reader's context.
        int expectedParams = mref.HasThis ? 1 : 2;
        if (mref.Parameters.Count != expectedParams) return false;
        foreach (var p in mref.Parameters)
            if (p.ParameterType.FullName != "System.String") return false;
        return true;
    }

    static int InstrumentStringComparisons(MethodBody body, ILProcessor il, MethodReference recordStringRef)
    {
        var targets = new List<Instruction>();
        foreach (var instr in body.Instructions)
        {
            if (instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt) continue;
            if (instr.Operand is not MethodReference mref) continue;
            if (mref.DeclaringType?.FullName != "System.String") continue;
            if (!IsTargetStringComparisonMethod(mref)) continue;
            if (IsExceptionBoundary(body, instr)) continue;
            targets.Add(instr);
        }

        foreach (var callInstr in targets)
        {
            // Both shapes (static 2-arg call, instance 1-arg call) push exactly two
            // string values consumed by the call, operandB on top of stack. Pop both
            // into temp locals, replay them for our recorder call, then replay them
            // again immediately before the untouched original call -- net effect on
            // the stack and on program behavior is zero.
            var tmpB = new VariableDefinition(body.Method.Module.TypeSystem.String);
            var tmpA = new VariableDefinition(body.Method.Module.TypeSystem.String);
            body.Variables.Add(tmpB);
            body.Variables.Add(tmpA);

            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Stloc, tmpB));
            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Stloc, tmpA));
            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Ldloc, tmpA));
            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Ldloc, tmpB));
            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Call, recordStringRef));
            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Ldloc, tmpA));
            il.InsertBefore(callInstr, Instruction.Create(OpCodes.Ldloc, tmpB));
        }
        return targets.Count;
    }

    // ── Integer literal-vs-compare sites ─────────────────────────────────────
    static bool IsInt32Const(Instruction instr) =>
        instr.OpCode == OpCodes.Ldc_I4 || instr.OpCode == OpCodes.Ldc_I4_S ||
        instr.OpCode == OpCodes.Ldc_I4_M1 ||
        (instr.OpCode.Code >= Code.Ldc_I4_0 && instr.OpCode.Code <= Code.Ldc_I4_8);

    static bool IsCompareOpcode(OpCode op) =>
        op == OpCodes.Ceq || op == OpCodes.Beq || op == OpCodes.Beq_S ||
        op == OpCodes.Bne_Un || op == OpCodes.Bne_Un_S;

    static int InstrumentIntComparisons(MethodBody body, ILProcessor il, MethodReference recordIntRef)
    {
        var instrs = body.Instructions;
        var sites = new List<(Instruction ldc, bool isI8)>();

        for (int i = 0; i < instrs.Count; i++)
        {
            var cur = instrs[i];
            bool isI4 = IsInt32Const(cur);
            bool isI8 = cur.OpCode == OpCodes.Ldc_I8;
            if (!isI4 && !isI8) continue;

            int j = i + 1;
            while (j < instrs.Count && instrs[j].OpCode == OpCodes.Nop) j++;
            if (j >= instrs.Count || !IsCompareOpcode(instrs[j].OpCode)) continue;
            if (IsExceptionBoundary(body, cur)) continue;

            sites.Add((cur, isI8));
        }

        foreach (var (ldc, isI8) in sites)
        {
            // dup the constant, widen the DUPLICATE to int64 for the recorder call,
            // leaving the original (int32 or int64) value on the stack untouched for
            // the compare instruction that follows.
            Instruction cursor = ldc;
            var dup = Instruction.Create(OpCodes.Dup);
            il.InsertAfter(cursor, dup);
            cursor = dup;
            if (!isI8)
            {
                var conv = Instruction.Create(OpCodes.Conv_I8);
                il.InsertAfter(cursor, conv);
                cursor = conv;
            }
            il.InsertAfter(cursor, Instruction.Create(OpCodes.Call, recordIntRef));
        }
        return sites.Count;
    }
}
