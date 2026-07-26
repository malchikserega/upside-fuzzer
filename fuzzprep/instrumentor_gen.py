"""Generates the SharpFuzz/Cecil instrumentor tool's own source copy (from
dotnet/instrumentor/Program.cs) plus the namespaces.json config it reads, and
-- for the default zero-edit hook mode -- the self-contained
UpsideFuzz.Coverage startup-hook assembly (DOTNET_STARTUP_HOOKS +
IHostingStartup), which needs no changes to the target's own source.
"""

import json
import shutil
from pathlib import Path

from .models import MultiAnalysisResult


def generate_unified_instrumentor(result: MultiAnalysisResult, output_path: Path):
    """Generate config-driven instrumentor using the generic Program.cs and a namespaces.json config."""

    instr_dir = output_path / "instrumentor_src"
    instr_dir.mkdir(parents=True, exist_ok=True)

    # Copy the generic instrumentor from the repository root
    repo_instrumentor = Path(__file__).parent.parent / "dotnet" / "instrumentor" / "Program.cs"
    if repo_instrumentor.exists():
        shutil.copy2(repo_instrumentor, instr_dir / "Program.cs")
        print(f"  Copied generic instrumentor from {repo_instrumentor}")
    else:
        # Fallback: write a minimal version inline (e.g. when running from a packaged install)
        print("  WARNING: instrumentor/Program.cs not found at expected path, writing inline fallback")
        (instr_dir / "Program.cs").write_text(_FALLBACK_INSTRUMENTOR_CS)

    # Generate namespaces.json config with discovered business-logic namespaces
    config_data = {
        "namespaces": sorted(set(result.all_namespaces)),
        "excludes": sorted(set(result.exclude_namespaces))
    }
    config_path = instr_dir / "namespaces.json"
    config_path.write_text(json.dumps(config_data, indent=2))
    print(f"  Generated namespaces.json with {len(result.all_namespaces)} allowed, {len(result.exclude_namespaces)} excluded namespace(s).")


# Inline fallback instrumentor for when the repo file isn't accessible.
_FALLBACK_INSTRUMENTOR_CS = r'''
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

if (args.Length == 0) { Console.Error.WriteLine("Usage: instrumentor <dll> [--namespaces Ns1 Ns2] [--instrument-all-user-code]"); return; }
string dllPath = args[0];
bool instrumentAll = args.Any(a => a == "--instrument-all-user-code");
var allowedNamespaces = new List<string>();
var excludedNamespaces = new List<string>();
for (int i = 1; i < args.Length; i++)
    if (args[i] == "--namespaces") for (int j = i+1; j < args.Length && !args[j].StartsWith("--"); j++) { allowedNamespaces.Add(args[j]); i = j; }
if (allowedNamespaces.Count == 0 && !instrumentAll) {
    var cfgPath = Path.Combine(Path.GetDirectoryName(dllPath) ?? ".", "namespaces.json");
    if (File.Exists(cfgPath)) {
        var doc = JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(File.ReadAllText(cfgPath));
        if (doc != null && doc.TryGetValue("namespaces", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var e in arr.EnumerateArray()) { var v = e.GetString(); if (!string.IsNullOrWhiteSpace(v)) allowedNamespaces.Add(v); }
        if (doc != null && doc.TryGetValue("excludes", out var extArr) && extArr.ValueKind == JsonValueKind.Array)
            foreach (var e in extArr.EnumerateArray()) { var v = e.GetString(); if (!string.IsNullOrWhiteSpace(v)) excludedNamespaces.Add(v); }
    }
}
if (allowedNamespaces.Count == 0 && !instrumentAll) { Console.Error.WriteLine("ERROR: no namespaces"); Environment.Exit(1); }
var skip = new[]{"System.","Microsoft.","SharpFuzz.","Mono.","Internal."};
// A plain substring check (fn.Contains(ns)) matches at any position, not just a
// namespace-segment boundary -- allowlisting "Bit.Core" would also silently pull in
// "Bit.CoreUtilities.Foo", which is a different namespace that merely starts with the
// same characters. Requiring an exact match or a match ending at a '.' boundary makes
// this a real namespace-prefix check. See instrumentor/Program.cs::MatchesNamespace,
// the primary (non-fallback) instrumentor this mirrors.
bool MatchesNamespace(string fn, string ns) => !string.IsNullOrEmpty(ns) && (fn == ns || fn.StartsWith(ns + ".", StringComparison.Ordinal));
bool Filter(string fn) {
    if (fn.Contains("<PrivateImplementationDetails>") || fn.Contains("c__DisplayClass") || fn.Contains("d__") || fn.Contains(".g.")) return false;
    foreach (var p in skip) if (fn.StartsWith(p)) return false;
    foreach (var ex in excludedNamespaces) if (MatchesNamespace(fn, ex)) return false;
    if (fn.Contains("Migration") || fn.Contains("CoverageExtensions") || fn.EndsWith(".Program") || fn.EndsWith(".Startup")) return false;
    if (instrumentAll) { Console.WriteLine($"  + {fn}"); return true; }
    foreach (var ns in allowedNamespaces) if (MatchesNamespace(fn, ns)) { Console.WriteLine($"  + {fn}"); return true; }
    return false;
}
try { SharpFuzz.Fuzzer.Instrument(dllPath, Filter, SharpFuzz.Options.Value); Console.WriteLine("Done"); }
catch (SharpFuzz.InstrumentationException ex) when (ex.Message.Contains("already instrumented")) { Console.WriteLine("Already instrumented"); }
catch (Exception ex) { Console.Error.WriteLine($"FAILED: {ex.Message}"); Environment.Exit(1); }
'''


# ============================================================================
# Zero-edit coverage hook assembly (DOTNET_STARTUP_HOOKS + ASP.NET hosting startup)
# ============================================================================

# Pure C# source (no Python substitutions) — kept as a raw string so its many
# braces don't need f-string escaping.
_COVERAGE_HOOK_CS = r'''// AUTO-GENERATED by fuzz-prep-multi.py — UpsideFuzz zero-edit coverage runtime.
//
// Loaded two ways, both requiring ZERO edits to the target application:
//   1. DOTNET_STARTUP_HOOKS -> StartupHook.Initialize() runs before Main. It maps
//      the shared coverage bitmap, links every SharpFuzz-instrumented assembly to it
//      (including assemblies loaded lazily/dynamically at request time, via an
//      AppDomain.AssemblyLoad handler), and registers an assembly resolver so this
//      DLL + SharpFuzz.Common.dll load from /coverage without being in the app dir.
//   2. ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=UpsideFuzz.Coverage -> CoverageHostingStartup
//      registers an IStartupFilter that inserts the coverage middleware, which serves
//      the /shm/* control endpoints and emits per-request X-Coverage-Delta headers.
#nullable disable
#pragma warning disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

[assembly: HostingStartup(typeof(UpsideFuzz.Coverage.CoverageHostingStartup))]

// StartupHook MUST be in the global namespace and named exactly "StartupHook".
internal class StartupHook
{
    public static void Initialize()
    {
        try { UpsideFuzz.Coverage.CoverageRuntime.Bootstrap(); } catch { }
    }
}

namespace UpsideFuzz.Coverage
{
    public static class CoverageRuntime
    {
        private const string SHM_PATH = "/coverage_shm/bitmap";
        private const int DEFAULT_SHM_SIZE = 262144;
        private const int MIN_SHM_SIZE = 65536;
        private const int MAX_SHM_SIZE = 8 * 1024 * 1024;
        // Top-20 #17: real instrumented-type count captured at build time by
        // instrumentor/Program.cs, used both to auto-size SHM_SIZE below (when the
        // env var isn't explicitly set) and reported via /shm/health for transparency.
        internal static readonly int InstrumentedTypeCount = ResolveInstrumentedTypeCount();
        internal static readonly int SHM_SIZE = ResolveShmSize();
        // Top-20+ #22: string/int literals harvested from the target's own IL at
        // instrument time by instrumentor/Program.cs::ConstantExtractor, read once here
        // (they're static -- extracted at build time, never change during a run) and
        // served over GET /shm/constants for the Go engine to fold into its mutation
        // pool. Absence (build predates this feature) resolves to empty arrays, not
        // an error -- see ResolveConstants.
        internal static readonly (string[] Strings, string[] Ints) ExtractedConstants = ResolveConstants();

        private static IntPtr globalShmAddr = IntPtr.Zero;
        private static bool isFileBacked = false;
        private static MemoryMappedFile mmf;
        private static MemoryMappedViewAccessor accessor;

        // AFL-style hit-count buckets + bucketed virgin map (see coverage.go / docs/ARCHITECTURE.md).
        private static readonly byte[] CountClass = BuildCountClass();
        private static byte[] seenBuckets;
        private static int totalClasses = 0;
        private static readonly object covLock = new object();

        private static readonly ConcurrentDictionary<string, byte> linkedAssemblies = new ConcurrentDictionary<string, byte>();
        private static int linkCount = 0;
        private static volatile bool booted = false;
        private static string hookDir = "/coverage";

        // Self-verifying, fail-closed instrumentation (Top-20 #4): track which
        // assemblies are "app" code (not framework/SharpFuzz itself) so /shm/health
        // can report whether instrumentation actually reached the target's own
        // code, not just that the SharpFuzz runtime loaded. Mirrors
        // instrumentor/Program.cs's `frameworkPrefixes` — kept in sync manually.
        private static readonly string[] frameworkPrefixes = {
            "System.", "Microsoft.", "SharpFuzz.", "Mono.", "Internal.",
            "Newtonsoft.", "Swashbuckle.", "NSwag.", "FluentValidation.",
            "Serilog.", "MediatR.", "AutoMapper.", "Dapper.",
            "Npgsql.", "MySqlConnector.", "StackExchange.",
            "Polly.", "Grpc.", "Google.Protobuf.",
        };
        // linked_app_assemblies is deliberately NOT tracked per-assembly: SharpFuzz's
        // Trace.SharedMem type lives only in SharpFuzz.Common.dll, never in the app's
        // own IL-rewritten assemblies, so "does this app assembly define the Trace
        // type" is always false and would be a false-negative fail-closed signal.
        // The only architecturally honest way to verify instrumentation reached app
        // code is to check whether the shared bitmap actually moves after real
        // traffic — done engine-side (void/go/coverage.go::checkCoverageHealth) via a
        // warm-up probe. This list is purely informational: which app assemblies the
        // runtime has observed loaded, for diagnostics when that probe fails.
        private static readonly ConcurrentDictionary<string, byte> seenAppAssemblies = new ConcurrentDictionary<string, byte>();

        private static bool IsAppAssembly(string name)
        {
            if (string.IsNullOrEmpty(name) || name == "UpsideFuzz.Coverage") return false;
            foreach (var prefix in frameworkPrefixes)
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }

        private static string JsonStringArray(System.Collections.Generic.IEnumerable<string> values)
        {
            var sb = new StringBuilder("[");
            bool first = true;
            foreach (var v in values)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(SanitizeHeader(v)).Append('"');
            }
            sb.Append(']');
            return sb.ToString();
        }

        // Called before Main via DOTNET_STARTUP_HOOKS.
        public static void Bootstrap()
        {
            if (booted) return;
            booted = true;
            try { hookDir = Path.GetDirectoryName(typeof(CoverageRuntime).Assembly.Location); } catch { }
            if (string.IsNullOrEmpty(hookDir)) hookDir = "/coverage";

            // Resolve UpsideFuzz.Coverage + SharpFuzz.Common from /coverage even though
            // they are NOT in the app's probing path — so the target dir stays untouched.
            AssemblyLoadContext.Default.Resolving += (ctx, name) =>
            {
                try
                {
                    var candidate = Path.Combine(hookDir, name.Name + ".dll");
                    if (File.Exists(candidate)) return ctx.LoadFromAssemblyPath(candidate);
                }
                catch { }
                return null;
            };

            InitializeShm();

            // Force-load + link the shared SharpFuzz coverage assembly immediately.
            foreach (var n in new[] { "SharpFuzz.Common", "SharpFuzz" })
            {
                try { LinkAssembly(Assembly.Load(n)); } catch { }
            }

            // Link everything already loaded, and everything loaded later. The
            // AssemblyLoad handler is the fix for lazily/dynamically loaded modules
            // (e.g. plugin-style module assemblies) whose coverage was previously lost.
            AppDomain.CurrentDomain.AssemblyLoad += (s, e) =>
            {
                try { LinkAssembly(e.LoadedAssembly); } catch { }
            };
            foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) LinkAssembly(a);
        }

        // ResolveInstrumentedTypeCount reads the JSONL meta file instrumentor/Program.cs
        // appends next to the app's DLLs (one line per instrumented assembly) and sums
        // instrumented_types across them. Returns 0 if the file is absent (e.g. a build
        // predating this feature, or the meta write failed) -- callers must treat 0 as
        // "unknown", not "zero types instrumented".
        private static int ResolveInstrumentedTypeCount()
        {
            try
            {
                var metaPath = Path.Combine(AppContext.BaseDirectory, ".upsidefuzz_instrumented.jsonl");
                if (!File.Exists(metaPath)) return 0;
                int total = 0;
                const string key = "\"instrumented_types\":";
                foreach (var line in File.ReadAllLines(metaPath))
                {
                    var idx = line.IndexOf(key, StringComparison.Ordinal);
                    if (idx < 0) continue;
                    int start = idx + key.Length;
                    int end = start;
                    while (end < line.Length && char.IsDigit(line[end])) end++;
                    if (end > start && int.TryParse(line.Substring(start, end - start), out var n))
                        total += n;
                }
                return total;
            }
            catch { return 0; }
        }

        // ResolveConstants reads .upsidefuzz_constants.jsonl (written next to the app's
        // DLLs by instrumentor/Program.cs::ConstantExtractor, one line per instrumented
        // assembly) and unions strings/ints across all lines, capped at the same
        // 512/256 bounds ConstantExtractor itself enforces per assembly -- a multi-DLL
        // app could otherwise exceed those per-assembly caps once merged. Absent file
        // (build predates this feature) resolves to empty arrays, never an error.
        private static (string[] Strings, string[] Ints) ResolveConstants()
        {
            const int maxStrings = 512, maxInts = 256;
            var strs = new List<string>();
            var strSeen = new HashSet<string>(StringComparer.Ordinal);
            var ints = new List<string>();
            var intSeen = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                var metaPath = Path.Combine(AppContext.BaseDirectory, ".upsidefuzz_constants.jsonl");
                if (!File.Exists(metaPath)) return (Array.Empty<string>(), Array.Empty<string>());
                foreach (var line in File.ReadAllLines(metaPath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        using var doc = JsonDocument.Parse(line);
                        var root = doc.RootElement;
                        if (strs.Count < maxStrings && root.TryGetProperty("strings", out var sArr) && sArr.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var el in sArr.EnumerateArray())
                            {
                                if (strs.Count >= maxStrings) break;
                                var s = el.GetString();
                                if (!string.IsNullOrEmpty(s) && strSeen.Add(s)) strs.Add(s);
                            }
                        }
                        if (ints.Count < maxInts && root.TryGetProperty("ints", out var iArr) && iArr.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var el in iArr.EnumerateArray())
                            {
                                if (ints.Count >= maxInts) break;
                                var s = el.GetString();
                                if (!string.IsNullOrEmpty(s) && intSeen.Add(s)) ints.Add(s);
                            }
                        }
                    }
                    catch { /* one malformed line must not lose the rest */ }
                }
            }
            catch { }
            return (strs.ToArray(), ints.ToArray());
        }

        // Serialized once (ExtractedConstants is read-only after startup) rather than
        // rebuilt per request. Same hand-rolled escaping CmpLogProbe.JsonEscape uses --
        // arbitrary source-code string literals can contain quotes/backslashes, so the
        // header-oriented SanitizeHeader/JsonStringArray helpers above (which drop rather
        // than escape those characters) aren't safe to reuse here.
        private static readonly string ConstantsJsonCached = BuildConstantsJson();

        private static string BuildConstantsJson()
        {
            var sb = new StringBuilder();
            sb.Append("{\"strings\":[");
            bool first = true;
            foreach (var s in ExtractedConstants.Strings)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(JsonEscapeConst(s)).Append('"');
            }
            sb.Append("],\"ints\":[");
            first = true;
            foreach (var n in ExtractedConstants.Ints)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(n).Append('"');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private static string JsonEscapeConst(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                if (c == '"' || c == '\\') { sb.Append('\\').Append(c); continue; }
                if (c == '\n') { sb.Append("\\n"); continue; }
                if (c == '\r') { sb.Append("\\r"); continue; }
                if (c < 32) continue;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static int ResolveShmSize()
        {
            try
            {
                var raw = Environment.GetEnvironmentVariable("SHM_SIZE");
                if (int.TryParse(raw, out var parsed))
                    return parsed < MIN_SHM_SIZE ? MIN_SHM_SIZE : parsed;
            }
            catch { }
            // Top-20 #17: size the bitmap from the real instrumented-type count instead
            // of a fixed 256KB guess, when the caller hasn't pinned SHM_SIZE explicitly.
            // SharpFuzz exposes no public branch/edge count, so instrumented TYPE count
            // is used as a proxy -- budget ~512 bitmap bytes per instrumented type
            // (generous enough to keep hash collisions rare for typical controller/
            // service-sized classes), rounded up to a power of two and clamped to
            // [MIN_SHM_SIZE, MAX_SHM_SIZE] so very small or very large apps stay sane.
            try
            {
                if (InstrumentedTypeCount > 0)
                {
                    long estimate = (long)InstrumentedTypeCount * 512;
                    int size = MIN_SHM_SIZE;
                    while (size < estimate && size < MAX_SHM_SIZE) size <<= 1;
                    return size;
                }
            }
            catch { }
            return DEFAULT_SHM_SIZE;
        }

        private static byte[] BuildCountClass()
        {
            var t = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte c = (byte)i;
                byte v;
                if (c == 0) v = 0;
                else if (c == 1) v = 1;
                else if (c == 2) v = 2;
                else if (c == 3) v = 4;
                else if (c <= 7) v = 8;
                else if (c <= 15) v = 16;
                else if (c <= 31) v = 32;
                else if (c <= 127) v = 64;
                else v = 128;
                t[i] = v;
            }
            return t;
        }

        private static void InitializeShm()
        {
            if (globalShmAddr != IntPtr.Zero) return;
            if (Directory.Exists(Path.GetDirectoryName(SHM_PATH)))
            {
                try
                {
                    var fs = new FileStream(SHM_PATH, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                    fs.SetLength(SHM_SIZE);
                    mmf = MemoryMappedFile.CreateFromFile(fs, null, SHM_SIZE, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, false);
                    accessor = mmf.CreateViewAccessor(0, SHM_SIZE);
                    unsafe
                    {
                        byte* ptr = null;
                        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
                        globalShmAddr = (IntPtr)ptr;
                    }
                    isFileBacked = true;
                }
                catch { globalShmAddr = Marshal.AllocHGlobal(SHM_SIZE); }
            }
            else
            {
                globalShmAddr = Marshal.AllocHGlobal(SHM_SIZE);
            }
            unsafe { byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }
            seenBuckets = new byte[SHM_SIZE];
            totalClasses = 0;
        }

        // Point a single assembly's SharpFuzz.Common.Trace.SharedMem at our bitmap.
        internal static void LinkAssembly(Assembly a)
        {
            if (a == null || globalShmAddr == IntPtr.Zero) return;
            try
            {
                string asmName = a.GetName().Name ?? a.FullName;
                bool isApp = IsAppAssembly(asmName);
                if (isApp) seenAppAssemblies.TryAdd(asmName, 1);

                string[] typeNames = { "SharpFuzz.Common.Trace", "SharpFuzz.Common.Instrumenter", "SharpFuzz.Trace", "SharpFuzz.Instrumenter" };
                bool matched = false;
                foreach (var tn in typeNames)
                {
                    Type t = a.GetType(tn, false);
                    if (t == null) continue;
                    string[] members = { "SharedMem", "SharedMemory", "sharedMemory", "_sharedMemory" };
                    foreach (var m in members)
                    {
                        var p = t.GetProperty(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                        if (p != null)
                        {
                            try { unsafe { p.SetValue(null, System.Reflection.Pointer.Box(globalShmAddr.ToPointer(), typeof(byte*))); } matched = true; } catch { }
                        }
                        var f = t.GetField(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                        if (f != null)
                        {
                            try { f.SetValue(null, globalShmAddr); matched = true; } catch { }
                        }
                    }
                }
                if (matched && linkedAssemblies.TryAdd(asmName, 1))
                    Interlocked.Increment(ref linkCount);
            }
            catch { }
        }

        // Single-pass novelty merge against the shared bucketed virgin map
        // (first-observer-wins) — see docs/ARCHITECTURE.md section 5.
        internal static int MergeAndCountNovel()
        {
            if (globalShmAddr == IntPtr.Zero || seenBuckets == null) return 0;
            int novel = 0;
            lock (covLock)
            {
                unsafe
                {
                    byte* b = (byte*)globalShmAddr;
                    int n = SHM_SIZE;
                    int i = 0;
                    for (; i + 8 <= n; i += 8)
                    {
                        if (*(ulong*)(b + i) == 0UL) continue;
                        for (int j = 0; j < 8; j++)
                        {
                            byte c = b[i + j];
                            if (c == 0) continue;
                            byte bucket = CountClass[c];
                            if ((seenBuckets[i + j] & bucket) == 0) { seenBuckets[i + j] |= bucket; novel++; }
                        }
                    }
                    for (; i < n; i++)
                    {
                        byte c = b[i];
                        if (c == 0) continue;
                        byte bucket = CountClass[c];
                        if ((seenBuckets[i] & bucket) == 0) { seenBuckets[i] |= bucket; novel++; }
                    }
                }
                totalClasses += novel;
            }
            return novel;
        }

        private static long RawHits()
        {
            if (globalShmAddr == IntPtr.Zero) return 0;
            long hits = 0;
            unsafe { byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) hits += b[i]; }
            return hits;
        }

        private static string SanitizeHeader(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(Math.Min(s.Length, 1024));
            foreach (var c in s)
            {
                if (sb.Length >= 1024) break;
                if (c == '\r' || c == '\n' || c == '\t') { sb.Append(' '); continue; }
                if (c >= 32 && c < 127) sb.Append(c);
            }
            return sb.ToString();
        }

        private static Task WriteJson(HttpContext ctx, string json)
        {
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            return ctx.Response.WriteAsync(json);
        }

        // Serves /shm/create, /shm/coverage, /shm/reset, /shm/health.
        public static Task HandleControlEndpoint(HttpContext context, string rawPath)
        {
            string path = rawPath.TrimEnd('/').ToLowerInvariant();
            if (path == "/shm/create")
            {
                InitializeShm();
                foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) LinkAssembly(a);
                return WriteJson(context, "{\"mode\":\"" + (isFileBacked ? "file-backed-mmap" : "heap") +
                    "\",\"size\":" + SHM_SIZE + ",\"status\":\"synced\",\"linked_assemblies\":" + linkCount + "}");
            }
            if (path == "/shm/coverage")
                return WriteJson(context, "{\"edges\":" + totalClasses + ",\"hits\":" + RawHits() + ",\"size\":" + SHM_SIZE + "}");
            if (path == "/shm/reset")
            {
                lock (covLock)
                {
                    if (globalShmAddr != IntPtr.Zero) unsafe { byte* b = (byte*)globalShmAddr; for (int i = 0; i < SHM_SIZE; i++) b[i] = 0; }
                    if (seenBuckets != null) Array.Clear(seenBuckets, 0, seenBuckets.Length);
                    totalClasses = 0;
                }
                return WriteJson(context, "{\"status\":\"reset\"}");
            }
            if (path == "/shm/health")
            {
                // Reports facts only, not a verdict: SharpFuzz's Trace type lives in
                // SharpFuzz.Common.dll, never in the app's own rewritten assemblies, so
                // per-assembly "linked" status can't be measured by type reflection here.
                // The fail-closed ok/degraded decision is made engine-side (Go), which can
                // send real warm-up traffic and check whether the bitmap actually moves —
                // see void/go/coverage.go::checkCoverageHealth. app_assemblies below is
                // purely diagnostic context for that decision.
                bool shmBound = globalShmAddr != IntPtr.Zero;
                var (cmplogStrs, cmplogInts) = CmpLogProbe.Counts();
                return WriteJson(context, "{\"linked_assemblies\":" + linkCount + ",\"total_classes\":" + totalClasses +
                    ",\"shm_bound\":" + (shmBound ? "true" : "false") +
                    ",\"mode\":\"" + (isFileBacked ? "file-backed-mmap" : "heap") + "\"" +
                    ",\"instrumented_types\":" + InstrumentedTypeCount +
                    ",\"cmplog_strings\":" + cmplogStrs + ",\"cmplog_ints\":" + cmplogInts +
                    ",\"app_assemblies\":" + JsonStringArray(seenAppAssemblies.Keys) + "}");
            }
            // Top-20+ #21: comparison operands harvested from the target's own IL by
            // instrumentor/Program.cs's CmpLogInstrumentor (--cmplog, hook mode only).
            // Absent (404, handled by the fallthrough below) on a target built without
            // --cmplog or in --inject-mode source -- the Go engine treats that as
            // "nothing available", not an error.
            if (path == "/shm/cmplog")
                return WriteJson(context, CmpLogProbe.ToJson());
            // Top-20+ #22: string/int literals harvested from the target's own IL at
            // instrument time (instrumentor/Program.cs::ConstantExtractor). Always 200
            // (possibly empty arrays) rather than 404-on-absence like /shm/cmplog, since
            // extraction is unconditional (no --cmplog-style build flag gates it) -- an
            // empty result here just means the build genuinely found nothing to harvest.
            if (path == "/shm/constants")
                return WriteJson(context, ConstantsJsonCached);
            context.Response.StatusCode = 404;
            return Task.CompletedTask;
        }

        // Per-request coverage attribution + production-mode exception capture.
        public static async Task RunWithCoverage(HttpContext context, RequestDelegate next)
        {
            bool isFuzzRequest = !string.IsNullOrEmpty(context.Request.Headers["X-Fuzz-Request-Id"]);
            string exType = null, exMsg = null;
            int coverageDelta = -1;
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                exType = ex.GetType().FullName;
                exMsg = ex.Message;
                if (isFuzzRequest && !context.Response.HasStarted)
                {
                    try
                    {
                        context.Response.Clear();
                        context.Response.StatusCode = 500;
                        coverageDelta = MergeAndCountNovel();
                        context.Response.Headers["X-Coverage-Delta"] = coverageDelta.ToString();
                        context.Response.Headers["X-Coverage-Edges"] = totalClasses.ToString();
                        context.Response.Headers["X-Exception-Type"] = SanitizeHeader(exType);
                        context.Response.Headers["X-Exception-Message"] = SanitizeHeader(exMsg);
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync("{\"error\":\"unhandled_exception\"}");
                    }
                    catch { }
                    return;
                }
                throw;
            }
            finally
            {
                if (coverageDelta < 0) coverageDelta = MergeAndCountNovel();
                try
                {
                    if (!context.Response.HasStarted)
                    {
                        context.Response.Headers["X-Coverage-Delta"] = coverageDelta.ToString();
                        context.Response.Headers["X-Coverage-Edges"] = totalClasses.ToString();
                        if (exType != null) context.Response.Headers["X-Exception-Type"] = SanitizeHeader(exType);
                        if (exMsg != null) context.Response.Headers["X-Exception-Message"] = SanitizeHeader(exMsg);
                    }
                }
                catch { }
            }
        }
    }

    // Top-20+ #21: runtime side of CmpLog/RedQueen via IL comparison instrumentation.
    // instrumentor/Program.cs's CmpLogInstrumentor pass (--cmplog, hook mode only)
    // rewrites the target's own IL so every String.Equals/op_Equality/StartsWith/
    // EndsWith/Contains call and every integer-literal-vs-compare (ceq/beq/bne.un)
    // site calls RecordString/RecordInt here with its operand(s) BEFORE the original
    // comparison executes -- the instrumented program's behavior is unchanged, this
    // is purely an observer. Bounded, deduped, thread-safe (concurrent requests hit
    // instrumented code from many threads); served over GET /shm/cmplog for the Go
    // engine to poll into its own mutation-candidate pool (void/go/cmplog.go).
    public static class CmpLogProbe
    {
        private const int MAX_STRINGS = 512;
        private const int MAX_INTS = 256;
        private const int MAX_STRING_LEN = 256;

        private static readonly ConcurrentQueue<string> stringQueue = new ConcurrentQueue<string>();
        private static readonly ConcurrentDictionary<string, byte> stringSeen = new ConcurrentDictionary<string, byte>();
        private static readonly ConcurrentQueue<long> intQueue = new ConcurrentQueue<long>();
        private static readonly ConcurrentDictionary<long, byte> intSeen = new ConcurrentDictionary<long, byte>();

        public static void RecordString(string a, string b)
        {
            RecordOne(a);
            RecordOne(b);
        }

        private static void RecordOne(string v)
        {
            if (string.IsNullOrEmpty(v) || v.Length > MAX_STRING_LEN) return;
            if (!stringSeen.TryAdd(v, 1)) return;
            stringQueue.Enqueue(v);
            while (stringQueue.Count > MAX_STRINGS && stringQueue.TryDequeue(out var old))
                stringSeen.TryRemove(old, out _);
        }

        public static void RecordInt(long v)
        {
            if (!intSeen.TryAdd(v, 1)) return;
            intQueue.Enqueue(v);
            while (intQueue.Count > MAX_INTS && intQueue.TryDequeue(out var old))
                intSeen.TryRemove(old, out _);
        }

        public static (int strings, int ints) Counts() => (stringQueue.Count, intQueue.Count);

        // ConcurrentQueue enumeration is a weakly-consistent snapshot -- safe to read
        // while RecordString/RecordInt run concurrently on other request threads;
        // worst case a poll misses a value added mid-enumeration, which the next
        // poll picks up (this is a best-effort dictionary source, not a correctness-
        // critical coverage signal).
        internal static string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{\"strings\":[");
            bool first = true;
            foreach (var s in stringQueue)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(JsonEscape(s)).Append('"');
            }
            sb.Append("],\"ints\":[");
            first = true;
            foreach (var n in intQueue)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(n).Append('"');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private static string JsonEscape(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                if (c == '"' || c == '\\') { sb.Append('\\').Append(c); continue; }
                if (c == '\n') { sb.Append("\\n"); continue; }
                if (c == '\r') { sb.Append("\\r"); continue; }
                if (c < 32) continue;
                sb.Append(c);
            }
            return sb.ToString();
        }
    }

    // ASP.NET hosting startup (loaded via ASPNETCORE_HOSTINGSTARTUPASSEMBLIES).
    public class CoverageHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddSingleton<IStartupFilter, CoverageStartupFilter>();
            });
        }
    }

    internal class CoverageStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                // Inserted at the very front so it always runs and can serve /shm/*.
                app.Use(async (context, mwNext) =>
                {
                    var path = context.Request.Path.Value ?? "";
                    if (path.StartsWith("/shm/", StringComparison.OrdinalIgnoreCase))
                    {
                        await CoverageRuntime.HandleControlEndpoint(context, path);
                        return;
                    }
                    await CoverageRuntime.RunWithCoverage(context, _ => mwNext());
                });
                next(app);
            };
        }
    }
}
'''


def generate_startup_hook_assembly(result: MultiAnalysisResult, output_path: Path):
    """Write the self-contained UpsideFuzz.Coverage hook assembly (zero-edit mode).

    Produces coverage_hook_src/{UpsideFuzz.Coverage.cs, UpsideFuzz.Coverage.csproj}.
    The Docker build (hook mode) compiles this and drops the DLL + SharpFuzz.Common.dll
    into /coverage in the runtime image, wired via DOTNET_STARTUP_HOOKS +
    ASPNETCORE_HOSTINGSTARTUPASSEMBLIES. The target application is never modified.
    """
    main_proj = next((p for p in result.projects if p.name == result.main_project), result.projects[0])
    tfm = main_proj.target_framework or "net8.0"
    sharpfuzz_version = "2.1.1"

    hook_dir = output_path / "coverage_hook_src"
    hook_dir.mkdir(parents=True, exist_ok=True)

    (hook_dir / "UpsideFuzz.Coverage.cs").write_text(_COVERAGE_HOOK_CS, encoding="utf-8")

    csproj = f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>{tfm}</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <AssemblyName>UpsideFuzz.Coverage</AssemblyName>
    <RootNamespace>UpsideFuzz.Coverage</RootNamespace>
    <IsPackable>false</IsPackable>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
  <ItemGroup>
    <!-- Pulls SharpFuzz.Common.dll into the build output so the instrumented
         app's probes resolve it at runtime (we reference it by reflection only). -->
    <PackageReference Include="SharpFuzz" Version="{sharpfuzz_version}" />
  </ItemGroup>
</Project>
"""
    (hook_dir / "UpsideFuzz.Coverage.csproj").write_text(csproj, encoding="utf-8")
    print(f"  Generated zero-edit coverage hook assembly in {hook_dir.name}/ (TFM {tfm})")

