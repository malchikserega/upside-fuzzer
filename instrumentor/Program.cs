Console.WriteLine("Instrumenting JsonParserLogic with coverage tracking...");
var dllPath = args.Length > 0 ? args[0] : "/app/bin/Release/net8.0/FuzzApi.dll";

bool ShouldInstrument(string fullName)
{
    // Instrument only our business logic classes in FuzzApi.Business namespace
    if (fullName.Contains("FuzzApi.Business") && fullName.Contains("Logic"))
    {
        Console.WriteLine($"  ✓ Instrumenting: {fullName}");
        return true;
    }
    return false;
}

try
{
    SharpFuzz.Fuzzer.Instrument(dllPath, ShouldInstrument, false);
    Console.WriteLine("✅ Instrumentation complete!");
}
catch (SharpFuzz.InstrumentationException ex) when (ex.Message.Contains("already instrumented"))
{
    Console.WriteLine("⚠️  Already instrumented - skipping");
}
