namespace instrumentor.Tests;

public class InstrumentationFilterTests
{
    private static readonly string[] FrameworkPrefixes =
    {
        "System.", "Microsoft.", "SharpFuzz.", "Mono.", "Internal.",
        "Newtonsoft.", "Swashbuckle.", "NSwag.", "FluentValidation.",
        "Serilog.", "MediatR.", "AutoMapper.", "Dapper.",
        "Npgsql.", "MySqlConnector.", "StackExchange.",
        "Polly.", "Grpc.", "Google.Protobuf.",
    };

    [Theory]
    [InlineData("MyApp.<PrivateImplementationDetails>")]
    [InlineData("MyApp.<Module>")]
    [InlineData("MyApp.Foo+<>c__DisplayClass1_0")]
    [InlineData("MyApp.Startup.g.SomeGenerated")]
    public void Decide_AlwaysSkipsGeneratedTypes(string fullName)
    {
        var decision = InstrumentationFilter.Decide(fullName, instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes);
        Assert.Equal(InstrumentDecision.SkipGenerated, decision);
    }

    // `d__` (async/iterator state-machine) types are deliberately NOT in the
    // always-skip-generated bucket above (removed 2026-07-26) -- see the long comment
    // on InstrumentationFilter.Decide. A business-logic type's own `async Task` state
    // machine must be instrumented exactly like the rest of that type, since that's
    // where almost all of a real `async` method's actual IL (branches, comparisons,
    // string literals) lives -- the "outer" method is just a thin builder stub.
    [Theory]
    [InlineData("MyApp.Business.OrderService+<PlaceOrderAsync>d__3")]
    [InlineData("MyApp.Business.OrderService/<PlaceOrderAsync>d__3")] // Cecil's slash-variant nesting notation
    public void Decide_AsyncStateMachineOfBusinessType_IsInstrumented(string fullName)
    {
        var decision = InstrumentationFilter.Decide(fullName, instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes);
        Assert.Equal(InstrumentDecision.Instrument, decision);
    }

    // A framework type's own state machine (e.g. something inside EF Core) must still
    // be correctly attributed to SkipFramework via the ordinary prefix check -- the
    // `d__` segment in the middle of the name must not defeat that.
    [Fact]
    public void Decide_AsyncStateMachineOfFrameworkType_IsSkippedAsFramework()
    {
        var decision = InstrumentationFilter.Decide(
            "Microsoft.EntityFrameworkCore.DbContext+<SaveChangesAsync>d__142",
            instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes);
        Assert.Equal(InstrumentDecision.SkipFramework, decision);
    }

    [Theory]
    [InlineData("Program")] // global-namespace top-level-statements entry point
    [InlineData("MyApp.Program")]
    [InlineData("MyApp.Startup")]
    [InlineData("Program+<>c")] // global-ns closure
    [InlineData("MyApp.Program+<>c")]
    [InlineData("MyApp.Migrations.Initial")]
    [InlineData("MyApp.DesignTimeDbContextFactory")]
    [InlineData("MyApp.CoverageExtensions")]
    public void Decide_AlwaysSkipsInfraTypes(string fullName)
    {
        var decision = InstrumentationFilter.Decide(fullName, instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes);
        Assert.Equal(InstrumentDecision.SkipInfra, decision);
    }

    // Regression guard for the original Bitwarden AccessViolationException class this
    // exclusion bucket exists to prevent (Bit.Api.Program+<>c..cctor, a static-init-timing
    // issue): a top-level-statements Program's OWN async state machine must still be
    // caught by the Program/Startup prefix checks even though `d__` alone no longer
    // triggers SkipGenerated -- proving removing the blanket `d__` check did not reopen
    // that crash class.
    [Theory]
    [InlineData("Program+<Main>d__0")]
    [InlineData("Program/<Main>d__0")]
    [InlineData("MyApp.Startup+<ConfigureAsync>d__5")]
    public void Decide_AsyncStateMachineOfEntryPointType_StillSkippedAsInfra(string fullName)
    {
        var decision = InstrumentationFilter.Decide(fullName, instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes);
        Assert.Equal(InstrumentDecision.SkipInfra, decision);
    }

    [Fact]
    public void Decide_InstrumentAllMode_SkipsFrameworkPrefixesAcceptsEverythingElse()
    {
        Assert.Equal(
            InstrumentDecision.SkipFramework,
            InstrumentationFilter.Decide("Microsoft.AspNetCore.Foo", instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes));
        Assert.Equal(
            InstrumentDecision.Instrument,
            InstrumentationFilter.Decide("MyApp.Business.OrderService", instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes));
    }

    [Fact]
    public void Decide_AllowlistMode_InstrumentsMatchAndSkipsNonMatchAsNoMatch()
    {
        var allowed = new[] { "MyApp.Business" };
        Assert.Equal(
            InstrumentDecision.Instrument,
            InstrumentationFilter.Decide("MyApp.Business.OrderService", instrumentAll: false, allowedNamespaces: allowed, frameworkPrefixes: FrameworkPrefixes));
        // Not in the allowlist and not framework code either -> SkipNoMatch, not SkipFramework.
        Assert.Equal(
            InstrumentDecision.SkipNoMatch,
            InstrumentationFilter.Decide("MyApp.OtherStuff.Thing", instrumentAll: false, allowedNamespaces: allowed, frameworkPrefixes: FrameworkPrefixes));
    }

    [Fact]
    public void Decide_AllowlistMode_FrameworkPrefixCollisionStillReportedAsSkipFramework()
    {
        // A namespace NOT in the allowlist but that happens to also be framework code
        // must report SkipFramework (for accurate counters), not SkipNoMatch.
        var allowed = new[] { "Microsoft.eShopWeb" }; // explicitly allowlisted despite the shared prefix
        Assert.Equal(
            InstrumentDecision.Instrument,
            InstrumentationFilter.Decide("Microsoft.eShopWeb.Catalog.CatalogItem", instrumentAll: false, allowedNamespaces: allowed, frameworkPrefixes: FrameworkPrefixes));
        Assert.Equal(
            InstrumentDecision.SkipFramework,
            InstrumentationFilter.Decide("Microsoft.EntityFrameworkCore.DbContext", instrumentAll: false, allowedNamespaces: allowed, frameworkPrefixes: FrameworkPrefixes));
    }

    [Fact]
    public void Decide_AllowlistTakesPrecedenceOverFrameworkPrefixCollision()
    {
        // Namespace-allowlist match wins even when the namespace shares a framework
        // prefix -- this is the whole reason the allowlist check runs BEFORE the
        // framework-prefix filter (documented in the original ShouldInstrument).
        var allowed = new[] { "Microsoft.eShopWeb.PublicApi" };
        Assert.Equal(
            InstrumentDecision.Instrument,
            InstrumentationFilter.Decide("Microsoft.eShopWeb.PublicApi.CatalogItemEndpoint", instrumentAll: false, allowedNamespaces: allowed, frameworkPrefixes: FrameworkPrefixes));
    }
}
