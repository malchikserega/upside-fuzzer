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
    [InlineData("MyApp.Foo+<Bar>d__2")]
    [InlineData("MyApp.Startup.g.SomeGenerated")]
    public void Decide_AlwaysSkipsGeneratedTypes(string fullName)
    {
        var decision = InstrumentationFilter.Decide(fullName, instrumentAll: true, allowedNamespaces: Array.Empty<string>(), frameworkPrefixes: FrameworkPrefixes);
        Assert.Equal(InstrumentDecision.SkipGenerated, decision);
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
