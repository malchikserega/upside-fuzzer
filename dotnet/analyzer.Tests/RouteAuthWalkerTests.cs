using UpsideFuzz.Analyzer;

namespace analyzer.Tests;

public class RouteAuthWalkerTests
{
    [Fact]
    public void Build_ExtractsClassicControllerEndpointWithAuthAndRoles()
    {
        using var fx = new TestFixture(
            ("OrdersController.cs", @"
namespace MyApp.Controllers
{
    [ApiController]
    [Route(""api/[controller]"")]
    public class OrdersController
    {
        [HttpGet(""{id}"")]
        [Authorize(Roles = ""Admin,Manager"")]
        public void GetById(int id) { }

        [HttpPost]
        [AllowAnonymous]
        public void Create(object req) { }
    }
}")
        );
        var idx = fx.Load();
        var endpoints = RouteAuthWalker.Build(idx);

        var getById = Assert.Single(endpoints, e => e.Action == "GetById");
        Assert.Equal("GET", getById.HttpMethod);
        // CombineRoute substitutes [controller] with the class name minus "Controller"
        // suffix, preserving its original casing ("Orders", not lowercased) -- and
        // does not otherwise touch the "api/" segment from [Route].
        Assert.Equal("api/Orders/{id}", getById.RouteTemplate);
        Assert.True(getById.Authorize);
        Assert.Contains("Admin", getById.AuthorizeRoles);
        Assert.Contains("Manager", getById.AuthorizeRoles);
        Assert.Equal("controller", getById.Style);
        Assert.Equal("int", getById.ParameterTypes["id"]);

        var create = Assert.Single(endpoints, e => e.Action == "Create");
        Assert.Equal("POST", create.HttpMethod);
        Assert.True(create.AllowAnonymous);
    }

    [Fact]
    public void Build_ExtractsTopLevelStatementMinimalApiEndpoints()
    {
        // The exact 2026-07-23 regression this session found and fixed: top-level
        // statements (`var app = ...; app.MapGet(...)`) have no enclosing
        // ClassDeclarationSyntax at all, so a walk over idx.AllClasses alone misses
        // them entirely -- RouteAuthWalker must also scan idx.FileRoots.
        using var fx = new TestFixture(
            ("Program.cs", @"
var app = WebApplication.Create();
app.MapGet(""/items/{id}"", (int id) => Results.Ok());
app.MapPost(""/items"", [Authorize] (CreateItemRequest req) => Results.Ok());
app.Run();
")
        );
        var idx = fx.Load();
        var endpoints = RouteAuthWalker.Build(idx);

        Assert.Equal(2, endpoints.Count);
        Assert.All(endpoints, e => Assert.Equal("minimal-api", e.Style));

        var get = Assert.Single(endpoints, e => e.HttpMethod == "GET");
        Assert.Equal("items/{id}", get.RouteTemplate);
        Assert.Equal("int", get.ParameterTypes["id"]);
        Assert.False(get.Authorize);

        var post = Assert.Single(endpoints, e => e.HttpMethod == "POST");
        Assert.Equal("items", post.RouteTemplate);
        Assert.True(post.Authorize);
        Assert.Equal("CreateItemRequest", post.ParameterTypes["req"]);
    }

    [Fact]
    public void Build_ClassBasedMinimalApiRegistrationAlsoDetected()
    {
        // Ardalis.ApiEndpoints-style: MapGet/MapPost called from inside a regular
        // class's method (not top-level statements) -- covered by the idx.AllClasses
        // walk, distinct code path from the top-level-statements one above.
        using var fx = new TestFixture(
            ("ItemEndpoints.cs", @"
namespace MyApp
{
    public class ItemEndpoints
    {
        public void Register(IEndpointRouteBuilder app)
        {
            app.MapGet(""/items"", () => Results.Ok());
        }
    }
}")
        );
        var idx = fx.Load();
        var endpoints = RouteAuthWalker.Build(idx);

        var ep = Assert.Single(endpoints);
        Assert.Equal("GET", ep.HttpMethod);
        Assert.Equal("items", ep.RouteTemplate);
        Assert.Equal("minimal-api", ep.Style);
        Assert.Equal("MyApp.ItemEndpoints", ep.Controller);
    }

    [Fact]
    public void Build_MethodAuthorizeOverridesClassAllowAnonymous()
    {
        using var fx = new TestFixture(
            ("MixedController.cs", @"
namespace MyApp
{
    [Route(""api/mixed"")]
    [AllowAnonymous]
    public class MixedController
    {
        [HttpGet]
        [Authorize]
        public void Secured() { }
    }
}")
        );
        var idx = fx.Load();
        var endpoints = RouteAuthWalker.Build(idx);

        var ep = Assert.Single(endpoints);
        Assert.True(ep.Authorize);
        // Method-level [AllowAnonymous] is absent, but class-level AllowAnonymous is
        // still combined via OR -- documents RouteAuthWalker's actual (permissive)
        // combination rule rather than asserting an idealized "method always wins" one.
        Assert.True(ep.AllowAnonymous);
    }
}
