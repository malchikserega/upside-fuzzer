using UpsideFuzz.Analyzer;

namespace analyzer.Tests;

public class SourceIndexTests
{
    [Fact]
    public void Load_ExcludesTestPathFiles()
    {
        using var fx = new TestFixture(
            ("src/Business/OrderService.cs", "namespace MyApp.Business { public class OrderService { } }"),
            ("UnitTests/OrderServiceTests.cs", "namespace MyApp.Tests { public class OrderServiceTests { } }")
        );
        var idx = fx.Load();

        Assert.True(idx.ClassesByFullName.ContainsKey("MyApp.Business.OrderService"));
        Assert.False(idx.ClassesByFullName.ContainsKey("MyApp.Tests.OrderServiceTests"));
        Assert.Equal(1, idx.Diagnostics.FilesParsed);
    }

    [Fact]
    public void Load_IndexesRecordsAsPseudoClasses()
    {
        using var fx = new TestFixture(
            ("Dtos.cs", "namespace MyApp.Dtos { public record CreateItemRequest(string Name, decimal Price); }")
        );
        var idx = fx.Load();

        Assert.Contains("MyApp.Dtos.CreateItemRequest", idx.AllFullNames());
        var decls = idx.DeclarationsFor("MyApp.Dtos.CreateItemRequest");
        Assert.Single(decls);
    }

    [Fact]
    public void Load_MergesPartialClassDeclarationsAcrossFiles()
    {
        using var fx = new TestFixture(
            ("Order.Core.cs", "namespace MyApp { public partial class Order { public int Id { get; set; } } }"),
            ("Order.Extra.cs", "namespace MyApp { public partial class Order { public string Name { get; set; } } }")
        );
        var idx = fx.Load();

        var decls = idx.DeclarationsFor("MyApp.Order");
        Assert.Equal(2, decls.Count); // both partial declarations retained, merged at ConstraintWalker time
    }

    [Theory]
    [InlineData("[ApiController]\npublic class OrderController { }", true)] // ApiController attribute
    [InlineData("public class OrderController { }", true)] // Controller-suffix naming
    [InlineData(
        "public class ItemEndpoint { [HttpPost(\"api/items\")] public void Handle() { } }",
        true)] // Ardalis.ApiEndpoints-style: no suffix, no [ApiController]/[Route], just an [Http*] method attribute
    [InlineData("public class OrderService { public void DoWork() { } }", false)]
    public void Load_ControllerCandidateDetectionCoversAllThreeSignals(string classSource, bool expectCandidate)
    {
        using var fx = new TestFixture(("Src.cs", $"using System.Web.Http;\nnamespace MyApp {{ {classSource} }}"));
        var idx = fx.Load();

        var isCandidate = idx.ControllerCandidates.Any();
        Assert.Equal(expectCandidate, isCandidate);
    }

    [Fact]
    public void Load_RegistersFluentValidationValidators()
    {
        using var fx = new TestFixture(
            ("OrderValidator.cs", @"
namespace MyApp
{
    public class Order { public string Name { get; set; } }
    public class OrderValidator : AbstractValidator<Order>
    {
        public OrderValidator() { RuleFor(x => x.Name).NotEmpty(); }
    }
}")
        );
        var idx = fx.Load();

        var v = Assert.Single(idx.Validators);
        Assert.Equal("MyApp.OrderValidator", v.ValidatorFullName);
        Assert.Equal("Order", v.ValidatesTypeName);
    }

    [Fact]
    public void Load_RetainsFileRootsForTopLevelStatementScanning()
    {
        using var fx = new TestFixture(
            ("Program.cs", "var app = 1;\nSystem.Console.WriteLine(app);")
        );
        var idx = fx.Load();

        Assert.Single(idx.FileRoots);
        Assert.Empty(idx.AllClasses); // top-level statements have no ClassDeclarationSyntax
    }
}
