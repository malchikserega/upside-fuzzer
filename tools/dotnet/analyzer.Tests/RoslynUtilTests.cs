using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using UpsideFuzz.Analyzer;

namespace analyzer.Tests;

public class RoslynUtilTests
{
    [Theory]
    // Must match: real test directories.
    [InlineData("/repo/Tests/Foo.cs", true)]
    [InlineData("/repo/MyApp.Tests/Bar.cs", true)]
    [InlineData("/repo/UnitTests/Bar.cs", true)] // the 2026-07-25 regression this suite found and fixed
    [InlineData("/repo/src/Api.Tests/Handler.cs", true)]
    [InlineData(@"C:\repo\Tests\Foo.cs", true)] // backslash path separators
    [InlineData("/repo/bin/Debug/Foo.cs", true)]
    [InlineData("/repo/obj/Debug/Foo.cs", true)]
    // Must NOT match: the exact 2026-07-23 regression this session found and fixed --
    // "testdata" merely STARTS WITH "test", it doesn't end with "test"/"tests".
    [InlineData("/repo/testdata/planted-bug-api/Program.cs", false)]
    [InlineData("/repo/testing-utils/Helper.cs", false)]
    [InlineData("/repo/src/Api/Program.cs", false)]
    public void IsTestPath_MatchesWholeSegmentsOnly(string path, bool expected)
    {
        Assert.Equal(expected, RoslynUtil.IsTestPath(path));
    }

    [Fact]
    public void GetFullName_WalksNestedNamespaceAndNestedClass()
    {
        var tree = CSharpSyntaxTree.ParseText(@"
namespace MyApp.Business
{
    public class Outer
    {
        public class Inner { }
    }
}");
        var root = tree.GetCompilationUnitRoot();
        var inner = root.DescendantNodes().OfType<ClassDeclarationSyntax>().Single(c => c.Identifier.Text == "Inner");
        Assert.Equal("MyApp.Business.Outer.Inner", RoslynUtil.GetFullName(inner));
    }

    [Fact]
    public void GetFullName_HandlesFileScopedNamespace()
    {
        var tree = CSharpSyntaxTree.ParseText("namespace MyApp.Business;\npublic class Order { }");
        var root = tree.GetCompilationUnitRoot();
        var cls = root.DescendantNodes().OfType<ClassDeclarationSyntax>().Single();
        Assert.Equal("MyApp.Business.Order", RoslynUtil.GetFullName(cls));
    }

    [Fact]
    public void GetNamespace_ReturnsEnclosingNamespaceOnly()
    {
        var tree = CSharpSyntaxTree.ParseText("namespace MyApp.Business { public class Order { } }");
        var root = tree.GetCompilationUnitRoot();
        var cls = root.DescendantNodes().OfType<ClassDeclarationSyntax>().Single();
        Assert.Equal("MyApp.Business", RoslynUtil.GetNamespace(cls));
    }

    [Fact]
    public void GetNamespace_ReturnsEmptyForGlobalNamespace()
    {
        var tree = CSharpSyntaxTree.ParseText("public class Order { }");
        var root = tree.GetCompilationUnitRoot();
        var cls = root.DescendantNodes().OfType<ClassDeclarationSyntax>().Single();
        Assert.Equal("", RoslynUtil.GetNamespace(cls));
    }

    private static AttributeArgumentSyntax[] ParseAttributeArgs(string attributeSource)
    {
        var tree = CSharpSyntaxTree.ParseText($"[{attributeSource}] class C {{ }}");
        var root = tree.GetCompilationUnitRoot();
        var attr = root.DescendantNodes().OfType<AttributeSyntax>().Single();
        return attr.ArgumentList!.Arguments.ToArray();
    }

    [Fact]
    public void EvalInt_ReadsPositiveAndNegativeIntegerLiterals()
    {
        var args = ParseAttributeArgs("Range(1, -5)");
        Assert.Equal(1, RoslynUtil.EvalInt(args[0].Expression));
        Assert.Equal(-5, RoslynUtil.EvalInt(args[1].Expression));
    }

    [Fact]
    public void EvalDouble_ReadsDecimalLiteral()
    {
        var args = ParseAttributeArgs("Range(0.01, 10000.5)");
        Assert.Equal(0.01, RoslynUtil.EvalDouble(args[0].Expression));
        Assert.Equal(10000.5, RoslynUtil.EvalDouble(args[1].Expression));
    }

    [Fact]
    public void EvalLiteral_FallsBackToNullForNonLiteralExpressions()
    {
        // nameof(...)/enum member access/const refs aren't literals -- must not throw,
        // must return null so callers can fall back to raw source text honestly.
        var args = ParseAttributeArgs("Range(SomeConst.Value, 5)");
        Assert.Null(RoslynUtil.EvalLiteral(args[0].Expression));
        Assert.NotNull(RoslynUtil.EvalLiteral(args[1].Expression));
    }

    [Fact]
    public void SplitArgs_AttributeArguments_SeparatesPositionalAndNamed()
    {
        var args = ParseAttributeArgs("StringLength(50, MinimumLength = 1)");
        var (positional, named) = RoslynUtil.SplitArgs(args.AsEnumerable());
        Assert.Single(positional);
        Assert.Equal("50", positional[0].ToString());
        Assert.True(named.ContainsKey("MinimumLength"));
        Assert.Equal("1", named["MinimumLength"].ToString());
    }

    [Fact]
    public void AttributeShortName_StripsNamespaceAndAttributeSuffix()
    {
        var tree = CSharpSyntaxTree.ParseText("[System.ComponentModel.DataAnnotations.RequiredAttribute] class C { }");
        var root = tree.GetCompilationUnitRoot();
        var attr = root.DescendantNodes().OfType<AttributeSyntax>().Single();
        Assert.Equal("Required", RoslynUtil.AttributeShortName(attr));
    }
}
