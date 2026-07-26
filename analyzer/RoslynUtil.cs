// Shared syntax-tree helpers used by every walker. Deliberately syntax-only —
// no semantic model / symbol resolution (see docs/ARCHITECTURE_REVIEW.md #10 scoping note):
// this trades cross-assembly type resolution for zero MSBuild/NuGet-restore fragility.

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace UpsideFuzz.Analyzer;

public static class RoslynUtil
{
    // Full dotted name: Namespace.Outer.Inner (walks enclosing namespace + nested type declarations).
    public static string GetFullName(SyntaxNode node)
    {
        var parts = new List<string>();
        for (var n = node; n is not null; n = n.Parent)
        {
            switch (n)
            {
                case BaseTypeDeclarationSyntax t:
                    parts.Insert(0, t.Identifier.Text);
                    break;
                case NamespaceDeclarationSyntax ns:
                    parts.Insert(0, ns.Name.ToString());
                    break;
                case FileScopedNamespaceDeclarationSyntax fns:
                    parts.Insert(0, fns.Name.ToString());
                    break;
            }
        }
        return string.Join(".", parts);
    }

    public static string GetNamespace(SyntaxNode node)
    {
        for (var n = node; n is not null; n = n.Parent)
        {
            if (n is NamespaceDeclarationSyntax ns) return ns.Name.ToString();
            if (n is FileScopedNamespaceDeclarationSyntax fns) return fns.Name.ToString();
        }
        return "";
    }

    public static IEnumerable<AttributeSyntax> AllAttributes(SyntaxList<AttributeListSyntax> lists)
        => lists.SelectMany(l => l.Attributes);

    public static string AttributeShortName(AttributeSyntax attr)
    {
        var name = attr.Name.ToString();
        var lastDot = name.LastIndexOf('.');
        if (lastDot >= 0) name = name[(lastDot + 1)..];
        if (name.EndsWith("Attribute")) name = name[..^"Attribute".Length];
        return name;
    }

    // Best-effort literal evaluation: numeric/string/bool/char literals, unary-minus on
    // numeric literals. Anything else (enum member access, nameof, const refs) falls back
    // to the raw source text so callers can still record *something* honestly.
    public static object? EvalLiteral(ExpressionSyntax expr)
    {
        switch (expr)
        {
            case LiteralExpressionSyntax lit:
                return lit.Token.Value;
            case PrefixUnaryExpressionSyntax { OperatorToken.RawKind: (int)SyntaxKind.MinusToken } neg
                when neg.Operand is LiteralExpressionSyntax negLit && negLit.Token.Value is not null:
                {
                    var v = negLit.Token.Value;
                    return v switch
                    {
                        int i => -i,
                        double d => -d,
                        long l => -l,
                        decimal m => -m,
                        _ => null
                    };
                }
            default:
                return null;
        }
    }

    public static string RawText(ExpressionSyntax expr) => expr.ToString().Trim('"');

    public static double? EvalDouble(ExpressionSyntax expr)
    {
        var v = EvalLiteral(expr);
        return v switch
        {
            int i => i,
            double d => d,
            long l => l,
            decimal m => (double)m,
            float f => f,
            _ => null
        };
    }

    public static int? EvalInt(ExpressionSyntax expr)
    {
        var v = EvalLiteral(expr);
        return v switch
        {
            int i => i,
            long l => (int)l,
            double d => (int)d,
            _ => null
        };
    }

    // Returns positional args by index and named args by name for an attribute/invocation-style
    // argument list, uniformly (used for both [Attribute(...)] and RuleFor(...).Chain(...) calls).
    public static (List<ExpressionSyntax> Positional, Dictionary<string, ExpressionSyntax> Named) SplitArgs(
        IEnumerable<AttributeArgumentSyntax>? args)
    {
        var pos = new List<ExpressionSyntax>();
        var named = new Dictionary<string, ExpressionSyntax>();
        if (args is null) return (pos, named);
        foreach (var a in args)
        {
            if (a.NameEquals is not null) named[a.NameEquals.Name.Identifier.Text] = a.Expression;
            else if (a.NameColon is not null) named[a.NameColon.Name.Identifier.Text] = a.Expression;
            else pos.Add(a.Expression);
        }
        return (pos, named);
    }

    public static (List<ExpressionSyntax> Positional, Dictionary<string, ExpressionSyntax> Named) SplitArgs(
        ArgumentListSyntax? argList)
    {
        var pos = new List<ExpressionSyntax>();
        var named = new Dictionary<string, ExpressionSyntax>();
        if (argList is null) return (pos, named);
        foreach (var a in argList.Arguments)
        {
            if (a.NameColon is not null) named[a.NameColon.Name.Identifier.Text] = a.Expression;
            else pos.Add(a.Expression);
        }
        return (pos, named);
    }

    // Matches whole path *segments* only (e.g. ".../Tests/Foo.cs", ".../MyApp.Tests/Bar.cs",
    // ".../UnitTests/Bar.cs") -- a naive substring check like `Contains("/test")` also
    // matches "/testdata/...", "/testing-utils/...", etc., silently excluding legitimate
    // non-test directories that merely start with "test" (caught via this project's own
    // testdata/planted-bug-api fixture parsing to 0 files before this fix -- "testdata"
    // doesn't *end* with "test", so it correctly stays excluded from exclusion).
    //
    // FIX (found writing this session's analyzer.Tests suite): the plural suffix check
    // only covered the dotted form (".tests", e.g. "MyApp.Tests") and the bare exact
    // match ("tests"), never a plain "ends with tests" (e.g. "UnitTests") -- exactly the
    // shape this function's own doc comment above claims to handle. Added
    // EndsWith("tests") alongside the existing EndsWith("test"), accepting the same
    // small false-positive tradeoff already accepted for the singular form (an unusual
    // business directory literally named "Contests" would also match) -- "UnitTests" not
    // being excluded is a far more likely, higher-impact miss than that edge case.
    public static bool IsTestPath(string path)
    {
        var lower = path.Replace('\\', '/').ToLowerInvariant();
        if (lower.Contains("/bin/") || lower.Contains("/obj/")) return true;
        foreach (var segment in lower.Split('/'))
        {
            if (segment == "test" || segment == "tests" ||
                segment.EndsWith(".tests") || segment.EndsWith("test") || segment.EndsWith("tests"))
                return true;
        }
        return false;
    }
}
