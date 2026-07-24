// Extracts endpoint route + [Authorize]/[AllowAnonymous] metadata in BOTH styles found
// in real .NET APIs: classic MVC controllers ([Route]/[Http*] on class+method) and
// minimal-API endpoint registration (`app.MapPost("route", [Authorize] (Dto req) => {...})`).
// eShopOnWeb's PublicApi uses the latter exclusively (Ardalis.ApiEndpoints-style
// `IEndpoint<...>` classes with an `AddRoute(IEndpointRouteBuilder)` method) — a pattern
// ARCHITECTURE_REVIEW.md explicitly calls out as under-detected by naming-convention
// heuristics, so both styles are first-class here, not an afterthought.

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace UpsideFuzz.Analyzer;

public static class RouteAuthWalker
{
    private static readonly Dictionary<string, string> MapVerbs = new(StringComparer.Ordinal)
    {
        ["MapGet"] = "GET", ["MapPost"] = "POST", ["MapPut"] = "PUT",
        ["MapDelete"] = "DELETE", ["MapPatch"] = "PATCH",
    };

    private static readonly Dictionary<string, string> HttpAttrVerbs = new(StringComparer.Ordinal)
    {
        ["HttpGet"] = "GET", ["HttpPost"] = "POST", ["HttpPut"] = "PUT",
        ["HttpDelete"] = "DELETE", ["HttpPatch"] = "PATCH",
    };

    public static List<EndpointInfo> Build(SourceIndex idx)
    {
        var result = new List<EndpointInfo>();
        result.AddRange(BuildControllerEndpoints(idx));
        result.AddRange(BuildMinimalApiEndpoints(idx));
        return result;
    }

    private static IEnumerable<EndpointInfo> BuildControllerEndpoints(SourceIndex idx)
    {
        foreach (var ctrl in idx.ControllerCandidates)
        {
            var classAttrs = RoslynUtil.AllAttributes(ctrl.AttributeLists).ToList();
            var classRoute = AttrFirstStringArg(classAttrs, "Route");
            var classAuth = GetAuth(classAttrs);

            foreach (var method in ctrl.Members.OfType<MethodDeclarationSyntax>())
            {
                var methodAttrs = RoslynUtil.AllAttributes(method.AttributeLists).ToList();
                string? verb = null;
                string? methodRoute = null;
                foreach (var attr in methodAttrs)
                {
                    var shortName = RoslynUtil.AttributeShortName(attr);
                    if (HttpAttrVerbs.TryGetValue(shortName, out var v))
                    {
                        verb = v;
                        var (pos, _) = RoslynUtil.SplitArgs(attr.ArgumentList?.Arguments);
                        if (pos.Count > 0 && pos[0] is LiteralExpressionSyntax { Token.Value: string s }) methodRoute = s;
                    }
                }
                if (verb is null) continue; // not an action method

                var methodAuth = GetAuth(methodAttrs);
                var combined = CombineRoute(classRoute, methodRoute, method.Identifier.Text, ctrl.Identifier.Text);

                var paramTypes = new Dictionary<string, string>();
                foreach (var p in method.ParameterList.Parameters)
                    paramTypes[p.Identifier.Text] = TypeResolver.StripGeneric(p.Type?.ToString() ?? "object");

                yield return new EndpointInfo
                {
                    Controller = RoslynUtil.GetFullName(ctrl),
                    Action = method.Identifier.Text,
                    HttpMethod = verb,
                    RouteTemplate = combined,
                    Authorize = methodAuth.Authorize ?? classAuth.Authorize ?? false,
                    AllowAnonymous = methodAuth.AllowAnonymous || classAuth.AllowAnonymous,
                    AuthorizeRoles = methodAuth.Roles.Count > 0 ? methodAuth.Roles : classAuth.Roles,
                    ParameterTypes = paramTypes,
                    Style = "controller",
                };
            }
        }
    }

    private static IEnumerable<EndpointInfo> BuildMinimalApiEndpoints(SourceIndex idx)
    {
        foreach (var cls in idx.AllClasses)
        {
            foreach (var ep in MapCallsIn(cls, RoslynUtil.GetFullName(cls), idx))
                yield return ep;
        }

        // Top-level-statement Program.cs (`var app = ...; app.MapGet(...)`, no enclosing
        // class) -- the modern ASP.NET default template style, entirely missed by the
        // idx.AllClasses walk above since there is no ClassDeclarationSyntax to find.
        foreach (var root in idx.FileRoots)
        {
            foreach (var globalStmt in root.Members.OfType<GlobalStatementSyntax>())
            {
                foreach (var ep in MapCallsIn(globalStmt, "Program", idx))
                    yield return ep;
            }
        }
    }

    private static IEnumerable<EndpointInfo> MapCallsIn(SyntaxNode scope, string controllerLabel, SourceIndex idx)
    {
        foreach (var invocation in scope.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax { Name: IdentifierNameSyntax nameId }) continue;
            if (!MapVerbs.TryGetValue(nameId.Identifier.Text, out var verb)) continue;

            var args = invocation.ArgumentList.Arguments;
            if (args.Count < 2) continue;
            if (args[0].Expression is not LiteralExpressionSyntax { Token.Value: string route }) continue;

            var handlerExpr = args[1].Expression;
            var (authorize, allowAnon, roles, paramTypes) = InspectHandler(handlerExpr, idx);

            yield return new EndpointInfo
            {
                Controller = controllerLabel,
                Action = null,
                HttpMethod = verb,
                RouteTemplate = route.TrimStart('/'),
                Authorize = authorize,
                AllowAnonymous = allowAnon,
                AuthorizeRoles = roles,
                ParameterTypes = paramTypes,
                Style = "minimal-api",
            };
        }
    }

    // Handler is usually an inline lambda carrying its own [Authorize]/[AllowAnonymous]
    // attribute list (as ASP.NET Core allows attributes directly on a delegate parameter,
    // per the eShopOnWeb pattern this was written against). Method-group handlers
    // (`app.MapGet("x", SomeClass.Handle)`) are left unresolved — documented limitation,
    // OAS-derived constraints still apply as a fallback for those endpoints.
    private static (bool authorize, bool allowAnon, List<string> roles, Dictionary<string, string> paramTypes) InspectHandler(
        ExpressionSyntax handler, SourceIndex idx)
    {
        var paramTypes = new Dictionary<string, string>();
        SyntaxList<AttributeListSyntax> attrLists = default;
        ParameterListSyntax? parameters = null;

        switch (handler)
        {
            case ParenthesizedLambdaExpressionSyntax pl:
                attrLists = pl.AttributeLists;
                parameters = pl.ParameterList;
                break;
            case SimpleLambdaExpressionSyntax sl:
                attrLists = sl.AttributeLists;
                paramTypes[sl.Parameter.Identifier.Text] = sl.Parameter.Type?.ToString() ?? "object";
                break;
        }

        if (parameters is not null)
        {
            foreach (var p in parameters.Parameters)
                paramTypes[p.Identifier.Text] = TypeResolver.StripGeneric(p.Type?.ToString() ?? "object");
        }

        var attrs = RoslynUtil.AllAttributes(attrLists).ToList();
        var auth = GetAuth(attrs);
        return (auth.Authorize ?? false, auth.AllowAnonymous, auth.Roles, paramTypes);
    }

    private static string? AttrFirstStringArg(List<AttributeSyntax> attrs, string shortName)
    {
        foreach (var attr in attrs)
        {
            if (RoslynUtil.AttributeShortName(attr) != shortName) continue;
            var (pos, _) = RoslynUtil.SplitArgs(attr.ArgumentList?.Arguments);
            if (pos.Count > 0 && pos[0] is LiteralExpressionSyntax { Token.Value: string s }) return s;
        }
        return null;
    }

    private static (bool? Authorize, bool AllowAnonymous, List<string> Roles) GetAuth(List<AttributeSyntax> attrs)
    {
        bool? authorize = null;
        bool allowAnon = false;
        var roles = new List<string>();
        foreach (var attr in attrs)
        {
            var shortName = RoslynUtil.AttributeShortName(attr);
            if (shortName == "Authorize")
            {
                authorize = true;
                var (_, named) = RoslynUtil.SplitArgs(attr.ArgumentList?.Arguments);
                if (named.TryGetValue("Roles", out var rolesExpr))
                {
                    var text = RoslynUtil.RawText(rolesExpr);
                    roles.AddRange(text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                }
            }
            else if (shortName == "AllowAnonymous")
            {
                allowAnon = true;
            }
        }
        return (authorize, allowAnon, roles);
    }

    private static string CombineRoute(string? classRoute, string? methodRoute, string actionName, string className)
    {
        var controllerToken = className.EndsWith("Controller") ? className[..^"Controller".Length] : className;
        string Norm(string? s) => (s ?? "")
            .Replace("[controller]", controllerToken, StringComparison.OrdinalIgnoreCase)
            .Replace("[action]", actionName, StringComparison.OrdinalIgnoreCase)
            .Trim('/');
        var c = Norm(classRoute);
        var m = Norm(methodRoute);
        if (c.Length == 0) return m;
        if (m.Length == 0) return c;
        return $"{c}/{m}";
    }
}
