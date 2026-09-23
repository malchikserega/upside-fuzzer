// Walks FluentValidation `RuleFor(x => x.Prop).Chain1().Chain2()...` statements via real
// syntax nodes (invocation/member-access/lambda), not a single-line regex slice — handles
// multi-line chains, arbitrary chain length, and `.When(...)` conditionals correctly.

using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace UpsideFuzz.Analyzer;

public static class FluentValidationWalker
{
    public static void Apply(SourceIndex idx, Dictionary<string, TypeConstraints> types)
    {
        foreach (var validator in idx.Validators)
        {
            var target = TypeResolver.Resolve(types, validator.ValidatesTypeName, RoslynUtil.GetNamespace(validator.Decl));
            if (target is null) continue; // validated type not found in this source tree — skip, don't guess
            target.ValidatorClass = validator.ValidatorFullName;

            foreach (var stmt in validator.Decl.DescendantNodes().OfType<ExpressionStatementSyntax>())
            {
                if (stmt.Expression is not InvocationExpressionSyntax outer) continue;
                var chainSteps = new List<InvocationExpressionSyntax>();
                var ruleFor = WalkChain(outer, chainSteps);
                if (ruleFor is null) continue;

                var propName = ExtractLambdaPropertyName(ruleFor);
                if (propName is null) continue;

                if (!target.Properties.TryGetValue(propName, out var pc))
                {
                    pc = new PropertyConstraint { ClrType = "unknown" };
                    target.Properties[propName] = pc;
                }
                ApplyChain(pc, chainSteps);
            }
        }
    }

    // Recursively unwinds an invocation chain down to its `RuleFor(...)` root, collecting
    // each `.Method(args)` step (outermost-last input order corrected to RuleFor-first).
    private static InvocationExpressionSyntax? WalkChain(InvocationExpressionSyntax invocation, List<InvocationExpressionSyntax> stepsOut)
    {
        if (invocation.Expression is IdentifierNameSyntax { Identifier.Text: "RuleFor" })
            return invocation;

        if (invocation.Expression is MemberAccessExpressionSyntax mae)
        {
            if (mae.Name.Identifier.Text == "RuleFor")
                return invocation; // `this.RuleFor(...)`

            if (mae.Expression is InvocationExpressionSyntax inner)
            {
                var root = WalkChain(inner, stepsOut);
                if (root is not null) stepsOut.Add(invocation);
                return root;
            }
        }
        return null; // not a RuleFor-rooted chain
    }

    private static string? ExtractLambdaPropertyName(InvocationExpressionSyntax ruleForCall)
    {
        var arg = ruleForCall.ArgumentList.Arguments.FirstOrDefault()?.Expression;
        if (arg is not SimpleLambdaExpressionSyntax lambda) return null;
        // Body is normally `x.Prop`; for `x.Nested.Prop` we take the final segment
        // (documented simplification — nested-property FluentValidation rules are rare
        // and the surrounding DTO's own attribute-based constraints still apply to Nested).
        if (lambda.Body is MemberAccessExpressionSyntax mae) return mae.Name.Identifier.Text;
        return null;
    }

    private static void ApplyChain(PropertyConstraint pc, List<InvocationExpressionSyntax> steps)
    {
        foreach (var step in steps)
        {
            if (step.Expression is not MemberAccessExpressionSyntax mae) continue;
            var method = mae.Name.Identifier.Text;
            var (pos, named) = RoslynUtil.SplitArgs(step.ArgumentList);

            switch (method)
            {
                case "MaximumLength":
                    if (pos.Count > 0 && RoslynUtil.EvalInt(pos[0]) is int maxLen) pc.MaxLength = maxLen;
                    pc.Source.Add("FluentValidation:MaximumLength");
                    break;
                case "MinimumLength":
                    if (pos.Count > 0 && RoslynUtil.EvalInt(pos[0]) is int minLen) pc.MinLength = minLen;
                    pc.Source.Add("FluentValidation:MinimumLength");
                    break;
                case "Length":
                    if (pos.Count >= 2)
                    {
                        pc.MinLength = RoslynUtil.EvalInt(pos[0]);
                        pc.MaxLength = RoslynUtil.EvalInt(pos[1]);
                    }
                    pc.Source.Add("FluentValidation:Length");
                    break;
                case "InclusiveBetween":
                    if (pos.Count >= 2)
                    {
                        pc.Minimum = RoslynUtil.EvalDouble(pos[0]);
                        pc.Maximum = RoslynUtil.EvalDouble(pos[1]);
                    }
                    pc.Source.Add("FluentValidation:InclusiveBetween");
                    break;
                case "GreaterThanOrEqualTo":
                    if (pos.Count > 0) pc.Minimum = RoslynUtil.EvalDouble(pos[0]);
                    pc.Source.Add("FluentValidation:GreaterThanOrEqualTo");
                    break;
                case "LessThanOrEqualTo":
                    if (pos.Count > 0) pc.Maximum = RoslynUtil.EvalDouble(pos[0]);
                    pc.Source.Add("FluentValidation:LessThanOrEqualTo");
                    break;
                case "Matches":
                    if (pos.Count > 0 && pos[0] is LiteralExpressionSyntax lit && lit.Token.Value is string pattern)
                        pc.Pattern = pattern;
                    pc.Source.Add("FluentValidation:Matches");
                    break;
                case "NotEmpty":
                    pc.Required = true;
                    pc.Source.Add("FluentValidation:NotEmpty");
                    break;
                case "EmailAddress":
                    pc.Email = true;
                    pc.Source.Add("FluentValidation:EmailAddress");
                    break;
                case "When":
                case "Unless":
                    pc.FluentConditional = true;
                    pc.Source.Add($"FluentValidation:{method}(conditional)");
                    break;
            }
        }
    }
}
