// Shared best-effort name -> TypeConstraints resolver used by ConstraintWalker's
// base-class merge, FluentValidationWalker's `AbstractValidator<T>` target lookup,
// and RouteAuthWalker's parameter-type matching. Syntax-only, so this is name-based,
// not symbol-based: exact full-name match first, else unique short-name match,
// preferring same-namespace when ambiguous. Documented, not silently wrong.

namespace UpsideFuzz.Analyzer;

public static class TypeResolver
{
    public static string StripGeneric(string typeText)
    {
        var idx = typeText.IndexOf('<');
        return (idx >= 0 ? typeText[..idx] : typeText).TrimEnd('?').Trim();
    }

    public static TypeConstraints? Resolve(Dictionary<string, TypeConstraints> all, string name, string preferNamespace)
    {
        name = StripGeneric(name);
        if (all.TryGetValue(name, out var exact)) return exact;
        TypeConstraints? sameNs = null;
        var candidates = new List<TypeConstraints>();
        foreach (var tc in all.Values)
        {
            if (tc.Name != name) continue;
            candidates.Add(tc);
            if (tc.Namespace == preferNamespace) sameNs = tc;
        }
        return sameNs ?? (candidates.Count == 1 ? candidates[0] : candidates.FirstOrDefault());
    }
}
