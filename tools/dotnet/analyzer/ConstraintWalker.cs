// Pass 2: per-type, per-property DataAnnotations constraint extraction.
//
// This directly replaces enhance-grammar.py::SourceExtractor's regex-based attribute
// parsing. The key fix vs. that implementation: constraints are keyed by
// (fully-qualified type name, property name), not a globally canonicalized property
// name — so `[StringLength(50)] Name` on one DTO no longer leaks onto every other
// `name`-shaped field in the app (docs/ARCHITECTURE_REVIEW.md subsystem-3 weakness #2).

using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace UpsideFuzz.Analyzer;

public static class ConstraintWalker
{
    // Well-known non-validation attributes we can say with confidence aren't constraints —
    // filtering these out of custom_attributes/unmodeled_validation keeps that signal
    // meaningful instead of drowning it in serialization/ORM/routing noise. Anything NOT
    // in this list is honestly unknown (could be a custom ValidationAttribute, could not
    // be) and gets surfaced rather than silently dropped either way.
    private static readonly HashSet<string> NonValidationAttributes = new(StringComparer.Ordinal)
    {
        "JsonPropertyName", "JsonIgnore", "JsonConverter", "JsonInclude", "JsonPropertyOrder",
        "Key", "Column", "Table", "NotMapped", "ForeignKey", "DatabaseGenerated", "InverseProperty",
        "DataMember", "XmlElement", "XmlAttribute", "XmlIgnore",
        "Display", "DisplayName", "DisplayFormat", "ScaffoldColumn", "UIHint",
        "Bind", "FromBody", "FromQuery", "FromRoute", "FromHeader", "FromForm", "FromServices",
        "Obsolete", "DefaultValue", "Description", "SwaggerSchema", "SwaggerIgnore",
        "Serializable", "NonSerialized", "CompilerGenerated", "DebuggerDisplay",
    };

    public static Dictionary<string, TypeConstraints> Build(SourceIndex idx, List<UnmodeledValidation> unmodeled)
    {
        var result = new Dictionary<string, TypeConstraints>();

        foreach (var fullName in idx.AllFullNames())
        {
            var decls = idx.DeclarationsFor(fullName);
            if (decls.Count == 0) continue;

            var tc = new TypeConstraints
            {
                Namespace = fullName.Contains('.') ? fullName[..fullName.LastIndexOf('.')] : "",
                Name = decls[0] is BaseTypeDeclarationSyntax btDecl ? btDecl.Identifier.Text : fullName,
                PartialMergeCount = decls.Count,
            };

            foreach (var decl in decls)
            {
                if (decl.BaseList is not null)
                {
                    foreach (var baseType in decl.BaseList.Types)
                    {
                        var baseName = StripGeneric(baseType.Type.ToString());
                        if (!tc.BaseTypes.Contains(baseName)) tc.BaseTypes.Add(baseName);
                    }
                }

                // Auto-properties: `[Attrs] public Type Name { get; set; }`
                foreach (var prop in decl.Members.OfType<PropertyDeclarationSyntax>())
                {
                    var name = prop.Identifier.Text;
                    var pc = GetOrAdd(tc, name, prop.Type.ToString());
                    ApplyAttributes(pc, RoslynUtil.AllAttributes(prop.AttributeLists), unmodeled, fullName, name);
                }

                // Positional record parameters: `record Foo([Attrs] string Name, ...)`
                if (decl is RecordDeclarationSyntax { ParameterList: not null } rec)
                {
                    foreach (var p in rec.ParameterList!.Parameters)
                    {
                        var name = p.Identifier.Text;
                        var pc = GetOrAdd(tc, name, p.Type?.ToString() ?? "object");
                        ApplyAttributes(pc, RoslynUtil.AllAttributes(p.AttributeLists), unmodeled, fullName, name);
                    }
                }

                // IValidatableObject detection (recorded, body not interpreted — honest limit).
                if (decl.BaseList?.Types.Any(t => StripGeneric(t.Type.ToString()) == "IValidatableObject") == true)
                {
                    tc.ImplementsIValidatableObject = true;
                    unmodeled.Add(new UnmodeledValidation
                    {
                        Type = fullName,
                        Kind = "IValidatableObject.Validate",
                        Note = "custom validation logic present; semantics not modeled by syntax-tree analysis"
                    });
                }
            }

            // Enum-typed properties: attach enum value tables from SourceIndex.
            foreach (var (propName, pc) in tc.Properties)
            {
                var enumInfo = ResolveEnum(idx, pc.ClrType);
                if (enumInfo is not null)
                {
                    pc.EnumValues = enumInfo.Names;
                    pc.EnumNumericValues = enumInfo.NumericValues;
                    pc.EnumNonLiteral = enumInfo.NonLiteral;
                    pc.Source.Add("EnumDeclaration");
                }
            }

            result[fullName] = tc;
        }

        // Base-class property inheritance (same-source-tree only; cross-assembly base
        // types are simply left unresolved — disclosed limitation, not silently wrong).
        foreach (var tc in result.Values)
        {
            MergeBaseProperties(tc, result, new HashSet<string> { Key(tc) });
        }

        return result;
    }

    private static string Key(TypeConstraints tc) => string.IsNullOrEmpty(tc.Namespace) ? tc.Name : $"{tc.Namespace}.{tc.Name}";

    private static void MergeBaseProperties(TypeConstraints tc, Dictionary<string, TypeConstraints> all, HashSet<string> visited)
    {
        foreach (var baseName in tc.BaseTypes)
        {
            var resolved = TypeResolver.Resolve(all, baseName, tc.Namespace);
            if (resolved is null || !visited.Add(Key(resolved))) continue; // unresolved or cycle
            MergeBaseProperties(resolved, all, visited); // ensure base's own base chain is merged first
            foreach (var (propName, basePc) in resolved.Properties)
            {
                if (!tc.Properties.ContainsKey(propName))
                {
                    tc.Properties[propName] = basePc;
                }
            }
        }
    }

    private static string StripGeneric(string typeText) => TypeResolver.StripGeneric(typeText);

    private static PropertyConstraint GetOrAdd(TypeConstraints tc, string name, string clrType)
    {
        if (!tc.Properties.TryGetValue(name, out var pc))
        {
            pc = new PropertyConstraint { ClrType = clrType };
            tc.Properties[name] = pc;
        }
        return pc;
    }

    private static EnumInfo? ResolveEnum(SourceIndex idx, string clrType)
    {
        var nullableStripped = clrType.TrimEnd('?');
        var shortName = StripGeneric(nullableStripped);
        var lastDot = shortName.LastIndexOf('.');
        if (lastDot >= 0) shortName = shortName[(lastDot + 1)..];
        if (idx.EnumsByFullName.TryGetValue(nullableStripped, out var byFull)) return byFull;
        if (idx.EnumsByShortName.TryGetValue(shortName, out var byShort)) return byShort;
        return null;
    }

    private static void ApplyAttributes(
        PropertyConstraint pc,
        IEnumerable<Microsoft.CodeAnalysis.CSharp.Syntax.AttributeSyntax> attrs,
        List<UnmodeledValidation> unmodeled,
        string typeFullName,
        string propName)
    {
        foreach (var attr in attrs)
        {
            var shortName = RoslynUtil.AttributeShortName(attr);
            var (pos, named) = RoslynUtil.SplitArgs(attr.ArgumentList?.Arguments);

            switch (shortName)
            {
                case "StringLength":
                    if (pos.Count > 0 && RoslynUtil.EvalInt(pos[0]) is int maxLen) pc.MaxLength = maxLen;
                    if (named.TryGetValue("MinimumLength", out var minExpr) && RoslynUtil.EvalInt(minExpr) is int minLen) pc.MinLength = minLen;
                    pc.Source.Add("DataAnnotations:StringLength");
                    break;
                case "MaxLength":
                    if (pos.Count > 0 && RoslynUtil.EvalInt(pos[0]) is int mx) pc.MaxLength = mx;
                    pc.Source.Add("DataAnnotations:MaxLength");
                    break;
                case "MinLength":
                    if (pos.Count > 0 && RoslynUtil.EvalInt(pos[0]) is int mn) pc.MinLength = mn;
                    pc.Source.Add("DataAnnotations:MinLength");
                    break;
                case "Range":
                    if (pos.Count >= 2)
                    {
                        pc.Minimum = RoslynUtil.EvalDouble(pos[0]);
                        pc.Maximum = RoslynUtil.EvalDouble(pos[1]);
                    }
                    pc.Source.Add("DataAnnotations:Range");
                    break;
                case "RegularExpression":
                    if (pos.Count > 0 && pos[0] is Microsoft.CodeAnalysis.CSharp.Syntax.LiteralExpressionSyntax lit && lit.Token.Value is string pattern)
                        pc.Pattern = pattern;
                    pc.Source.Add("DataAnnotations:RegularExpression");
                    break;
                case "Required":
                    pc.Required = true;
                    pc.Source.Add("DataAnnotations:Required");
                    break;
                case "EmailAddress":
                    pc.Email = true;
                    pc.Source.Add("DataAnnotations:EmailAddress");
                    break;
                case "Url":
                    pc.Url = true;
                    pc.Source.Add("DataAnnotations:Url");
                    break;
                default:
                    if (NonValidationAttributes.Contains(shortName)) break; // known-safe to ignore
                    // Unknown attribute, possibly a custom ValidationAttribute — record, don't silently drop.
                    pc.CustomAttributes.Add(shortName);
                    unmodeled.Add(new UnmodeledValidation
                    {
                        Type = typeFullName,
                        Property = propName,
                        Kind = "custom_attribute",
                        Attribute = shortName,
                        Note = "unrecognized attribute; semantics not modeled"
                    });
                    break;
            }
        }
    }
}
