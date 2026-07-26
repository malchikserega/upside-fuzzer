// Output model for roslyn-constraints.json — the contract grammarc/roslyn_merge.py reads.
// Kept intentionally flat/serializable (no cyclic refs) since this crosses the
// C#-to-Python process boundary as plain JSON.

using System.Text.Json.Serialization;

namespace UpsideFuzz.Analyzer;

public sealed class PropertyConstraint
{
    [JsonPropertyName("clr_type")] public string ClrType { get; set; } = "";
    [JsonPropertyName("min_length")] public int? MinLength { get; set; }
    [JsonPropertyName("max_length")] public int? MaxLength { get; set; }
    [JsonPropertyName("minimum")] public double? Minimum { get; set; }
    [JsonPropertyName("maximum")] public double? Maximum { get; set; }
    [JsonPropertyName("pattern")] public string? Pattern { get; set; }
    [JsonPropertyName("required")] public bool Required { get; set; }
    [JsonPropertyName("email")] public bool Email { get; set; }
    [JsonPropertyName("url")] public bool Url { get; set; }
    [JsonPropertyName("enum_values")] public List<string> EnumValues { get; set; } = new();
    [JsonPropertyName("enum_numeric_values")] public List<string> EnumNumericValues { get; set; } = new();
    [JsonPropertyName("enum_non_literal")] public bool EnumNonLiteral { get; set; }
    [JsonPropertyName("custom_attributes")] public List<string> CustomAttributes { get; set; } = new();
    [JsonPropertyName("fluent_conditional")] public bool FluentConditional { get; set; }
    [JsonPropertyName("source")] public List<string> Source { get; set; } = new();
}

public sealed class TypeConstraints
{
    [JsonPropertyName("namespace")] public string Namespace { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("base_types")] public List<string> BaseTypes { get; set; } = new();
    [JsonPropertyName("partial_merge_count")] public int PartialMergeCount { get; set; }
    [JsonPropertyName("properties")] public Dictionary<string, PropertyConstraint> Properties { get; set; } = new();
    [JsonPropertyName("validator_class")] public string? ValidatorClass { get; set; }
    [JsonPropertyName("implements_ivalidatableobject")] public bool ImplementsIValidatableObject { get; set; }
}

public sealed class UnmodeledValidation
{
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("property")] public string? Property { get; set; }
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("attribute")] public string? Attribute { get; set; }
    [JsonPropertyName("note")] public string Note { get; set; } = "";
}

public sealed class EndpointInfo
{
    [JsonPropertyName("controller")] public string? Controller { get; set; }
    [JsonPropertyName("action")] public string? Action { get; set; }
    [JsonPropertyName("http_method")] public string HttpMethod { get; set; } = "";
    [JsonPropertyName("route_template")] public string RouteTemplate { get; set; } = "";
    [JsonPropertyName("authorize")] public bool Authorize { get; set; }
    [JsonPropertyName("authorize_roles")] public List<string> AuthorizeRoles { get; set; } = new();
    [JsonPropertyName("allow_anonymous")] public bool AllowAnonymous { get; set; }
    [JsonPropertyName("parameter_types")] public Dictionary<string, string> ParameterTypes { get; set; } = new();
    [JsonPropertyName("style")] public string Style { get; set; } = ""; // "controller" | "minimal-api"
}

public sealed class Diagnostics
{
    [JsonPropertyName("files_parsed")] public int FilesParsed { get; set; }
    [JsonPropertyName("files_failed")] public int FilesFailed { get; set; }
    [JsonPropertyName("parse_errors")] public List<string> ParseErrors { get; set; } = new();
}

public sealed class AnalyzerOutput
{
    [JsonPropertyName("generated_at")] public string GeneratedAt { get; set; } = "";
    [JsonPropertyName("source_root")] public string SourceRoot { get; set; } = "";
    [JsonPropertyName("types")] public Dictionary<string, TypeConstraints> Types { get; set; } = new();
    [JsonPropertyName("unmodeled_validation")] public List<UnmodeledValidation> UnmodeledValidation { get; set; } = new();
    [JsonPropertyName("endpoints")] public List<EndpointInfo> Endpoints { get; set; } = new();
    [JsonPropertyName("diagnostics")] public Diagnostics Diagnostics { get; set; } = new();
}
