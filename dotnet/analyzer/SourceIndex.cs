// Pass 1: parse every .cs file under --src and build lookup indexes the later
// walkers (ConstraintWalker, FluentValidationWalker, RouteAuthWalker) share.
// Notably resolves `partial class` declarations split across files into one
// logical type — the regex-based enhance-grammar.py::SourceExtractor had no
// concept of this at all.

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace UpsideFuzz.Analyzer;

public sealed class EnumInfo
{
    public List<string> Names { get; } = new();
    public List<string> NumericValues { get; } = new();
    public bool NonLiteral { get; set; }
}

public sealed class ValidatorInfo
{
    public string ValidatorFullName = "";
    public string ValidatesTypeName = ""; // short or full name as written in AbstractValidator<T>
    public ClassDeclarationSyntax Decl = null!;
}

public sealed class SourceIndex
{
    public readonly Dictionary<string, List<ClassDeclarationSyntax>> ClassesByFullName = new();
    public readonly Dictionary<string, EnumInfo> EnumsByFullName = new();
    public readonly Dictionary<string, EnumInfo> EnumsByShortName = new(); // best-effort unqualified lookup
    public readonly List<ValidatorInfo> Validators = new();
    public readonly List<ClassDeclarationSyntax> ControllerCandidates = new();
    public readonly List<ClassDeclarationSyntax> AllClasses = new();
    // File-level roots, kept so RouteAuthWalker can also find `app.MapGet(...)`-style
    // minimal-API registrations written as C# 9+ top-level statements directly in
    // Program.cs (no enclosing class at all) -- AllClasses alone misses these entirely,
    // since top-level statements have no ClassDeclarationSyntax in the parsed syntax
    // tree (the "Program" class wrapper is a compile-time/semantic construct, not
    // present syntactically). Found via this project's own fixtures/planted-bug-api,
    // written in exactly this (the modern ASP.NET default template) style.
    public readonly List<Microsoft.CodeAnalysis.CSharp.Syntax.CompilationUnitSyntax> FileRoots = new();
    public readonly Diagnostics Diagnostics = new();

    public void Load(string srcRoot)
    {
        var files = Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories)
            .Where(f => !RoslynUtil.IsTestPath(f))
            .ToList();

        foreach (var file in files)
        {
            string text;
            try { text = File.ReadAllText(file); }
            catch (Exception ex) { Diagnostics.FilesFailed++; Diagnostics.ParseErrors.Add($"{file}: {ex.Message}"); continue; }

            SyntaxTree tree;
            try { tree = CSharpSyntaxTree.ParseText(text, path: file); }
            catch (Exception ex) { Diagnostics.FilesFailed++; Diagnostics.ParseErrors.Add($"{file}: {ex.Message}"); continue; }

            var root = tree.GetCompilationUnitRoot();
            Diagnostics.FilesParsed++;
            FileRoots.Add(root);

            foreach (var cls in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                IndexClass(cls);
            }
            foreach (var rec in root.DescendantNodes().OfType<RecordDeclarationSyntax>())
            {
                // Records are DTOs too (init-only properties, positional params) — index
                // them under the same class map keyed by full name so ConstraintWalker
                // can treat classes and records uniformly via BaseTypeDeclarationSyntax.
                IndexRecordAsPseudoClass(rec);
            }
            foreach (var en in root.DescendantNodes().OfType<EnumDeclarationSyntax>())
            {
                IndexEnum(en);
            }
        }
    }

    private void IndexClass(ClassDeclarationSyntax cls)
    {
        var fullName = RoslynUtil.GetFullName(cls);
        if (!ClassesByFullName.TryGetValue(fullName, out var list))
        {
            list = new List<ClassDeclarationSyntax>();
            ClassesByFullName[fullName] = list;
        }
        list.Add(cls);
        AllClasses.Add(cls);

        // Controller candidates: name ends in "Controller", has [ApiController]/[Route], OR
        // (the real signal, broader than any naming convention) any method carries an
        // [Http*] attribute directly — this is what actually catches libraries like
        // Ardalis.ApiEndpoints' `EndpointBaseAsync.WithRequest<T>.WithActionResult<R>`
        // pattern (eShopOnWeb's AuthenticateEndpoint: no Controller suffix, no
        // [ApiController]/[Route], just `[HttpPost("api/authenticate")]` on the method).
        // Naming/attribute-only detection would silently miss this class entirely.
        var attrNames = RoslynUtil.AllAttributes(cls.AttributeLists).Select(RoslynUtil.AttributeShortName).ToList();
        var hasHttpMethodAttr = cls.Members.OfType<MethodDeclarationSyntax>()
            .Any(m => RoslynUtil.AllAttributes(m.AttributeLists)
                .Select(RoslynUtil.AttributeShortName)
                .Any(n => n is "HttpGet" or "HttpPost" or "HttpPut" or "HttpDelete" or "HttpPatch"));
        if (cls.Identifier.Text.EndsWith("Controller") || attrNames.Contains("ApiController") ||
            attrNames.Contains("Route") || hasHttpMethodAttr)
        {
            ControllerCandidates.Add(cls);
        }

        // FluentValidation: class X : AbstractValidator<Y>
        if (cls.BaseList is not null)
        {
            foreach (var baseType in cls.BaseList.Types)
            {
                if (baseType.Type is GenericNameSyntax { Identifier.Text: "AbstractValidator" } gen &&
                    gen.TypeArgumentList.Arguments.Count == 1)
                {
                    Validators.Add(new ValidatorInfo
                    {
                        ValidatorFullName = fullName,
                        ValidatesTypeName = gen.TypeArgumentList.Arguments[0].ToString(),
                        Decl = cls
                    });
                }
            }
        }
    }

    // Records declared with a body (`record Foo { public string X {get;set;} }`) parse to
    // RecordDeclarationSyntax, which is NOT a ClassDeclarationSyntax but shares the same
    // BaseTypeDeclarationSyntax/TypeDeclarationSyntax lineage for members/attributes/base list.
    // We don't reuse ClassDeclarationSyntax storage (can't upcast), so ConstraintWalker
    // accepts TypeDeclarationSyntax generally; this method just registers records into the
    // same full-name index under a synthetic wrapper list keyed by full name for base-class
    // and controller-candidate purposes where relevant (records are rarely controllers).
    private readonly Dictionary<string, List<TypeDeclarationSyntax>> _recordsByFullName = new();
    private void IndexRecordAsPseudoClass(RecordDeclarationSyntax rec)
    {
        var fullName = RoslynUtil.GetFullName(rec);
        if (!_recordsByFullName.TryGetValue(fullName, out var list))
        {
            list = new List<TypeDeclarationSyntax>();
            _recordsByFullName[fullName] = list;
        }
        list.Add(rec);
    }

    public IEnumerable<TypeDeclarationSyntax> AllTypeDeclarations()
    {
        foreach (var kv in ClassesByFullName)
            foreach (var c in kv.Value)
                yield return c;
        foreach (var kv in _recordsByFullName)
            foreach (var r in kv.Value)
                yield return r;
    }

    public IEnumerable<string> AllFullNames()
        => ClassesByFullName.Keys.Concat(_recordsByFullName.Keys).Distinct();

    public IReadOnlyList<TypeDeclarationSyntax> DeclarationsFor(string fullName)
    {
        var result = new List<TypeDeclarationSyntax>();
        if (ClassesByFullName.TryGetValue(fullName, out var classes)) result.AddRange(classes);
        if (_recordsByFullName.TryGetValue(fullName, out var recs)) result.AddRange(recs);
        return result;
    }

    private void IndexEnum(EnumDeclarationSyntax en)
    {
        var fullName = RoslynUtil.GetFullName(en);
        var info = new EnumInfo();
        long next = 0;
        foreach (var member in en.Members)
        {
            info.Names.Add(member.Identifier.Text);
            if (member.EqualsValue is not null)
            {
                if (member.EqualsValue.Value is LiteralExpressionSyntax lit && lit.Token.Value is not null)
                {
                    try
                    {
                        next = Convert.ToInt64(lit.Token.Value);
                    }
                    catch { info.NonLiteral = true; }
                }
                else
                {
                    info.NonLiteral = true;
                }
            }
            info.NumericValues.Add(next.ToString());
            next++;
        }
        EnumsByFullName[fullName] = info;
        EnumsByShortName[en.Identifier.Text] = info; // last-write-wins on collision; documented best-effort
    }
}
