using UpsideFuzz.Analyzer;

namespace analyzer.Tests;

public class FluentValidationWalkerTests
{
    private static Dictionary<string, TypeConstraints> RunPipeline(SourceIndex idx, out List<UnmodeledValidation> unmodeled)
    {
        unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);
        FluentValidationWalker.Apply(idx, types);
        return types;
    }

    [Fact]
    public void Apply_ExtractsSimpleChain()
    {
        using var fx = new TestFixture(
            ("Order.cs", @"
namespace MyApp
{
    public class Order { public string Name { get; set; } }

    public class OrderValidator : AbstractValidator<Order>
    {
        public OrderValidator()
        {
            RuleFor(x => x.Name).Length(1, 50);
        }
    }
}")
        );
        var idx = fx.Load();
        var types = RunPipeline(idx, out _);

        var name = types["MyApp.Order"].Properties["Name"];
        Assert.Equal(1, name.MinLength);
        Assert.Equal(50, name.MaxLength);
        Assert.Contains("FluentValidation:Length", name.Source);
        Assert.Equal("MyApp.OrderValidator", types["MyApp.Order"].ValidatorClass);
    }

    [Fact]
    public void Apply_ExtractsMultiStepChainAcrossSeveralLines()
    {
        using var fx = new TestFixture(
            ("Order.cs", @"
namespace MyApp
{
    public class Order { public string Email { get; set; } }

    public class OrderValidator : AbstractValidator<Order>
    {
        public OrderValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress()
                .MaximumLength(100);
        }
    }
}")
        );
        var idx = fx.Load();
        var types = RunPipeline(idx, out _);

        var email = types["MyApp.Order"].Properties["Email"];
        Assert.True(email.Required);
        Assert.True(email.Email);
        Assert.Equal(100, email.MaxLength);
    }

    [Fact]
    public void Apply_MarksConditionalRulesWithoutInterpretingCondition()
    {
        using var fx = new TestFixture(
            ("Order.cs", @"
namespace MyApp
{
    public class Order { public string Note { get; set; } public bool IsPriority { get; set; } }

    public class OrderValidator : AbstractValidator<Order>
    {
        public OrderValidator()
        {
            RuleFor(x => x.Note).NotEmpty().When(x => x.IsPriority);
        }
    }
}")
        );
        var idx = fx.Load();
        var types = RunPipeline(idx, out _);

        var note = types["MyApp.Order"].Properties["Note"];
        Assert.True(note.FluentConditional);
        Assert.Contains("FluentValidation:When(conditional)", note.Source);
    }

    [Fact]
    public void Apply_NumericRangeChainSetsMinimumAndMaximum()
    {
        using var fx = new TestFixture(
            ("Order.cs", @"
namespace MyApp
{
    public class Order { public int Quantity { get; set; } }

    public class OrderValidator : AbstractValidator<Order>
    {
        public OrderValidator()
        {
            RuleFor(x => x.Quantity).InclusiveBetween(1, 100);
        }
    }
}")
        );
        var idx = fx.Load();
        var types = RunPipeline(idx, out _);

        var quantity = types["MyApp.Order"].Properties["Quantity"];
        Assert.Equal(1, quantity.Minimum);
        Assert.Equal(100, quantity.Maximum);
    }

    [Fact]
    public void Apply_SkipsValidatorWhenTargetTypeNotFoundInSourceTree()
    {
        // "validated type not found in this source tree -- skip, don't guess" (the
        // walker's own documented behavior for a validator whose target DTO lives in
        // a different assembly/isn't part of this analysis run).
        using var fx = new TestFixture(
            ("Validator.cs", @"
namespace MyApp
{
    public class ExternalDtoValidator : AbstractValidator<SomeExternalAssembly.Dto>
    {
        public ExternalDtoValidator() { RuleFor(x => x.Name).NotEmpty(); }
    }
}")
        );
        var idx = fx.Load();
        // Must not throw, and must simply produce no constraints for the unresolvable type.
        var types = RunPipeline(idx, out _);
        Assert.DoesNotContain(types.Values, tc => tc.ValidatorClass == "MyApp.ExternalDtoValidator");
    }
}
