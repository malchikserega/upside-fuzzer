using UpsideFuzz.Analyzer;

namespace analyzer.Tests;

public class ConstraintWalkerTests
{
    [Fact]
    public void Build_ExtractsDataAnnotationsConstraintsFromAutoProperties()
    {
        using var fx = new TestFixture(
            ("Order.cs", @"
namespace MyApp
{
    public enum Status { Pending, Shipped, Delivered }

    public class Order
    {
        [Range(1, 100)]
        public int Quantity { get; set; }

        [StringLength(50, MinimumLength = 1)]
        public string Name { get; set; }

        [Required]
        [EmailAddress]
        public string ContactEmail { get; set; }

        public Status Status { get; set; }
    }
}")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        var order = types["MyApp.Order"];
        Assert.Equal("Order", order.Name);
        Assert.Equal("MyApp", order.Namespace);

        var quantity = order.Properties["Quantity"];
        Assert.Equal(1, quantity.Minimum);
        Assert.Equal(100, quantity.Maximum);

        var name = order.Properties["Name"];
        Assert.Equal(50, name.MaxLength);
        Assert.Equal(1, name.MinLength);

        var email = order.Properties["ContactEmail"];
        Assert.True(email.Required);
        Assert.True(email.Email);

        var status = order.Properties["Status"];
        Assert.Equal(new List<string> { "Pending", "Shipped", "Delivered" }, status.EnumValues);
        Assert.Equal(new List<string> { "0", "1", "2" }, status.EnumNumericValues);
    }

    [Fact]
    public void Build_ExtractsConstraintsFromPositionalRecordParameters()
    {
        using var fx = new TestFixture(
            ("Dtos.cs", @"
namespace MyApp
{
    public record CreateItemRequest([Required][StringLength(50)] string Name, decimal Price);
}")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        var dto = types["MyApp.CreateItemRequest"];
        var name = dto.Properties["Name"];
        Assert.True(name.Required);
        Assert.Equal(50, name.MaxLength);
    }

    [Fact]
    public void Build_KeysConstraintsPerTypeNotGlobally()
    {
        // Regression guard for the exact bug this walker's own header comment calls
        // out: [StringLength(50)] on one DTO's "Name" must not leak onto a different
        // DTO's differently-constrained "Name" property.
        using var fx = new TestFixture(
            ("Dtos.cs", @"
namespace MyApp
{
    public class Narrow { [StringLength(5)] public string Name { get; set; } }
    public class Wide { [StringLength(500)] public string Name { get; set; } }
}")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        Assert.Equal(5, types["MyApp.Narrow"].Properties["Name"].MaxLength);
        Assert.Equal(500, types["MyApp.Wide"].Properties["Name"].MaxLength);
    }

    [Fact]
    public void Build_MergesBaseClassPropertiesButChildOverridesWin()
    {
        using var fx = new TestFixture(
            ("Hierarchy.cs", @"
namespace MyApp
{
    public class BaseDto { [Required] public string SharedField { get; set; } }
    public class ChildDto : BaseDto { [StringLength(10)] public string OwnField { get; set; } }
}")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        var child = types["MyApp.ChildDto"];
        Assert.True(child.Properties["SharedField"].Required); // inherited from BaseDto
        Assert.Equal(10, child.Properties["OwnField"].MaxLength);
    }

    [Fact]
    public void Build_RecordsUnknownAttributesAsUnmodeledRatherThanSilentlyDropping()
    {
        using var fx = new TestFixture(
            ("Dto.cs", "namespace MyApp { public class Dto { [SomeCustomValidation] public string Field { get; set; } } }")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        Assert.Contains("SomeCustomValidation", types["MyApp.Dto"].Properties["Field"].CustomAttributes);
        Assert.Contains(unmodeled, u => u.Attribute == "SomeCustomValidation" && u.Property == "Field");
    }

    [Fact]
    public void Build_WellKnownNonValidationAttributesAreNotRecordedAsUnmodeled()
    {
        using var fx = new TestFixture(
            ("Dto.cs", "namespace MyApp { public class Dto { [JsonPropertyName(\"field\")] public string Field { get; set; } } }")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        Assert.Empty(types["MyApp.Dto"].Properties["Field"].CustomAttributes);
        Assert.Empty(unmodeled);
    }

    [Fact]
    public void Build_DetectsIValidatableObjectWithoutInterpretingItsBody()
    {
        using var fx = new TestFixture(
            ("Dto.cs", "namespace MyApp { public class Dto : IValidatableObject { public string Field { get; set; } } }")
        );
        var idx = fx.Load();
        var unmodeled = new List<UnmodeledValidation>();
        var types = ConstraintWalker.Build(idx, unmodeled);

        Assert.True(types["MyApp.Dto"].ImplementsIValidatableObject);
        Assert.Contains(unmodeled, u => u.Kind == "IValidatableObject.Validate");
    }
}
