namespace instrumentor.Tests;

// Regression coverage for the namespace substring-match footgun found and fixed this
// session: fullName.Contains(ns) matched at ANY position, not just a namespace-segment
// boundary, so allowlisting "Bit.Core" would also silently pull in "Bit.CoreUtilities.Foo".
public class NamespaceMatcherTests
{
    [Theory]
    [InlineData("Bit.Core", "Bit.Core", true)] // exact match
    [InlineData("Bit.Core.RealCoreType", "Bit.Core", true)] // real prefix, '.'-boundary
    [InlineData("Bit.CoreUtilities.Foo", "Bit.Core", false)] // substring but NOT a namespace boundary
    [InlineData("MyApp.Bit.CoreExtensions.Bar", "Bit.Core", false)] // substring elsewhere in the string
    [InlineData("Bit.Commercial.Core", "Bit.Core", false)] // same suffix, different tree
    [InlineData("Bit", "Bit.Core", false)] // shorter than ns, never a match
    public void Matches_RequiresExactOrDotBoundaryPrefix(string fullName, string ns, bool expected)
    {
        Assert.Equal(expected, NamespaceMatcher.Matches(fullName, ns));
    }

    [Theory]
    [InlineData("Bit.Core.Foo", "")]
    [InlineData("Bit.Core.Foo", null)]
    public void Matches_RejectsEmptyOrNullNamespace(string fullName, string? ns)
    {
        Assert.False(NamespaceMatcher.Matches(fullName, ns!));
    }
}
