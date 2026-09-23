using Mono.Cecil;
using Mono.Cecil.Cil;

namespace instrumentor.Tests;

public class ConstantExtractorFilterTests
{
    [Theory]
    [InlineData("UPSIDEFUZZ_MAGIC_TOKEN_12345", true)]
    [InlineData("hello world", true)]
    [InlineData("", false)] // empty rejected
    [InlineData("   ", false)] // whitespace-only rejected after trim
    public void TryCleanString_HandlesBasicCases(string input, bool expectedOk)
    {
        var ok = ConstantExtractor.TryCleanString(input, out var cleaned);
        Assert.Equal(expectedOk, ok);
        if (ok)
        {
            Assert.Equal(input.Trim(), cleaned);
        }
    }

    [Fact]
    public void TryCleanString_RejectsStringsLongerThanMaxStringLen()
    {
        var tooLong = new string('a', ConstantExtractor.MaxStringLen + 1);
        Assert.False(ConstantExtractor.TryCleanString(tooLong, out _));

        var exactly = new string('a', ConstantExtractor.MaxStringLen);
        Assert.True(ConstantExtractor.TryCleanString(exactly, out var cleaned));
        Assert.Equal(exactly, cleaned);
    }

    [Fact]
    public void TryCleanString_RejectsMostlyNonPrintableContent()
    {
        // < 90% printable/letter/digit/punctuation/whitespace -- looks like a binary
        // blob or a control-char-heavy resource key, not a real string literal.
        // Only 1 of the 5 characters here is printable (well below the 90% threshold).
        var mostlyControl = "\u0001\u0002\u0003\u0004a";
        Assert.False(ConstantExtractor.TryCleanString(mostlyControl, out _));
    }

    [Fact]
    public void TryCleanString_AcceptsContentAtExactlyThePrintableThreshold()
    {
        // 9 printable out of 10 total = exactly 90% -- the boundary condition of the
        // ">= 90%" check (printable * 10 >= length * 9).
        var atThreshold = "aaaaaaaaa\u0001"; // 9 letters + 1 control char
        Assert.True(ConstantExtractor.TryCleanString(atThreshold, out _));
    }

    [Fact]
    public void TryGetInterestingIntConst_AcceptsExplicitOperandForms()
    {
        Assert.True(ConstantExtractor.TryGetInterestingIntConst(Instruction.Create(OpCodes.Ldc_I4, 424242), out var i4));
        Assert.Equal(424242, i4);

        Assert.True(ConstantExtractor.TryGetInterestingIntConst(Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)77), out var i4s));
        Assert.Equal(77, i4s);

        Assert.True(ConstantExtractor.TryGetInterestingIntConst(Instruction.Create(OpCodes.Ldc_I8, 8675309L), out var i8));
        Assert.Equal(8675309L, i8);
    }

    // The implicit short forms (ldc.i4.0..8, ldc.i4.m1) only ever encode -1..8 --
    // mutateInt's own hardcoded candidate list already has those, so harvesting them
    // would be pure noise. This is the exact distinction that keeps ConstantExtractor's
    // pool free of low-value candidates.
    [Theory]
    [MemberData(nameof(ImplicitShortFormOpcodes))]
    public void TryGetInterestingIntConst_RejectsImplicitShortForms(OpCode opcode)
    {
        var ok = ConstantExtractor.TryGetInterestingIntConst(Instruction.Create(opcode), out var value);
        Assert.False(ok);
        Assert.Equal(0, value);
    }

    public static IEnumerable<object[]> ImplicitShortFormOpcodes()
    {
        yield return new object[] { OpCodes.Ldc_I4_M1 };
        yield return new object[] { OpCodes.Ldc_I4_0 };
        yield return new object[] { OpCodes.Ldc_I4_1 };
        yield return new object[] { OpCodes.Ldc_I4_8 };
    }

    [Fact]
    public void TryGetInterestingIntConst_RejectsNonIntOpcode()
    {
        Assert.False(ConstantExtractor.TryGetInterestingIntConst(Instruction.Create(OpCodes.Ldstr, "not an int"), out _));
    }
}
