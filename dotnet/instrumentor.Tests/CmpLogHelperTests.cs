using Mono.Cecil;
using Mono.Cecil.Cil;

namespace instrumentor.Tests;

public class CmpLogHelperTests
{
    [Fact]
    public void IsInt32Const_AcceptsAllInt32ConstOpcodeForms()
    {
        Assert.True(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldc_I4, 424242)));
        Assert.True(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)77)));
        Assert.True(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldc_I4_M1)));
        Assert.True(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldc_I4_0)));
        Assert.True(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldc_I4_8)));
    }

    [Fact]
    public void IsInt32Const_RejectsNonInt32ConstOpcodes()
    {
        Assert.False(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldc_I8, 1L)));
        Assert.False(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Ldstr, "x")));
        Assert.False(CmpLogInstrumentor.IsInt32Const(Instruction.Create(OpCodes.Nop)));
    }

    [Fact]
    public void IsCompareOpcode_AcceptsEqualityCompareFamily()
    {
        Assert.True(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Ceq));
        Assert.True(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Beq));
        Assert.True(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Beq_S));
        Assert.True(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Bne_Un));
        Assert.True(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Bne_Un_S));
    }

    [Fact]
    public void IsCompareOpcode_RejectsRelationalAndOtherOpcodes()
    {
        // Documented v1 scope limit: general relational compares (clt/cgt/ble/bge)
        // are NOT covered -- this locks that limitation in as an explicit, tested fact
        // rather than a silent gap.
        Assert.False(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Clt));
        Assert.False(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Cgt));
        Assert.False(CmpLogInstrumentor.IsCompareOpcode(OpCodes.Nop));
    }

    private static ModuleDefinition NewTestModule() =>
        ModuleDefinition.CreateModule("CmpLogHelperTests.Module", ModuleKind.Dll);

    private static MethodReference MakeMethodRef(ModuleDefinition module, string name, bool hasThis, params TypeReference[] paramTypes)
    {
        var mref = new MethodReference(name, module.TypeSystem.Boolean, module.TypeSystem.String) { HasThis = hasThis };
        foreach (var t in paramTypes)
            mref.Parameters.Add(new ParameterDefinition(t));
        return mref;
    }

    [Theory]
    [InlineData("Equals")]
    [InlineData("op_Equality")]
    [InlineData("StartsWith")]
    [InlineData("EndsWith")]
    [InlineData("Contains")]
    public void IsTargetStringComparisonMethod_AcceptsInstanceOneArgOverload(string methodName)
    {
        using var module = NewTestModule();
        // Instance form: bool <name>(string) -- HasThis=true means 1 explicit param.
        var mref = MakeMethodRef(module, methodName, hasThis: true, module.TypeSystem.String);
        Assert.True(CmpLogInstrumentor.IsTargetStringComparisonMethod(mref));
    }

    [Fact]
    public void IsTargetStringComparisonMethod_AcceptsStaticTwoArgOverload()
    {
        using var module = NewTestModule();
        // Static form: bool Equals(string, string) -- HasThis=false means 2 explicit params.
        var mref = MakeMethodRef(module, "Equals", hasThis: false, module.TypeSystem.String, module.TypeSystem.String);
        Assert.True(CmpLogInstrumentor.IsTargetStringComparisonMethod(mref));
    }

    [Fact]
    public void IsTargetStringComparisonMethod_RejectsUnrelatedMethodName()
    {
        using var module = NewTestModule();
        var mref = MakeMethodRef(module, "ToUpper", hasThis: true);
        Assert.False(CmpLogInstrumentor.IsTargetStringComparisonMethod(mref));
    }

    [Fact]
    public void IsTargetStringComparisonMethod_RejectsStringComparisonOverload()
    {
        using var module = NewTestModule();
        // Equals(string, StringComparison) -- restricted to plain (string[, string])
        // overloads by design; a non-string second parameter must be rejected. A
        // System.Int32 stand-in is enough to prove the type check fires -- the real
        // StringComparison enum isn't needed to exercise this rejection path.
        var mref = MakeMethodRef(module, "Equals", hasThis: true, module.TypeSystem.Int32);
        Assert.False(CmpLogInstrumentor.IsTargetStringComparisonMethod(mref));
    }

    [Fact]
    public void IsTargetStringComparisonMethod_RejectsWrongParameterCount()
    {
        using var module = NewTestModule();
        // Instance form with 2 params (should have exactly 1) -- shape mismatch.
        var mref = MakeMethodRef(module, "Equals", hasThis: true, module.TypeSystem.String, module.TypeSystem.String);
        Assert.False(CmpLogInstrumentor.IsTargetStringComparisonMethod(mref));
    }
}
