using FluentAssertions;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.Helpers;

public class InstructionExtensionsTests
{
    [Fact]
    public void GetPushCount_WithVoidCall_ReturnsZero()
    {
        var method = CreateMethodReference("System.Void");
        var instruction = Instruction.Create(OpCodes.Call, method);

        instruction.GetPushCount().Should().Be(0);
    }

    [Fact]
    public void GetPushCount_WithNonVoidCall_ReturnsOne()
    {
        var method = CreateMethodReference("System.String");
        var instruction = Instruction.Create(OpCodes.Callvirt, method);

        instruction.GetPushCount().Should().Be(1);
    }

    [Fact]
    public void GetPushCount_WithNewobj_ReturnsOne()
    {
        var ctor = CreateMethodReference("System.Void");
        var instruction = Instruction.Create(OpCodes.Newobj, ctor);

        instruction.GetPushCount().Should().Be(1);
    }

    [Fact]
    public void GetPopCount_WithStaticCall_ReturnsParameterCount()
    {
        var method = CreateMethodReference("System.Void", parameterCount: 2, hasThis: false);
        var instruction = Instruction.Create(OpCodes.Call, method);

        instruction.GetPopCount().Should().Be(2);
    }

    [Fact]
    public void GetPopCount_WithInstanceCall_ReturnsParameterCountPlusThis()
    {
        var method = CreateMethodReference("System.Void", parameterCount: 2, hasThis: true);
        var instruction = Instruction.Create(OpCodes.Callvirt, method);

        instruction.GetPopCount().Should().Be(3);
    }

    [Fact]
    public void GetPopCount_WithNewobj_ReturnsConstructorParameterCount()
    {
        var ctor = CreateMethodReference("System.Void", parameterCount: 3);
        var instruction = Instruction.Create(OpCodes.Newobj, ctor);

        instruction.GetPopCount().Should().Be(3);
    }

    [Theory]
    [InlineData(Code.Ldc_I4_M1, -1)]
    [InlineData(Code.Ldc_I4_0, 0)]
    [InlineData(Code.Ldc_I4_8, 8)]
    public void TryResolveInt32Literal_WithInlineConstants_ReturnsExpectedValue(Code code, int expected)
    {
        var instruction = Instruction.Create(OpCodeFor(code));

        var success = instruction.TryResolveInt32Literal(out var value);

        success.Should().BeTrue();
        value.Should().Be(expected);
    }

    [Fact]
    public void TryResolveInt32Literal_WithLdcI4Operand_ReturnsExpectedValue()
    {
        var instruction = Instruction.Create(OpCodes.Ldc_I4, 42);

        var success = instruction.TryResolveInt32Literal(out var value);

        success.Should().BeTrue();
        value.Should().Be(42);
    }

    [Fact]
    public void TryResolveInt32Literal_WithLdcI4SOperand_ReturnsExpectedValue()
    {
        var instruction = Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)-12);

        var success = instruction.TryResolveInt32Literal(out var value);

        success.Should().BeTrue();
        value.Should().Be(-12);
    }

    [Fact]
    public void TryResolveInt32Literal_WithNonLiteralInstruction_ReturnsFalse()
    {
        var instruction = Instruction.Create(OpCodes.Ldstr, "x");

        var success = instruction.TryResolveInt32Literal(out var value);

        success.Should().BeFalse();
        value.Should().Be(0);
    }

    [Fact]
    public void TryGetLocalIndex_WithShortAndLongForms_ReturnsIndex()
    {
        var variable = CreateVariableDefinition(5);

        Instruction.Create(OpCodes.Ldloc_2).TryGetLocalIndex(out var shortIndex).Should().BeTrue();
        shortIndex.Should().Be(2);

        Instruction.Create(OpCodes.Ldloc_S, variable).TryGetLocalIndex(out var shortFormIndex).Should().BeTrue();
        shortFormIndex.Should().Be(5);

        Instruction.Create(OpCodes.Ldloc, variable).TryGetLocalIndex(out var longFormIndex).Should().BeTrue();
        longFormIndex.Should().Be(5);
    }

    [Fact]
    public void TryGetLocalIndex_WithNonLocalInstruction_ReturnsFalse()
    {
        var instruction = Instruction.Create(OpCodes.Ldarg_0);

        var success = instruction.TryGetLocalIndex(out _);

        success.Should().BeFalse();
    }

    [Fact]
    public void TryGetStoredLocalIndex_WithShortAndLongForms_ReturnsIndex()
    {
        var variable = CreateVariableDefinition(7);

        Instruction.Create(OpCodes.Stloc_3).TryGetStoredLocalIndex(out var shortIndex).Should().BeTrue();
        shortIndex.Should().Be(3);

        Instruction.Create(OpCodes.Stloc_S, variable).TryGetStoredLocalIndex(out var shortFormIndex).Should().BeTrue();
        shortFormIndex.Should().Be(7);

        Instruction.Create(OpCodes.Stloc, variable).TryGetStoredLocalIndex(out var longFormIndex).Should().BeTrue();
        longFormIndex.Should().Be(7);
    }

    [Fact]
    public void TryGetArgumentIndex_WithShortAndLongForms_ReturnsIndex()
    {
        var parameter = CreateParameterDefinition(4);

        Instruction.Create(OpCodes.Ldarg_1).TryGetArgumentIndex(out var shortIndex).Should().BeTrue();
        shortIndex.Should().Be(1);

        Instruction.Create(OpCodes.Ldarg_S, parameter).TryGetArgumentIndex(out var shortFormIndex).Should().BeTrue();
        shortFormIndex.Should().Be(4);

        Instruction.Create(OpCodes.Ldarg, parameter).TryGetArgumentIndex(out var longFormIndex).Should().BeTrue();
        longFormIndex.Should().Be(4);
    }

    [Fact]
    public void IsValueProducerAndConsumer_ReflectStackBehavior()
    {
        Instruction.Create(OpCodes.Ldstr, "value").IsValueProducer().Should().BeTrue();
        Instruction.Create(OpCodes.Pop).IsValueConsumer().Should().BeTrue();
        Instruction.Create(OpCodes.Nop).IsValueProducer().Should().BeFalse();
        Instruction.Create(OpCodes.Nop).IsValueConsumer().Should().BeFalse();
    }

    [Fact]
    public void IsMethodCallAndGetMethodReference_ReturnExpectedResults()
    {
        var method = CreateMethodReference("System.String");
        var callInstruction = Instruction.Create(OpCodes.Call, method);
        var ctorInstruction = Instruction.Create(OpCodes.Newobj, method);
        var nonCallInstruction = Instruction.Create(OpCodes.Nop);

        callInstruction.IsMethodCall().Should().BeTrue();
        ctorInstruction.IsMethodCall().Should().BeTrue();
        nonCallInstruction.IsMethodCall().Should().BeFalse();

        callInstruction.GetMethodReference().Should().BeSameAs(method);
        nonCallInstruction.GetMethodReference().Should().BeNull();
    }

    [Fact]
    public void IsCallOrCallvirt_ExcludesNewobj()
    {
        var method = CreateMethodReference("System.Void");

        Instruction.Create(OpCodes.Call, method).IsCallOrCallvirt().Should().BeTrue();
        Instruction.Create(OpCodes.Callvirt, method).IsCallOrCallvirt().Should().BeTrue();
        Instruction.Create(OpCodes.Newobj, method).IsCallOrCallvirt().Should().BeFalse();
    }

    [Fact]
    public void IsBranch_RecognizesBranchAndNonBranchOpcodes()
    {
        Instruction.Create(OpCodes.Brtrue_S, Instruction.Create(OpCodes.Nop)).IsBranch().Should().BeTrue();
        Instruction.Create(OpCodes.Blt_Un, Instruction.Create(OpCodes.Nop)).IsBranch().Should().BeTrue();
        Instruction.Create(OpCodes.Call, CreateMethodReference("System.Void")).IsBranch().Should().BeFalse();
    }

    [Fact]
    public void IsArgumentLoad_RecognizesSupportedOpcodes()
    {
        var parameter = new ParameterDefinition("value", ParameterAttributes.None, CreateTypeReference("System.String"));

        Instruction.Create(OpCodes.Ldarg_0).IsArgumentLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldarg_S, parameter).IsArgumentLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldarg, parameter).IsArgumentLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldloc_0).IsArgumentLoad().Should().BeFalse();
    }

    [Fact]
    public void IsSimpleConstantLoad_RecognizesSupportedOpcodes()
    {
        Instruction.Create(OpCodes.Ldstr, "value").IsSimpleConstantLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldc_I4, 5).IsSimpleConstantLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)2).IsSimpleConstantLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldnull).IsSimpleConstantLoad().Should().BeTrue();
        Instruction.Create(OpCodes.Ldc_I8, 5L).IsSimpleConstantLoad().Should().BeFalse();
    }

    private static MethodReference CreateMethodReference(string returnTypeFullName, int parameterCount = 0, bool hasThis = false)
    {
        var module = ModuleDefinition.CreateModule("InstructionExtensionsTests", ModuleKind.Dll);
        var declaringType = new TypeReference("Test", "Target", module, module.TypeSystem.CoreLibrary);
        var method = new MethodReference("Invoke", CreateTypeReference(returnTypeFullName, module), declaringType)
        {
            HasThis = hasThis
        };

        for (var i = 0; i < parameterCount; i++)
        {
            method.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        }

        return method;
    }

    private static VariableDefinition CreateVariableDefinition(int index)
    {
        var module = ModuleDefinition.CreateModule("InstructionExtensionsVars", ModuleKind.Dll);
        var type = new TypeDefinition("Test", "Holder", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Test", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        for (var i = 0; i <= index; i++)
        {
            method.Body.Variables.Add(new VariableDefinition(module.TypeSystem.String));
        }

        return method.Body.Variables[index];
    }

    private static ParameterDefinition CreateParameterDefinition(int index)
    {
        var module = ModuleDefinition.CreateModule("InstructionExtensionsParams", ModuleKind.Dll);
        var method = new MethodDefinition("Test", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);

        for (var i = 0; i <= index; i++)
        {
            method.Parameters.Add(new ParameterDefinition($"arg{i}", ParameterAttributes.None, module.TypeSystem.String));
        }

        return method.Parameters[index];
    }

    private static TypeReference CreateTypeReference(string fullName)
    {
        var module = ModuleDefinition.CreateModule("InstructionExtensionsTypes", ModuleKind.Dll);
        return CreateTypeReference(fullName, module);
    }

    private static TypeReference CreateTypeReference(string fullName, ModuleDefinition module)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : string.Empty;
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
        return new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
    }

    private static OpCode OpCodeFor(Code code)
    {
        return code switch
        {
            Code.Ldc_I4_M1 => OpCodes.Ldc_I4_M1,
            Code.Ldc_I4_0 => OpCodes.Ldc_I4_0,
            Code.Ldc_I4_8 => OpCodes.Ldc_I4_8,
            _ => throw new ArgumentOutOfRangeException(nameof(code), code, null)
        };
    }
}
