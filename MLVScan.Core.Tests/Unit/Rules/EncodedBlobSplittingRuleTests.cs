using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EncodedBlobSplittingRuleTests
{
    private readonly EncodedBlobSplittingRule _rule = new();

    [Theory]
    [InlineData((sbyte)96, "backtick (`)")]
    [InlineData((sbyte)45, "dash (-)")]
    public void AnalyzeInstructions_SplitWithSuspiciousSeparatorAndLoop_ProducesFinding(sbyte separator, string expectedLabel)
    {
        var method = CreateMethodDefinition("BlobType", "Decode");
        var splitRef = CreateStringSplitMethod(method.Module, parameterCount: 2);

        var loopStart = Instruction.Create(OpCodes.Ldloc_0);
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ldc_I4_S, separator),
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Callvirt, splitRef),
            loopStart,
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Clt),
            Instruction.Create(OpCodes.Brtrue_S, loopStart),
            Instruction.Create(OpCodes.Ret)
        };

        var findings = _rule.AnalyzeInstructions(method, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain(expectedLabel);
        findings[0].CodeSnippet.Should().NotBeNullOrEmpty();
        findings[0].CodeSnippet.Should().Contain(">>>");
    }

    [Fact]
    public void AnalyzeInstructions_SplitWithoutSuspiciousSeparator_DoesNotReport()
    {
        var method = CreateMethodDefinition("BlobType", "Decode");
        var splitRef = CreateStringSplitMethod(method.Module, parameterCount: 2);

        var loopStart = Instruction.Create(OpCodes.Ldloc_0);
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)44), // ','
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Callvirt, splitRef),
            loopStart,
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Clt),
            Instruction.Create(OpCodes.Brtrue_S, loopStart)
        };

        var findings = _rule.AnalyzeInstructions(method, instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_SplitWithSeparatorButNoLoop_DoesNotReport()
    {
        var method = CreateMethodDefinition("BlobType", "Decode");
        var splitRef = CreateStringSplitMethod(method.Module, parameterCount: 2);

        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)96),
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Callvirt, splitRef),
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Ret)
        };

        var findings = _rule.AnalyzeInstructions(method, instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_SplitWithOneParameter_DoesNotReport()
    {
        var method = CreateMethodDefinition("BlobType", "Decode");
        var splitRef = CreateStringSplitMethod(method.Module, parameterCount: 1);

        var loopStart = Instruction.Create(OpCodes.Ldloc_0);
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)96),
            Instruction.Create(OpCodes.Callvirt, splitRef),
            loopStart,
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Clt),
            Instruction.Create(OpCodes.Brtrue_S, loopStart)
        };

        var findings = _rule.AnalyzeInstructions(method, instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    private static MethodDefinition CreateMethodDefinition(string typeName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("EncodedBlobTests", new Version(1, 0, 0, 0)),
            "EncodedBlobTests",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", typeName, TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);
        return method;
    }

    private static MethodReference CreateStringSplitMethod(ModuleDefinition module, int parameterCount)
    {
        var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
        var method = new MethodReference("Split", module.ImportReference(typeof(string[])), stringType)
        {
            HasThis = true
        };

        for (int i = 0; i < parameterCount; i++)
        {
            method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Int32));
        }

        return method;
    }
}
