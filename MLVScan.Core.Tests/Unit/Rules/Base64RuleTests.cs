using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class Base64RuleTests
{
    private readonly Base64Rule _rule = new();

    [Fact]
    public void RuleId_ReturnsBase64Rule()
    {
        _rule.RuleId.Should().Be("Base64Rule");
    }

    [Fact]
    public void Severity_ReturnsLow()
    {
        _rule.Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsTrue()
    {
        _rule.RequiresCompanionFinding.Should().BeTrue();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().NotBeNullOrWhiteSpace();
        _rule.DeveloperGuidance.IsRemediable.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Convert", "FromBase64String", true)]
    [InlineData("System.Convert", "FromBase64CharArray", true)]
    [InlineData("MyNamespace.Convert", "FromBase64String", false)]
    [InlineData("System.Convert", "ToBase64String", false)]
    [InlineData("System.Convert", "ToInt32", false)]
    [InlineData("System.String", "FromBase64String", false)]
    [InlineData("System.Text.Encoding", "GetBytes", false)]
    public void IsSuspicious_VariousMethods_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var methodRef = MethodReferenceFactory.Create(typeName, methodName);

        var result = _rule.IsSuspicious(methodRef);

        result.Should().Be(expected);
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullDeclaringType_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.CreateWithNullType("FromBase64String");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_DynamicInputWithoutDangerousContext_ReturnsTrue()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldarg_0),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        _rule.ShouldSuppressFinding(methodRef, instructions, 1, new MethodSignals()).Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_EmbeddedBase64LikeLiteral_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "SGVsbG8gZnJvbSBNTFZTY2FuIQ=="),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        _rule.ShouldSuppressFinding(methodRef, instructions, 1, new MethodSignals()).Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ProcessSinkAfterDecode_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        var processStart = MethodReferenceFactory.Create("System.Diagnostics.Process", "Start");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldarg_0),
            Instruction.Create(OpCodes.Call, methodRef),
            Instruction.Create(OpCodes.Ldstr, "cmd.exe"),
            Instruction.Create(OpCodes.Call, processStart)
        };

        _rule.ShouldSuppressFinding(methodRef, instructions, 1, new MethodSignals()).Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_FileStagingAfterDecode_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        var writeAllBytes = MethodReferenceFactory.Create("System.IO.File", "WriteAllBytes");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldarg_0),
            Instruction.Create(OpCodes.Call, methodRef),
            Instruction.Create(OpCodes.Call, writeAllBytes)
        };

        _rule.ShouldSuppressFinding(methodRef, instructions, 1, new MethodSignals()).Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_MultipleCallsInSameMethod_CollectsEvidenceOnce()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldarg_0),
            Instruction.Create(OpCodes.Call, methodRef),
            Instruction.Create(OpCodes.Ldarg_0),
            Instruction.Create(OpCodes.Call, methodRef)
        };
        int collectionCount = 0;
        var rule = new Base64Rule(methodInstructions =>
        {
            collectionCount++;
            return ObfuscatedExecutionHeuristics.CollectEvidence(methodInstructions);
        });

        rule.ShouldSuppressFinding(methodRef, instructions, 1, new MethodSignals()).Should().BeTrue();
        rule.ShouldSuppressFinding(methodRef, instructions, 3, new MethodSignals()).Should().BeTrue();

        collectionCount.Should().Be(1);
    }
}
