using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EnvironmentPathRuleSimpleTests
{
    private readonly EnvironmentPathRule _rule = new();

    [Fact]
    public void RuleId_ReturnsEnvironmentPathRule()
    {
        _rule.RuleId.Should().Be("EnvironmentPathRule");
    }

    [Fact]
    public void Severity_ReturnsLow()
    {
        _rule.Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_EnvironmentGetFolderPath_ReturnsTrue()
    {
        var methodRef = MethodReferenceFactory.Create("System.Environment", "GetFolderPath");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void AnalyzeContextualPattern_SensitiveFolderConstant_ReturnsFinding()
    {
        var methodRef = MethodReferenceFactory.Create("System.Environment", "GetFolderPath");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, 28),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("LocalApplicationData");
        findings[0].CodeSnippet.Should().Contain("Environment.GetFolderPath(28)");
    }

    [Fact]
    public void AnalyzeContextualPattern_NonSensitiveFolderConstant_ReturnsEmpty()
    {
        var methodRef = MethodReferenceFactory.Create("System.Environment", "GetFolderPath");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, 2),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NoIntegerArgument_ReturnsEmpty()
    {
        var methodRef = MethodReferenceFactory.Create("System.Environment", "GetFolderPath");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "not-a-folder-enum"),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Theory]
    [InlineData(26, "ApplicationData", true)]
    [InlineData(7, "Startup", true)]
    [InlineData(28, "LocalApplicationData", true)]
    [InlineData(35, "CommonApplicationData", true)]
    [InlineData(0, "Folder(0)", false)]
    [InlineData(99, "Folder(99)", false)]
    public void IsSensitiveFolder_VariousValues_ReturnsExpected(int folderValue, string expectedName, bool expectedSensitive)
    {
        var isSensitive = EnvironmentPathRule.IsSensitiveFolder(folderValue);
        var folderName = EnvironmentPathRule.GetFolderName(folderValue);

        isSensitive.Should().Be(expectedSensitive);
        folderName.Should().Be(expectedName);
    }
}
