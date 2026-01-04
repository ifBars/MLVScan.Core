using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ProcessStartRuleTests
{
    private readonly ProcessStartRule _rule = new();

    [Fact]
    public void RuleId_ReturnsProcessStartRule()
    {
        _rule.RuleId.Should().Be("ProcessStartRule");
    }

    [Fact]
    public void Severity_ReturnsCritical()
    {
        _rule.Severity.Should().Be(Severity.Critical);
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
        _rule.DeveloperGuidance!.IsRemediable.Should().BeFalse();
    }

    [Theory]
    [InlineData("System.Diagnostics.Process", "Start", true)]
    [InlineData("System.Diagnostics.ProcessStartInfo", "Start", true)] // ProcessStartInfo contains "Process"
    [InlineData("MyProcess", "Start", true)] // Contains "Process" and method is "Start"
    [InlineData("System.Diagnostics.Process", "Kill", false)]
    [InlineData("System.Diagnostics.Process", "WaitForExit", false)]
    [InlineData("System.IO.File", "Start", false)]
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
        var methodRef = MethodReferenceFactory.CreateWithNullType("Start");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }
}
