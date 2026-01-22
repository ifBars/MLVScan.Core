using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class HexStringRuleSimpleTests
{
    private readonly HexStringRule _rule = new();

    [Fact]
    public void RuleId_ReturnsHexStringRule()
    {
        _rule.RuleId.Should().Be("HexStringRule");
    }

    [Fact]
    public void Severity_ReturnsMedium()
    {
        _rule.Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().NotBeNullOrWhiteSpace();
        _rule.DeveloperGuidance.IsRemediable.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Convert", "FromHexString", true)]
    [InlineData("System.Convert", "ToHexString", false)]
    [InlineData("MyNamespace.Convert", "FromHexString", true)]
    [InlineData("System.String", "FromHexString", false)]
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
        var methodRef = MethodReferenceFactory.CreateWithNullType("FromHexString");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }
}
