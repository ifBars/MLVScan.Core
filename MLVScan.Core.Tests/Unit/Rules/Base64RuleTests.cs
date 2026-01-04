using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
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
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
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
    [InlineData("MyNamespace.Convert", "FromBase64String", true)]
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
}
