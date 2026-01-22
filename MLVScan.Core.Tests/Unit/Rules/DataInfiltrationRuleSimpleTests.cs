using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class DataInfiltrationRuleSimpleTests
{
    private readonly DataInfiltrationRule _rule = new();

    [Fact]
    public void RuleId_ReturnsDataInfiltrationRule()
    {
        _rule.RuleId.Should().Be("DataInfiltrationRule");
    }

    [Fact]
    public void Severity_ReturnsHigh()
    {
        _rule.Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsTrue()
    {
        _rule.RequiresCompanionFinding.Should().BeTrue();
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrWhiteSpace();
        _rule.Description.Should().Contain("infiltration");
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().NotBeNullOrWhiteSpace();
        _rule.DeveloperGuidance.IsRemediable.Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }
}
