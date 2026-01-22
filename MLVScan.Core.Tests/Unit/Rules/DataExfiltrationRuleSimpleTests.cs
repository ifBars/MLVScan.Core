using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class DataExfiltrationRuleSimpleTests
{
    private readonly DataExfiltrationRule _rule = new();

    [Fact]
    public void RuleId_ReturnsDataExfiltrationRule()
    {
        _rule.RuleId.Should().Be("DataExfiltrationRule");
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
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrWhiteSpace();
        _rule.Description.Should().Contain("exfiltration");
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }
}
