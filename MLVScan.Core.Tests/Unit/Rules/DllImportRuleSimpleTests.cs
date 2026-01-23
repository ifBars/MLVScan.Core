using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class DllImportRuleSimpleTests
{
    private readonly DllImportRule _rule = new();

    [Fact]
    public void RuleId_ReturnsDllImportRule()
    {
        _rule.RuleId.Should().Be("DllImportRule");
    }

    [Fact]
    public void Severity_DefaultIsMedium()
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
        _rule.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
    }
}