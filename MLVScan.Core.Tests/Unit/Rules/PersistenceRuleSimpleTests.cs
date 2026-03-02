using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class PersistenceRuleSimpleTests
{
    private readonly PersistenceRule _rule = new();

    [Fact]
    public void RuleId_ReturnsPersistenceRule()
    {
        _rule.RuleId.Should().Be("PersistenceRule");
    }

    [Fact]
    public void Severity_ReturnsMedium()
    {
        _rule.Severity.Should().Be(Severity.Medium);
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
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrEmpty();
    }
}
