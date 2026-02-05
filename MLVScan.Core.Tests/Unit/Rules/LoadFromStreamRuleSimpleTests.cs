using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

/// <summary>
/// Basic property tests for AssemblyDynamicLoadRule (replacement for LoadFromStreamRule).
/// </summary>
public class AssemblyDynamicLoadRuleSimpleTests
{
    private readonly AssemblyDynamicLoadRule _rule = new();

    [Fact]
    public void RuleId_ReturnsAssemblyDynamicLoadRule()
    {
        _rule.RuleId.Should().Be("AssemblyDynamicLoadRule");
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
        _rule.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void DeveloperGuidance_IsNotNull()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.IsRemediable.Should().BeTrue();
    }
}
