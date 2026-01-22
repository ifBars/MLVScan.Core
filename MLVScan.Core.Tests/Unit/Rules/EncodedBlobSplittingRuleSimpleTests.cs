using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EncodedBlobSplittingRuleSimpleTests
{
    private readonly EncodedBlobSplittingRule _rule = new();

    [Fact]
    public void RuleId_ReturnsEncodedBlobSplittingRule()
    {
        _rule.RuleId.Should().Be("EncodedBlobSplittingRule");
    }

    [Fact]
    public void Severity_ReturnsHigh()
    {
        _rule.Severity.Should().Be(Severity.High);
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
        _rule.Description.Should().Contain("blob splitting");
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_NullMethod_ReturnsEmpty()
    {
        var findings = _rule.AnalyzeInstructions(null!, null!, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }
}
