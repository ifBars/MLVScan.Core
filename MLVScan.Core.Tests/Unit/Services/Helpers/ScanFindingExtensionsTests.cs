using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.Helpers;

public class ScanFindingExtensionsTests
{
    [Fact]
    public void WithRuleMetadata_WithNullFinding_ReturnsNull()
    {
        var rule = new RuleStub("RuleA", new DeveloperGuidance("Fix A"));

        var result = ScanFindingExtensions.WithRuleMetadata(null!, rule);

        result.Should().BeNull();
    }

    [Fact]
    public void WithRuleMetadata_WithNullRule_ReturnsOriginalFindingUnchanged()
    {
        var finding = new ScanFinding("Test.Type.Method", "description", Severity.Low);

        var result = finding.WithRuleMetadata(null!);

        result.Should().BeSameAs(finding);
        finding.RuleId.Should().BeNull();
        finding.DeveloperGuidance.Should().BeNull();
    }

    [Fact]
    public void WithRuleMetadata_WithValidRule_AssignsRuleIdAndGuidance()
    {
        var finding = new ScanFinding("Test.Type.Method", "description", Severity.Low);
        var guidance = new DeveloperGuidance("Use safe API", "https://example.test/docs");
        var rule = new RuleStub("RuleB", guidance);

        var result = finding.WithRuleMetadata(rule);

        result.Should().BeSameAs(finding);
        finding.RuleId.Should().Be("RuleB");
        finding.DeveloperGuidance.Should().Be(guidance);
    }

    private sealed class RuleStub : IScanRule
    {
        public RuleStub(string ruleId, IDeveloperGuidance? developerGuidance)
        {
            RuleId = ruleId;
            DeveloperGuidance = developerGuidance;
        }

        public string Description => "Rule stub";
        public Severity Severity => Severity.Low;
        public string RuleId { get; }
        public bool RequiresCompanionFinding => false;
        public IDeveloperGuidance? DeveloperGuidance { get; }

        public bool IsSuspicious(MethodReference method) => false;
    }
}
