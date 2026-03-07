using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class SuspiciousAssemblyNameRuleTests
{
    private readonly SuspiciousAssemblyNameRule _rule = new();

    [Fact]
    public void AnalyzeAssemblyMetadata_MelonLoaderModNumberedName_ReturnsFinding()
    {
        var assembly = TestAssemblyBuilder.Create("MelonLoaderMod55").Build();

        var findings = _rule.AnalyzeAssemblyMetadata(assembly).ToList();

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().BeNull();
        findings[0].Severity.Should().Be(Severity.Medium);
        findings[0].Description.Should().Contain("MelonLoaderMod##");
    }

    [Fact]
    public void AnalyzeAssemblyMetadata_NormalModName_ReturnsNoFinding()
    {
        var assembly = TestAssemblyBuilder.Create("CustomerSearchBar_IL2CPP").Build();

        var findings = _rule.AnalyzeAssemblyMetadata(assembly).ToList();

        findings.Should().BeEmpty();
    }
}
