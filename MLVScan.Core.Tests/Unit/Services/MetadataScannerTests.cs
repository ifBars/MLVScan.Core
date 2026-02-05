using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class MetadataScannerTests
{
    [Fact]
    public void Constructor_WithNullRules_ThrowsArgumentNullException()
    {
        var act = () => new MetadataScanner(null!);

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("rules");
    }

    [Fact]
    public void ScanAssemblyMetadata_EnrichesFindingsWithRuleMetadata()
    {
        var guidance = new DeveloperGuidance("Use trusted metadata values");
        var rule = new MetadataRuleStub(new[]
        {
            new ScanFinding("assembly", "Suspicious metadata", Severity.High)
        }, "MetadataRule", guidance);
        var scanner = new MetadataScanner(new[] { rule });
        var assembly = TestAssemblyBuilder.Create("MetaAssembly").Build();

        var findings = scanner.ScanAssemblyMetadata(assembly).ToList();

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("MetadataRule");
        findings[0].DeveloperGuidance.Should().Be(guidance);
    }

    [Fact]
    public void ScanAssemblyMetadata_WhenRuleThrows_ReturnsFindingsCollectedBeforeFailure()
    {
        var goodRule = new MetadataRuleStub(new[]
        {
            new ScanFinding("assembly", "First finding", Severity.Medium)
        }, "GoodRule", null);
        var throwingRule = new ThrowingMetadataRuleStub();
        var scanner = new MetadataScanner(new IScanRule[] { goodRule, throwingRule });
        var assembly = TestAssemblyBuilder.Create("MetaAssembly").Build();

        var findings = scanner.ScanAssemblyMetadata(assembly).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("GoodRule");
    }

    private sealed class MetadataRuleStub : IScanRule
    {
        private readonly IReadOnlyCollection<ScanFinding> _findings;

        public MetadataRuleStub(IEnumerable<ScanFinding> findings, string ruleId, IDeveloperGuidance? developerGuidance)
        {
            _findings = findings.ToList();
            RuleId = ruleId;
            DeveloperGuidance = developerGuidance;
        }

        public string Description => "Metadata rule stub";
        public Severity Severity => Severity.Low;
        public string RuleId { get; }
        public bool RequiresCompanionFinding => false;
        public IDeveloperGuidance? DeveloperGuidance { get; }

        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly) => _findings;
    }

    private sealed class ThrowingMetadataRuleStub : IScanRule
    {
        public string Description => "Throwing metadata rule";
        public Severity Severity => Severity.Low;
        public string RuleId => "ThrowingRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            throw new InvalidOperationException("Simulated metadata rule failure");
        }
    }
}
