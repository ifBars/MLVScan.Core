using FluentAssertions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class RuleFactoryTests
{
    [Fact]
    public void CreateDefaultRules_ReturnsNonEmptyList()
    {
        var rules = RuleFactory.CreateDefaultRules();

        rules.Should().NotBeEmpty();
    }

    [Fact]
    public void CreateDefaultRules_ReturnsExpectedCount()
    {
        var rules = RuleFactory.CreateDefaultRules();

        // Based on RuleFactory.cs, there are 19 rules.
        rules.Should().HaveCount(19);
    }

    [Fact]
    public void CreateDefaultRules_ContainsAllExpectedRuleTypes()
    {
        var rules = RuleFactory.CreateDefaultRules();

        rules.Should().ContainSingle(r => r is Base64Rule);
        rules.Should().ContainSingle(r => r is ProcessStartRule);
        rules.Should().ContainSingle(r => r is AssemblyDynamicLoadRule);
        rules.Should().ContainSingle(r => r is ByteArrayManipulationRule);
        rules.Should().ContainSingle(r => r is DllImportRule);
        rules.Should().ContainSingle(r => r is RegistryRule);
        rules.Should().ContainSingle(r => r is EncodedStringLiteralRule);
        rules.Should().ContainSingle(r => r is ReflectionRule);
        rules.Should().ContainSingle(r => r is EncodedStringPipelineRule);
        rules.Should().ContainSingle(r => r is EncodedBlobSplittingRule);
        rules.Should().ContainSingle(r => r is COMReflectionAttackRule);
        rules.Should().ContainSingle(r => r is DataExfiltrationRule);
        rules.Should().ContainSingle(r => r is DataInfiltrationRule);
        rules.Should().ContainSingle(r => r is PersistenceRule);
        rules.Should().ContainSingle(r => r is HexStringRule);
        rules.Should().ContainSingle(r => r is SuspiciousLocalVariableRule);
        rules.Should().ContainSingle(r => r is ObfuscatedReflectiveExecutionRule);
        rules.Should().ContainSingle(r => r is EmbeddedResourceScriptRule);
        rules.Should().ContainSingle(r => r is SuspiciousAssemblyNameRule);
    }

    [Fact]
    public void CreateDefaultRules_AllRulesHaveUniqueRuleIds()
    {
        var rules = RuleFactory.CreateDefaultRules();
        var ruleIds = rules.Select(r => r.RuleId).ToList();

        ruleIds.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void CreateDefaultRules_AllRulesHaveDescriptions()
    {
        var rules = RuleFactory.CreateDefaultRules();

        foreach (var rule in rules)
        {
            rule.Description.Should().NotBeNullOrWhiteSpace($"Rule {rule.RuleId} should have a description");
        }
    }

    [Fact]
    public void CreateDefaultRules_AllRulesHaveValidSeverity()
    {
        var rules = RuleFactory.CreateDefaultRules();

        foreach (var rule in rules)
        {
            rule.Severity.Should().BeOneOf(
                Severity.Low,
                Severity.Medium,
                Severity.High,
                Severity.Critical);
        }
    }

    [Fact]
    public void CreateDefaultRules_ReturnsReadOnlyList()
    {
        var rules = RuleFactory.CreateDefaultRules();

        rules.Should().BeAssignableTo<IReadOnlyList<IScanRule>>();
    }

    [Fact]
    public void CreateDefaultRules_MultipleCalls_ReturnDifferentInstances()
    {
        var rules1 = RuleFactory.CreateDefaultRules();
        var rules2 = RuleFactory.CreateDefaultRules();

        rules1.Should().NotBeSameAs(rules2);
    }

    [Fact]
    public void CreateDefaultRulesWith_AppendsAdditionalRulesAfterBuiltInRules()
    {
        var customRule = new CustomRule("CustomConsumerRule");

        var rules = RuleFactory.CreateDefaultRulesWith(customRule);

        rules.Should().HaveCount(20);
        rules.Take(19).Should().ContainSingle(r => r is Base64Rule);
        rules[^1].Should().BeSameAs(customRule);
        rules.Should().BeAssignableTo<IReadOnlyList<IScanRule>>();
    }

    [Fact]
    public void CreateDefaultRulesWith_RejectsNullAdditionalRulesArray()
    {
        Action act = () => RuleFactory.CreateDefaultRulesWith(null!);

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("additionalRules");
    }

    [Fact]
    public void CreateDefaultRulesWith_RejectsNullAdditionalRuleEntry()
    {
        Action act = () => RuleFactory.CreateDefaultRulesWith(new CustomRule("CustomConsumerRule"), null!);

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("additionalRules");
    }

    [Fact]
    public void CreateDefaultRulesWith_RejectsDuplicateRuleIds()
    {
        Action act = () => RuleFactory.CreateDefaultRulesWith(new CustomRule("ProcessStartRule"));

        act.Should().Throw<ArgumentException>()
            .WithMessage("*Duplicate rule ID 'ProcessStartRule'*");
    }

    [Fact]
    public void CreateDefaultRulesWith_RejectsBlankRuleIds()
    {
        Action act = () => RuleFactory.CreateDefaultRulesWith(new CustomRule(" "));

        act.Should().Throw<ArgumentException>()
            .WithMessage("*Rule IDs cannot be null, empty, or whitespace*");
    }

    private sealed class CustomRule : IScanRule
    {
        public CustomRule(string ruleId)
        {
            RuleId = ruleId;
        }

        public string Description => "Consumer-supplied custom rule";
        public Severity Severity => Severity.Low;
        public string RuleId { get; }
        public bool RequiresCompanionFinding => false;
        public bool IsSuspicious(MethodReference method) => false;
    }
}
