using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
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

        // Based on RuleFactory.cs, there are 18 rules
        rules.Should().HaveCount(18);
    }

    [Fact]
    public void CreateDefaultRules_ContainsAllExpectedRuleTypes()
    {
        var rules = RuleFactory.CreateDefaultRules();

        rules.Should().ContainSingle(r => r is Base64Rule);
        rules.Should().ContainSingle(r => r is ProcessStartRule);
        rules.Should().ContainSingle(r => r is Shell32Rule);
        rules.Should().ContainSingle(r => r is LoadFromStreamRule);
        rules.Should().ContainSingle(r => r is ByteArrayManipulationRule);
        rules.Should().ContainSingle(r => r is DllImportRule);
        rules.Should().ContainSingle(r => r is RegistryRule);
        rules.Should().ContainSingle(r => r is EncodedStringLiteralRule);
        rules.Should().ContainSingle(r => r is ReflectionRule);
        rules.Should().ContainSingle(r => r is EnvironmentPathRule);
        rules.Should().ContainSingle(r => r is EncodedStringPipelineRule);
        rules.Should().ContainSingle(r => r is EncodedBlobSplittingRule);
        rules.Should().ContainSingle(r => r is COMReflectionAttackRule);
        rules.Should().ContainSingle(r => r is DataExfiltrationRule);
        rules.Should().ContainSingle(r => r is DataInfiltrationRule);
        rules.Should().ContainSingle(r => r is PersistenceRule);
        rules.Should().ContainSingle(r => r is HexStringRule);
        rules.Should().ContainSingle(r => r is SuspiciousLocalVariableRule);
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
}
