using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DataFlowAnalyzerTests
{
    [Fact]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();

        // Act
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Assert
        analyzer.Should().NotBeNull();
    }

    [Fact]
    public void BuildDataFlowFindings_WithNoSuspiciousChains_ReturnsEmpty()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var findings = analyzer.BuildDataFlowFindings();

        // Assert
        findings.Should().BeEmpty();
    }

    [Fact]
    public void DataFlowChainCount_InitiallyZero()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var count = analyzer.DataFlowChainCount;

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public void SuspiciousChainCount_InitiallyZero()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var count = analyzer.SuspiciousChainCount;

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public void Clear_ResetsDataFlowChainCount()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        analyzer.Clear();

        // Assert
        analyzer.DataFlowChainCount.Should().Be(0);
    }
}
