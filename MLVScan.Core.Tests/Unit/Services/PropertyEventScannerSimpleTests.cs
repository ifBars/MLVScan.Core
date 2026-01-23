using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class PropertyEventScannerSimpleTests
{
    [Fact]
    public void Constructor_WithNullMethodScanner_ThrowsArgumentNullException()
    {
        var act = () => new PropertyEventScanner(null!, new ScanConfig());

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("methodScanner");
    }

    [Fact]
    public void Constructor_WithNullConfig_UsesDefaultConfig()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var rules = RuleFactory.CreateDefaultRules();
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector,
                                                          stringPatternDetector, snippetBuilder, config, null);
        var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder,
                                              localVariableAnalyzer, exceptionHandlerAnalyzer, config);

        var act = () => new PropertyEventScanner(methodScanner, null!);

        act.Should().NotThrow();
    }

    [Fact]
    public void ScanProperties_WithAnalyzePropertyAccessorsDisabled_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = false };
        var rules = RuleFactory.CreateDefaultRules();
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector,
                                                          stringPatternDetector, snippetBuilder, config, null);
        var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder,
                                              localVariableAnalyzer, exceptionHandlerAnalyzer, config);
        var scanner = new PropertyEventScanner(methodScanner, config);

        // Create a minimal type - we can't easily test with null due to internal checks
        var assembly = TestUtilities.TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();
        var type = assembly.MainModule.Types[0];

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanEvents_WithAnalyzePropertyAccessorsDisabled_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = false };
        var rules = RuleFactory.CreateDefaultRules();
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector,
                                                          stringPatternDetector, snippetBuilder, config, null);
        var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder,
                                              localVariableAnalyzer, exceptionHandlerAnalyzer, config);
        var scanner = new PropertyEventScanner(methodScanner, config);

        var assembly = TestUtilities.TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();
        var type = assembly.MainModule.Types[0];

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().BeEmpty();
    }
}
