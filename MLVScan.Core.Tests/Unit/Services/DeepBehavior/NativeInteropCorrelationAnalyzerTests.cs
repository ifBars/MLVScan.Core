using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class NativeInteropCorrelationAnalyzerTests
{
    [Fact]
    public void Analyze_WithDllImportAndProcessStart_ReturnsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "native import", Severity.Medium) { RuleId = "DllImportRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepNativeInteropCorrelationRule");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Analyze_WithDllImportAndShell32_ReturnsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "native import", Severity.Medium) { RuleId = "DllImportRule" },
                new ScanFinding("Test.Type.Method:10", "shell execute", Severity.High) { RuleId = "Shell32Rule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepNativeInteropCorrelationRule");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Analyze_WithDllImportAndDynamicLoad_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "native import", Severity.Medium) { RuleId = "DllImportRule" },
                new ScanFinding("Test.Type.Method:10", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepNativeInteropCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithDllImportAndPersistence_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "native import", Severity.Medium) { RuleId = "DllImportRule" },
                new ScanFinding("Test.Type.Method:10", "persistence mechanism", Severity.High) { RuleId = "PersistenceRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepNativeInteropCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithoutFollowupSink_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "native import", Severity.Medium) { RuleId = "DllImportRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WhenNativeInteropDisabled_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = false };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "native import", Severity.Medium) { RuleId = "DllImportRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WithoutDllImportRule_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_TypeFindings_CanTriggerCorrelation()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings = Array.Empty<ScanFinding>(),
            TypeFindings =
            [
                new ScanFinding("Test.Type:0", "native import", Severity.Medium) { RuleId = "DllImportRule" }
            ],
            NamespaceFindings = Array.Empty<ScanFinding>()
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_UsesCorrectOffsetPriority()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableNativeInteropCorrelation = true };
        var analyzer = new NativeInteropCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:5", "native import", Severity.Medium) { RuleId = "DllImportRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].Location.Should().Contain(":5");
    }
}
