using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class EnvironmentPivotAnalyzerTests
{
    [Fact]
    public void Analyze_WithEnvironmentPathAndProcessStart_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var signals = new MethodSignals { HasProcessLikeCall = true };
        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepEnvironmentPivotRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithEnvironmentPathAndPersistence_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" },
                new ScanFinding("Test.Type.Method:10", "persistence mechanism", Severity.High) { RuleId = "PersistenceRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepEnvironmentPivotRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithEnvironmentPathAndFileWrite_ReturnsMediumFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var signals = new MethodSignals { HasFileWrite = true };
        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepEnvironmentPivotRule");
        findings[0].Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public void Analyze_WithEnvironmentPathAndDynamicLoad_ReturnsMediumFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" },
                new ScanFinding("Test.Type.Method:10", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepEnvironmentPivotRule");
        findings[0].Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public void Analyze_WithoutFollowupSink_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WhenEnvironmentPivotDisabled_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = false };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var signals = new MethodSignals { HasProcessLikeCall = true };
        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WithoutEnvironmentPathRule_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var signals = new MethodSignals { HasProcessLikeCall = true };
        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
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

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var signals = new MethodSignals { HasProcessLikeCall = true };
        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings = Array.Empty<ScanFinding>(),
            TypeFindings =
            [
                new ScanFinding("Test.Type:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" },
                new ScanFinding("Test.Type:5", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ],
            NamespaceFindings = Array.Empty<ScanFinding>()
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepEnvironmentPivotRule");
    }

    [Fact]
    public void Analyze_NamespaceFindings_CanTriggerCorrelation()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();

        var config = new DeepBehaviorAnalysisConfig { EnableEnvironmentPivotCorrelation = true };
        var analyzer = new EnvironmentPivotAnalyzer(config, new CodeSnippetBuilder());

        var signals = new MethodSignals { HasProcessLikeCall = true };
        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings = Array.Empty<ScanFinding>(),
            TypeFindings = Array.Empty<ScanFinding>(),
            NamespaceFindings =
            [
                new ScanFinding("Test.Namespace:0", "environment path access", Severity.Medium) { RuleId = "EnvironmentPathRule" },
                new ScanFinding("Test.Namespace:5", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepEnvironmentPivotRule");
    }
}
