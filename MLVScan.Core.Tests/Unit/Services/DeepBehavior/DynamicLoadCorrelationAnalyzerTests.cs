using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class DynamicLoadCorrelationAnalyzerTests
{
    [Fact]
    public void Analyze_WithDynamicLoadAndReflectionAndExecutionSink_ReturnsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "reflection invocation", Severity.High) { RuleId = "ReflectionRule" },
                new ScanFinding("Test.Type.Method:20", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Analyze_WithDynamicLoadAndReflectionOnly_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "reflection invocation", Severity.High) { RuleId = "ReflectionRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithDynamicLoadAndBase64_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "base64 encoded string", Severity.Medium) { RuleId = "Base64Rule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithDynamicLoadAndHexString_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "hex string encoding", Severity.Medium) { RuleId = "HexStringRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithDynamicLoadAndEncodedStringLiteral_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "encoded string literal", Severity.Medium) { RuleId = "EncodedStringLiteralRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithDynamicLoadAndProcessStart_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithDynamicLoadAndShell32_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "shell execute", Severity.High) { RuleId = "Shell32Rule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepDynamicLoadCorrelationRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Analyze_WithoutFollowupSink_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WhenDynamicLoadDisabled_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = false };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WithoutDynamicLoadRule_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

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
    public void Analyze_UsesDynamicLoadOffset()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:5", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" },
                new ScanFinding("Test.Type.Method:10", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].Location.Should().Contain(":5");
    }

    [Fact]
    public void Analyze_TypeFindings_CanTriggerCorrelation()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        
        var config = new DeepBehaviorAnalysisConfig { EnableDynamicLoadCorrelation = true };
        var analyzer = new DynamicLoadCorrelationAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings = Array.Empty<ScanFinding>(),
            TypeFindings =
            [
                new ScanFinding("Test.Type:0", "dynamic assembly load", Severity.High) { RuleId = "AssemblyDynamicLoadRule" }
            ],
            NamespaceFindings = Array.Empty<ScanFinding>()
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }
}
