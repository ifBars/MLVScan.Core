using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class StringDecodeFlowAnalyzerTests
{
    [Fact]
    public void Analyze_WithEncodedAndRiskySink_EmitsCorrelationFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var analyzer = new StringDecodeFlowAnalyzer(new DeepBehaviorAnalysisConfig(), new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:10", "encoded pipeline", Severity.Low) { RuleId = "EncodedStringPipelineRule" },
                new ScanFinding("Test.Type.Method:20", "process launch", Severity.Critical) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepStringDecodeFlowRule");
    }
}
