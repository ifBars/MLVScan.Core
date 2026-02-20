using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class ExecutionChainAnalyzerTests
{
    [Fact]
    public void Analyze_WithDownloadWriteExecuteSignals_EmitsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var analyzer = new ExecutionChainAnalyzer(new DeepBehaviorAnalysisConfig(), new CodeSnippetBuilder());

        var signals = new MethodSignals
        {
            HasNetworkCall = true,
            HasFileWrite = true,
            HasProcessLikeCall = true
        };

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:15", "process launch", Severity.Critical) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepExecutionChainRule");
        findings[0].Severity.Should().Be(Severity.Critical);
    }
}
