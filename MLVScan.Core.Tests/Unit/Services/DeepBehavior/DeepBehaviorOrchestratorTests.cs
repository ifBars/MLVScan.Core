using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class DeepBehaviorOrchestratorTests
{
    [Fact]
    public void ShouldDeepScan_WithSeedRule_ReturnsTrue()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var orchestrator = new DeepBehaviorOrchestrator(
            new DeepBehaviorAnalysisConfig { EnableDeepAnalysis = true },
            new CodeSnippetBuilder());

        var result = orchestrator.ShouldDeepScan(
            method,
            new MethodSignals(),
            [new ScanFinding("T.M:1", "seed", Severity.High) { RuleId = "DllImportRule" }]);

        result.Should().BeTrue();
    }

    [Fact]
    public void AnalyzeMethod_WithCorrelatedInputs_ProducesBehaviorFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var config = new DeepBehaviorAnalysisConfig
        {
            EnableDeepAnalysis = true,
            DeepScanOnlyFlaggedMethods = false,
            EnableExecutionChainAnalysis = true,
            EnableStringDecodeFlow = true,
            EnableResourcePayloadAnalysis = true,
            EnableDynamicLoadCorrelation = true,
            EnableNativeInteropCorrelation = true,
            EnableScriptHostLaunchAnalysis = true,
            EnableEnvironmentPivotCorrelation = true
        };

        var orchestrator = new DeepBehaviorOrchestrator(config, new CodeSnippetBuilder());

        var signals = new MethodSignals
        {
            HasNetworkCall = true,
            HasFileWrite = true,
            HasProcessLikeCall = true
        };

        var findings = orchestrator.AnalyzeMethod(
                method,
                signals,
                [new ScanFinding("T.M:4", "process launch", Severity.Critical) { RuleId = "ProcessStartRule" }],
                [],
                [])
            .ToList();

        findings.Should().NotBeEmpty();
        findings.Should().Contain(finding => finding.RuleId == "DeepExecutionChainRule");
    }
}
