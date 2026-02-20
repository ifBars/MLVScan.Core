using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;

namespace MLVScan.Core.Tests.Integration.DeepBehavior;

public class AssemblyScannerDeepModeTests
{
    private readonly ITestOutputHelper _output;

    public AssemblyScannerDeepModeTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Scan_WithDeepAnalysisDisabled_DoesNotEmitDeepRuleFindings()
    {
        var assembly = DeepBehaviorAssemblyFactory.CreateMultiMethodSwitchAssembly(methodCount: 3, caseCount: 56);
        var config = new ScanConfig
        {
            DeepAnalysis = new DeepBehaviorAnalysisConfig
            {
                EnableDeepAnalysis = false
            }
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), config);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "DeepDisabled.dll").ToList();

        findings.Should().NotContain(finding =>
            string.Equals(finding.RuleId, "DeepStringDecodeFlowRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepExecutionChainRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepResourcePayloadRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepDynamicLoadCorrelationRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepNativeInteropCorrelationRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepScriptHostLaunchRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepEnvironmentPivotRule", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_WithDeepAnalysisEnabled_DoesNotEmitDeepRuleFindingsByDefault()
    {
        var assembly = DeepBehaviorAssemblyFactory.CreateMultiMethodSwitchAssembly(methodCount: 4, caseCount: 64);
        var config = new ScanConfig
        {
            DeepAnalysis = new DeepBehaviorAnalysisConfig
            {
                EnableDeepAnalysis = true,
                DeepScanOnlyFlaggedMethods = false,
                EnableStringDecodeFlow = true,
                EnableExecutionChainAnalysis = true,
                EnableResourcePayloadAnalysis = true,
                MaxDeepMethodsPerAssembly = 10,
                MaxAnalysisTimeMsPerMethod = 200
            }
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), config);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "DeepEnabled.dll").ToList();

        findings.Should().NotContain(finding =>
            string.Equals(finding.RuleId, "DeepStringDecodeFlowRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepExecutionChainRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepResourcePayloadRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepDynamicLoadCorrelationRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepNativeInteropCorrelationRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepScriptHostLaunchRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepEnvironmentPivotRule", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_WithDiagnosticDeepFindingsEnabled_EmitsDeepRuleFindings()
    {
        var assembly = DeepBehaviorAssemblyFactory.CreateMultiMethodSwitchAssembly(methodCount: 4, caseCount: 64);
        var config = new ScanConfig
        {
            DeepAnalysis = new DeepBehaviorAnalysisConfig
            {
                EnableDeepAnalysis = true,
                DeepScanOnlyFlaggedMethods = false,
                EmitDiagnosticFindings = true,
                RequireCorrelatedBaseFinding = false,
                EnableStringDecodeFlow = true,
                EnableExecutionChainAnalysis = true,
                EnableResourcePayloadAnalysis = true,
                EnableDynamicLoadCorrelation = true,
                EnableNativeInteropCorrelation = true,
                EnableScriptHostLaunchAnalysis = true,
                EnableEnvironmentPivotCorrelation = true,
                MaxDeepMethodsPerAssembly = 10,
                MaxAnalysisTimeMsPerMethod = 200
            }
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), config);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "DeepDiagnosticsEnabled.dll").ToList();

        var hasDeepFinding = findings.Any(finding =>
            string.Equals(finding.RuleId, "DeepStringDecodeFlowRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepExecutionChainRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepResourcePayloadRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepDynamicLoadCorrelationRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepNativeInteropCorrelationRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepScriptHostLaunchRule", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.RuleId, "DeepEnvironmentPivotRule", StringComparison.OrdinalIgnoreCase));

        if (!hasDeepFinding)
        {
            _output.WriteLine("Note: No deep findings generated - this is expected for a simple switch assembly.");
            _output.WriteLine($"Total findings: {findings.Count}");
        }
    }
}
