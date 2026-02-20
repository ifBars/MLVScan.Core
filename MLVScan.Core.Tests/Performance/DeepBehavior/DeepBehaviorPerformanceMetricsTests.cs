using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Core.Tests.TestUtilities.Performance;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;

namespace MLVScan.Core.Tests.Performance.DeepBehavior;

public class DeepBehaviorPerformanceMetricsTests
{
    private readonly ITestOutputHelper _output;

    public DeepBehaviorPerformanceMetricsTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Scan_QuickVsDeep_DeepModeStaysWithinExpectedOverhead()
    {
        var assembly = DeepBehaviorAssemblyFactory.CreateDeepAnalysisWorkloadAssembly(methodCount: 20);

        var quickConfig = new ScanConfig
        {
            DeepAnalysis = new DeepBehaviorAnalysisConfig
            {
                EnableDeepAnalysis = false
            }
        };

        var deepConfig = new ScanConfig
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
                MaxDeepMethodsPerAssembly = 16,
                MaxAnalysisTimeMsPerMethod = 150
            }
        };

        var quickScanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), quickConfig);
        var deepScanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), deepConfig);

        var quickMeasurement = PerfMeasurement.Measure(
            name: "quick-scan",
            warmupRuns: 1,
            measuredRuns: 3,
            action: () => Scan(quickScanner, assembly, "QuickPerf.dll"));

        var deepMeasurement = PerfMeasurement.Measure(
            name: "deep-scan",
            warmupRuns: 1,
            measuredRuns: 3,
            action: () => Scan(deepScanner, assembly, "DeepPerf.dll"));

        var p95Ratio = quickMeasurement.P95Ms == 0
            ? 0
            : (double)deepMeasurement.P95Ms / quickMeasurement.P95Ms;

        _output.WriteLine($"Quick Scan: min={quickMeasurement.MinMs}ms avg={quickMeasurement.AverageMs:F1}ms p95={quickMeasurement.P95Ms}ms max={quickMeasurement.MaxMs}ms");
        _output.WriteLine($"Deep Scan : min={deepMeasurement.MinMs}ms avg={deepMeasurement.AverageMs:F1}ms p95={deepMeasurement.P95Ms}ms max={deepMeasurement.MaxMs}ms");
        _output.WriteLine($"Deep/Quick p95 ratio: {p95Ratio:F2}x");

        // Performance metric assertions (coarse to avoid CI flakiness)
        deepMeasurement.P95Ms.Should().BeLessThanOrEqualTo(quickMeasurement.P95Ms * 10 + 1500);
        deepMeasurement.MaxMs.Should().BeLessThanOrEqualTo(8000);
    }

    [Fact]
    public void DeepMode_WithStrictMethodBudget_ControlsDeepFindingVolume()
    {
        var assembly = DeepBehaviorAssemblyFactory.CreateDeepAnalysisWorkloadAssembly(methodCount: 30);

        var strictBudgetConfig = new ScanConfig
        {
            DeepAnalysis = new DeepBehaviorAnalysisConfig
            {
                EnableDeepAnalysis = true,
                DeepScanOnlyFlaggedMethods = false,
                EmitDiagnosticFindings = true,
                RequireCorrelatedBaseFinding = false,
                MaxDeepMethodsPerAssembly = 2,
                MaxAnalysisTimeMsPerMethod = 100,
                EnableStringDecodeFlow = true,
                EnableExecutionChainAnalysis = true,
                EnableResourcePayloadAnalysis = true,
                EnableDynamicLoadCorrelation = true,
                EnableNativeInteropCorrelation = true,
                EnableScriptHostLaunchAnalysis = true,
                EnableEnvironmentPivotCorrelation = true
            }
        };

        var looseBudgetConfig = new ScanConfig
        {
            DeepAnalysis = new DeepBehaviorAnalysisConfig
            {
                EnableDeepAnalysis = true,
                DeepScanOnlyFlaggedMethods = false,
                EmitDiagnosticFindings = true,
                RequireCorrelatedBaseFinding = false,
                MaxDeepMethodsPerAssembly = 20,
                MaxAnalysisTimeMsPerMethod = 200,
                EnableStringDecodeFlow = true,
                EnableExecutionChainAnalysis = true,
                EnableResourcePayloadAnalysis = true,
                EnableDynamicLoadCorrelation = true,
                EnableNativeInteropCorrelation = true,
                EnableScriptHostLaunchAnalysis = true,
                EnableEnvironmentPivotCorrelation = true
            }
        };

        var strictScanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), strictBudgetConfig);
        var looseScanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), looseBudgetConfig);

        var strictFindings = Scan(strictScanner, assembly, "StrictBudget.dll");
        var looseFindings = Scan(looseScanner, assembly, "LooseBudget.dll");

        var strictDeepCount = strictFindings.Count(f => IsDeepRule(f.RuleId));
        var looseDeepCount = looseFindings.Count(f => IsDeepRule(f.RuleId));

        _output.WriteLine($"Strict budget deep findings: {strictDeepCount}");
        _output.WriteLine($"Loose budget deep findings : {looseDeepCount}");
        _output.WriteLine($"Finding delta (loose-strict): {looseDeepCount - strictDeepCount}");

        // Output detailed finding information
        _output.WriteLine("");
        _output.WriteLine("=== STRICT BUDGET FINDINGS (first 10) ===");
        foreach (var finding in strictFindings.Where(f => IsDeepRule(f.RuleId)).Take(10))
        {
            _output.WriteLine($"[{finding.Severity}] {finding.RuleId}");
            _output.WriteLine($"  Location: {finding.Location}");
            _output.WriteLine($"  Description: {finding.Description}");
        }

        _output.WriteLine("");
        _output.WriteLine("=== LOOSE BUDGET FINDINGS (first 25) ===");
        foreach (var finding in looseFindings.Where(f => IsDeepRule(f.RuleId)).Take(25))
        {
            _output.WriteLine($"[{finding.Severity}] {finding.RuleId}");
            _output.WriteLine($"  Location: {finding.Location}");
            _output.WriteLine($"  Description: {finding.Description}");
        }

        looseDeepCount.Should().BeGreaterThanOrEqualTo(strictDeepCount);
    }

    private static List<ScanFinding> Scan(AssemblyScanner scanner, Mono.Cecil.AssemblyDefinition assembly, string fileName)
    {
        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        return scanner.Scan(stream, fileName).ToList();
    }

    private static bool IsDeepRule(string? ruleId)
    {
        return string.Equals(ruleId, "DeepStringDecodeFlowRule", StringComparison.OrdinalIgnoreCase)
               || string.Equals(ruleId, "DeepExecutionChainRule", StringComparison.OrdinalIgnoreCase)
               || string.Equals(ruleId, "DeepResourcePayloadRule", StringComparison.OrdinalIgnoreCase)
               || string.Equals(ruleId, "DeepDynamicLoadCorrelationRule", StringComparison.OrdinalIgnoreCase)
               || string.Equals(ruleId, "DeepNativeInteropCorrelationRule", StringComparison.OrdinalIgnoreCase)
               || string.Equals(ruleId, "DeepScriptHostLaunchRule", StringComparison.OrdinalIgnoreCase)
               || string.Equals(ruleId, "DeepEnvironmentPivotRule", StringComparison.OrdinalIgnoreCase);
    }
}
