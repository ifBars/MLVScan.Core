using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Integration.DeepBehavior;

public class DeepBehaviorQuarantineComparisonTests
{
    private readonly ITestOutputHelper _output;

    public DeepBehaviorQuarantineComparisonTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [SkippableFact]
    public void CompareQuickAndDeep_OnScheduleIMoreNpcs_StaticScanOnly()
    {
        var quarantineFolder = FindQuarantineFolder();
        Skip.If(quarantineFolder == null, "QUARANTINE folder not found.");

        var samplePath = Path.Combine(quarantineFolder!, "ScheduleIMoreNpcs.dll.di");
        Skip.IfNot(File.Exists(samplePath), "ScheduleIMoreNpcs.dll.di not found in QUARANTINE folder.");

        var quickScanner = new AssemblyScanner(
            RuleFactory.CreateDefaultRules(),
            new ScanConfig
            {
                DeepAnalysis = new DeepBehaviorAnalysisConfig
                {
                    EnableDeepAnalysis = false
                }
            });

        var deepScanner = new AssemblyScanner(
            RuleFactory.CreateDefaultRules(),
            new ScanConfig
            {
                DeepAnalysis = new DeepBehaviorAnalysisConfig
                {
                    EnableDeepAnalysis = true,
                    DeepScanOnlyFlaggedMethods = false,
                    EnableStringDecodeFlow = true,
                    EnableExecutionChainAnalysis = true,
                    EnableResourcePayloadAnalysis = true,
                    EnableDynamicLoadCorrelation = true,
                    EnableNativeInteropCorrelation = true,
                    EnableScriptHostLaunchAnalysis = true,
                    EnableEnvironmentPivotCorrelation = true,
                    EmitDiagnosticFindings = true,
                    RequireCorrelatedBaseFinding = false,
                    MaxAnalysisTimeMsPerMethod = 200,
                    MaxDeepMethodsPerAssembly = 500
                }
            });

        // Static analysis only: load/inspect IL metadata, never execute sample code.
        var quickFindings = quickScanner.Scan(samplePath).ToList();
        var deepFindings = deepScanner.Scan(samplePath).ToList();

        quickFindings.Should().NotBeEmpty("quarantine sample should trigger detections");
        deepFindings.Should().NotBeEmpty("deep scan should also detect suspicious behavior");

        _output.WriteLine("=== SCHEDULEIMORENPCS QUICK VS DEEP (STATIC ANALYSIS) ===");
        _output.WriteLine($"Sample: {samplePath}");
        _output.WriteLine($"Quick findings: {quickFindings.Count}");
        _output.WriteLine($"Deep findings : {deepFindings.Count}");
        _output.WriteLine($"Delta (deep-quick): {deepFindings.Count - quickFindings.Count}");
        _output.WriteLine(string.Empty);

        LogRuleSummary("Quick", quickFindings);
        LogRuleSummary("Deep", deepFindings);

        var quickSignatures = new HashSet<string>(quickFindings.Select(GetFindingSignature), StringComparer.OrdinalIgnoreCase);
        var deepOnly = deepFindings
            .Where(finding => !quickSignatures.Contains(GetFindingSignature(finding)))
            .ToList();

        _output.WriteLine(string.Empty);
        _output.WriteLine($"Deep-only findings: {deepOnly.Count}");
        foreach (var finding in deepOnly.Take(40))
        {
            LogFindingDetail(finding);
        }

        if (deepOnly.Count > 40)
        {
            _output.WriteLine($"... and {deepOnly.Count - 40} more deep-only findings.");
        }

        _output.WriteLine(string.Empty);
        _output.WriteLine("=== ALL QUICK FINDINGS (DETAILED) ===");
        foreach (var finding in quickFindings)
        {
            LogFindingDetail(finding);
        }

        _output.WriteLine(string.Empty);
        _output.WriteLine("=== ALL DEEP FINDINGS (DETAILED) ===");
        foreach (var finding in deepFindings)
        {
            LogFindingDetail(finding);
        }
    }

    private void LogFindingDetail(ScanFinding finding)
    {
        _output.WriteLine(string.Empty);
        _output.WriteLine("================================================================================");
        _output.WriteLine($"Rule: {finding.RuleId ?? "(none)"}");
        _output.WriteLine($"Severity: {finding.Severity}");
        _output.WriteLine($"Location: {finding.Location}");
        _output.WriteLine($"Description: {finding.Description}");
        
        if (finding.RiskScore.HasValue)
        {
            _output.WriteLine($"Risk Score: {finding.RiskScore}");
        }

        if (!string.IsNullOrEmpty(finding.CodeSnippet))
        {
            _output.WriteLine("--- Code Snippet ---");
            _output.WriteLine(finding.CodeSnippet);
        }

        if (finding.HasDataFlow && finding.DataFlowChain != null)
        {
            _output.WriteLine("--- Data Flow Chain ---");
            _output.WriteLine($"  Pattern: {finding.DataFlowChain.Pattern}");
            _output.WriteLine($"  Confidence: {finding.DataFlowChain.Confidence * 100:F0}%");
            _output.WriteLine($"  Summary: {finding.DataFlowChain.Summary}");
            _output.WriteLine("  Flow:");
            foreach (var node in finding.DataFlowChain.Nodes)
            {
                _output.WriteLine($"    [{node.NodeType}] {node.Operation}");
                _output.WriteLine($"      Data: {node.DataDescription}");
                _output.WriteLine($"      Location: {node.Location}");
                if (!string.IsNullOrEmpty(node.CodeSnippet))
                {
                    _output.WriteLine($"      Snippet: {node.CodeSnippet}");
                }
            }
        }

        if (finding.HasCallChain && finding.CallChain != null)
        {
            _output.WriteLine("--- Call Chain ---");
            _output.WriteLine($"  Summary: {finding.CallChain.Summary}");
            _output.WriteLine("  Chain:");
            foreach (var node in finding.CallChain.Nodes)
            {
                _output.WriteLine($"    -> {node.Location}");
                _output.WriteLine($"      Type: {node.NodeType}");
                _output.WriteLine($"      Description: {node.Description}");
                if (!string.IsNullOrEmpty(node.CodeSnippet))
                {
                    _output.WriteLine($"      Code Snippet:");
                    _output.WriteLine(node.CodeSnippet);
                }
            }
        }

        _output.WriteLine("================================================================================");
    }

    private void LogRuleSummary(string label, IEnumerable<ScanFinding> findings)
    {
        var grouped = findings
            .GroupBy(f => f.RuleId ?? "(none)")
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .ToList();

        _output.WriteLine($"{label} rules:");
        foreach (var group in grouped)
        {
            _output.WriteLine($"  {group.Key}: {group.Count()}");
        }
    }

    private static string GetFindingSignature(ScanFinding finding)
    {
        return $"{finding.RuleId}|{finding.Location}|{finding.Description}|{finding.Severity}";
    }

    private static string? FindQuarantineFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var direct = Path.Combine(currentDir, "QUARANTINE");
            if (Directory.Exists(direct))
            {
                return direct;
            }

            var nested = Path.Combine(currentDir, "MLVScan.Core", "QUARANTINE");
            if (Directory.Exists(nested))
            {
                return nested;
            }

            currentDir = Directory.GetParent(currentDir)?.FullName;
        }

        return null;
    }
}
