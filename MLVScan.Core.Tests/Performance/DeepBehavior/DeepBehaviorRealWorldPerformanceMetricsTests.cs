using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.Performance;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Performance.DeepBehavior;

public class DeepBehaviorRealWorldPerformanceMetricsTests
{
    private const string ShowFindingDetailsEnvVar = "MLVSCAN_SHOW_FINDING_DETAILS";

    private readonly ITestOutputHelper _output;
    private readonly string? _falsePositivesFolder;

    public DeepBehaviorRealWorldPerformanceMetricsTests(ITestOutputHelper output)
    {
        _output = output;
        _falsePositivesFolder = FindFalsePositivesFolder();
    }

    [SkippableFact]
    public void Scan_RealWorldFalsePositiveSamples_QuickVsDeep_ReportsMetrics()
    {
        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. Real-world performance test requires local sample assemblies.");

        var samples = new[]
        {
            "BankApp.dll",
            "CustomTV.dll",
            "LethalLizard.ModManager.dll",
            "SimpleSingleplayerRespawn.dll"
        };

        var showFindingDetails = IsEnabled(ShowFindingDetailsEnvVar);

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
                    DeepScanOnlyFlaggedMethods = true,
                    EmitDiagnosticFindings = showFindingDetails,
                    RequireCorrelatedBaseFinding = !showFindingDetails,
                    EnableStringDecodeFlow = true,
                    EnableExecutionChainAnalysis = true,
                    EnableResourcePayloadAnalysis = true,
                    EnableDynamicLoadCorrelation = true,
                    EnableNativeInteropCorrelation = true,
                    EnableScriptHostLaunchAnalysis = true,
                    EnableEnvironmentPivotCorrelation = true,
                    MaxAnalysisTimeMsPerMethod = 150,
                    MaxDeepMethodsPerAssembly = 300
                }
            });

        var measured = new List<(string Sample, PerfMeasurement Quick, PerfMeasurement Deep, int QuickFindings, int DeepFindings)>();

        foreach (var sample in samples)
        {
            var path = Path.Combine(_falsePositivesFolder!, sample);
            Skip.IfNot(File.Exists(path), $"Sample not found: {sample}");

            var quickFindingsCount = 0;
            var deepFindingsCount = 0;

            var quickMeasurement = PerfMeasurement.Measure(
                name: $"quick-{sample}",
                warmupRuns: 1,
                measuredRuns: 2,
                action: () =>
                {
                    var findings = quickScanner.Scan(path).ToList();
                    quickFindingsCount = findings.Count;
                });

            var deepMeasurement = PerfMeasurement.Measure(
                name: $"deep-{sample}",
                warmupRuns: 1,
                measuredRuns: 2,
                action: () =>
                {
                    var findings = deepScanner.Scan(path).ToList();
                    deepFindingsCount = findings.Count;
                });

            measured.Add((sample, quickMeasurement, deepMeasurement, quickFindingsCount, deepFindingsCount));
        }

        _output.WriteLine("=== REAL-WORLD QUICK VS DEEP PERFORMANCE ===");
        _output.WriteLine("Sample | Quick p95 | Deep p95 | Ratio | Quick findings | Deep findings");
        _output.WriteLine("-------|-----------|----------|-------|----------------|--------------");

        foreach (var row in measured)
        {
            var ratio = row.Quick.P95Ms == 0 ? 0d : (double)row.Deep.P95Ms / row.Quick.P95Ms;
            _output.WriteLine(
                $"{row.Sample} | {row.Quick.P95Ms}ms | {row.Deep.P95Ms}ms | {ratio:F2}x | {row.QuickFindings} | {row.DeepFindings}");
        }

        if (showFindingDetails)
        {
            _output.WriteLine("");
            _output.WriteLine("=== QUICK VS DEEP FINDING DETAILS ===");
            foreach (var sample in samples)
            {
                var path = Path.Combine(_falsePositivesFolder!, sample);
                if (!File.Exists(path))
                {
                    continue;
                }

                var quickFindings = quickScanner.Scan(path).ToList();
                var deepFindings = deepScanner.Scan(path).ToList();

                _output.WriteLine($"--- {sample} ---");
                _output.WriteLine($"Quick findings: {quickFindings.Count}");
                _output.WriteLine($"Deep findings : {deepFindings.Count}");

                LogRuleSummary("Quick", quickFindings);
                LogRuleSummary("Deep", deepFindings);

                var quickSignatures = new HashSet<string>(quickFindings.Select(GetFindingSignature), StringComparer.OrdinalIgnoreCase);
                var deepOnly = deepFindings
                    .Where(f => !quickSignatures.Contains(GetFindingSignature(f)))
                    .ToList();

                if (deepOnly.Count == 0)
                {
                    _output.WriteLine("Deep-only findings: none");
                }
                else
                {
                    _output.WriteLine($"Deep-only findings ({deepOnly.Count}):");
                    foreach (var finding in deepOnly.Take(20))
                    {
                        _output.WriteLine($"  [{finding.Severity}] {finding.RuleId} | {finding.Location}");
                        _output.WriteLine($"    {finding.Description}");
                    }

                    if (deepOnly.Count > 20)
                    {
                        _output.WriteLine($"  ... and {deepOnly.Count - 20} more");
                    }
                }

                _output.WriteLine("");
            }
        }

        measured.Should().NotBeEmpty();

        // Coarse guardrails to detect major regressions without making CI flaky.
        measured.Should().AllSatisfy(row =>
        {
            row.Quick.MaxMs.Should().BeLessThan(60_000, $"quick scan should stay bounded for {row.Sample}");
            row.Deep.MaxMs.Should().BeLessThan(120_000, $"deep scan should stay bounded for {row.Sample}");

            var ratio = row.Quick.P95Ms == 0 ? 0d : (double)row.Deep.P95Ms / row.Quick.P95Ms;
            ratio.Should().BeLessThan(50, $"deep/quick p95 ratio should avoid catastrophic regressions for {row.Sample}");
        });
    }

    private void LogRuleSummary(string label, IEnumerable<ScanFinding> findings)
    {
        var grouped = findings
            .GroupBy(f => f.RuleId ?? "(none)")
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (grouped.Count == 0)
        {
            _output.WriteLine($"{label} rules: none");
            return;
        }

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

    private static bool IsEnabled(string envVar)
    {
        var value = Environment.GetEnvironmentVariable(envVar);
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Equals("1", StringComparison.OrdinalIgnoreCase)
               || value.Equals("true", StringComparison.OrdinalIgnoreCase)
               || value.Equals("yes", StringComparison.OrdinalIgnoreCase)
               || value.Equals("on", StringComparison.OrdinalIgnoreCase);
    }

    private static string? FindFalsePositivesFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var falsePositivesPath = Path.Combine(currentDir, "FALSE_POSITIVES");
            if (Directory.Exists(falsePositivesPath))
            {
                return falsePositivesPath;
            }

            var mlvScanCorePath = Path.Combine(currentDir, "MLVScan.Core", "FALSE_POSITIVES");
            if (Directory.Exists(mlvScanCorePath))
            {
                return mlvScanCorePath;
            }

            var parent = Directory.GetParent(currentDir);
            currentDir = parent?.FullName;
        }

        return null;
    }
}
