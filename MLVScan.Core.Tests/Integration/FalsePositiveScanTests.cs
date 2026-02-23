using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Integration;

/// <summary>
/// Integration tests that scan known false positive samples from the FALSE_POSITIVES folder.
/// These samples should NOT be flagged by default rules.
/// </summary>
public class FalsePositiveScanTests
{
    private readonly ITestOutputHelper _output;
    private readonly string? _falsePositivesFolder;

    public FalsePositiveScanTests(ITestOutputHelper output)
    {
        _output = output;
        _falsePositivesFolder = FindFalsePositivesFolder();
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

    private string GetSamplePath(string filename)
    {
        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        var path = Path.Combine(_falsePositivesFolder, filename);
        Skip.IfNot(File.Exists(path), $"Sample {filename} not found in FALSE_POSITIVES folder.");

        return path;
    }

    private void LogFindings(List<ScanFinding> findings, string sampleName)
    {
        _output.WriteLine($"=== {sampleName} ===");
        _output.WriteLine($"Total findings: {findings.Count}");

        foreach (var finding in findings)
        {
            _output.WriteLine($"[{finding.Severity}] {finding.RuleId}");
            _output.WriteLine($"  Location: {finding.Location}");
            _output.WriteLine($"  Description: {finding.Description}");
            _output.WriteLine("");
        }
    }

    #region False Positive Sample Tests

    [SkippableTheory]
    [InlineData("AudioImportLib.dll")]
    [InlineData("DeliveryCartPlus_v.1.0.dll")]
    [InlineData("NoMoreTrashMono.dll")]
    [InlineData("RecipeRandomizer.dll")]
    public void Scan_FalsePositiveSample_ShouldNotProduceFindings(string filename)
    {
        var path = GetSamplePath(filename);

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, filename);

        findings.Should().BeEmpty($"{filename} is a known false positive and should not trigger findings");
    }

    /// <summary>
    /// LethalLizard.ModManager.dll uses Process.Start for legitimate purposes:
    /// 1. Opening folders in Windows Explorer (Process.Start("explorer.exe", path))
    /// 2. Restarting the current game process
    /// 
    /// With the updated ProcessStartRule, these patterns are recognized as safe
    /// and suppressed. SuspiciousLocalVariableRule is now supporting-signal only,
    /// so it should not emit standalone findings.
    /// </summary>
    [SkippableFact]
    public void Scan_LethalLizardModManager_ShouldNotProduceCriticalFindings()
    {
        var path = GetSamplePath("LethalLizard.ModManager.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "LethalLizard.ModManager.dll");

        // Should have no Critical findings - Process.Start is now properly suppressed
        findings.Should().NotContain(f => f.Severity == Severity.Critical,
            "LethalLizard.ModManager.dll should not trigger Critical findings after ProcessStartRule fix");

        findings.Should().BeEmpty(
            "LethalLizard.ModManager.dll should not emit standalone findings when only supporting signals are present");
    }

    /// <summary>
    /// S1APILoader uses AssemblyResolve for a legitimate Il2CppInterop fallback and reflection
    /// to probe MelonLoader internal APIs. Neither pattern alone should trigger blocking findings.
    /// AssemblyResolve with a safe handler (score &lt; 25) must not serve as a companion signal
    /// that unlocks ReflectionRule or AssemblyDynamicLoadRule at High/Critical severity.
    /// </summary>
    [SkippableFact]
    public void Scan_S1APILoader_ShouldNotProduceHighOrCriticalFindings()
    {
        var path = GetSamplePath("S1APILoader.MelonLoader.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "S1APILoader.MelonLoader.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "S1APILoader uses AssemblyResolve for a safe Il2CppInterop fallback and reflection " +
            "for MelonLoader internal API access — these are legitimate patterns that must not block the mod");

        findings.Should().NotContain(f => f.RuleId == "ReflectionRule",
            "ReflectionRule should not trigger without a real companion (Low-severity AssemblyResolve is not a companion)");
    }

    /// <summary>
    /// CustomTV legitimately uses System.Diagnostics.Process for controlled yt-dlp execution
    /// (UseShellExecute=false, output redirection, timeout-based WaitForExit).
    /// The SuspiciousLocalVariableRule should suppress this low-signal pattern.
    /// </summary>
    [SkippableFact]
    public void Scan_CustomTV_ShouldNotProduceSuspiciousLocalVariableFindings()
    {
        var path = GetSamplePath("CustomTV.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "CustomTV.dll");

        findings.Should().NotContain(f => f.RuleId == "SuspiciousLocalVariableRule",
            "CustomTV's controlled yt-dlp process usage should not trigger SuspiciousLocalVariableRule");
    }

    /// <summary>
    /// DeliveryCartPlus uses Il2CppInterop reflection and runtime interop glue code.
    /// These patterns should not produce blocking findings on their own.
    /// </summary>
    [SkippableFact]
    public void Scan_DeliveryCartPlus_ShouldNotProduceHighOrCriticalFindings()
    {
        var path = GetSamplePath("DeliveryCartPlus_v.1.0.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "DeliveryCartPlus_v.1.0.dll");

        findings.Should().BeEmpty(
            "DeliveryCartPlus is a known false-positive sample and should not emit standalone findings");
    }

    /// <summary>
    /// Deep analysis should also avoid elevating Il2Cpp interop glue code into blocking findings.
    /// </summary>
    [SkippableFact]
    public void Scan_DeliveryCartPlus_WithDeepAnalysisEnabled_ShouldNotProduceHighOrCriticalFindings()
    {
        var path = GetSamplePath("DeliveryCartPlus_v.1.0.dll");

        var config = new ScanConfig
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
                EnableNetworkToExecutionCorrelation = true,
                EmitDiagnosticFindings = true,
                RequireCorrelatedBaseFinding = false,
                MaxAnalysisTimeMsPerMethod = 200,
                MaxDeepMethodsPerAssembly = 600
            }
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), config);
        var findings = scanner.Scan(path).ToList();

        LogFindings(findings, "DeliveryCartPlus_v.1.0.dll (deep)");

        findings.Should().BeEmpty(
            "DeliveryCartPlus deep analysis should not emit standalone findings for Il2Cpp interop glue code");
    }

    #endregion

    #region Summary Report

    [SkippableFact]
    public void Scan_AllFalsePositiveSamples_SummaryReport()
    {
        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        var samples = new[]
        {
            "AudioImportLib.dll",
            "BankApp.dll",
            "CustomTV.dll",
            "DeliveryCartPlus_v.1.0.dll",
            "LethalLizard.ModManager.dll",
            "NoMoreTrashMono.dll",
            "RecipeRandomizer.dll",
            "S1APILoader.MelonLoader.dll"
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var results = new List<(string Sample, int TotalFindings, int HighSeverity, int LowSeverity, List<string> RulesTriggered)>();

        foreach (var sample in samples)
        {
            var path = Path.Combine(_falsePositivesFolder, sample);
            if (!File.Exists(path))
            {
                _output.WriteLine($"SKIP: {sample} not found");
                continue;
            }

            var findings = scanner.Scan(path).ToList();
            if (findings.Count > 0)
            {
                LogFindings(findings, sample);
            }

            var rulesTriggered = findings
                .Where(f => f.RuleId != null)
                .Select(f => f.RuleId!)
                .Distinct()
                .ToList();

            results.Add((
                sample,
                findings.Count,
                findings.Count(f => f.Severity >= Severity.High),
                findings.Count(f => f.Severity == Severity.Low),
                rulesTriggered
            ));
        }

        _output.WriteLine("=== FALSE POSITIVE SCAN SUMMARY ===");
        _output.WriteLine("");
        _output.WriteLine("| Sample | Total | High+ | Low | Rules Triggered |");
        _output.WriteLine("|--------|-------|-------|-----|-----------------| ");

        foreach (var (sample, total, high, low, rules) in results)
        {
            var rulesStr = rules.Count > 0
                ? string.Join(", ", rules.Take(3)) + (rules.Count > 3 ? $" (+{rules.Count - 3})" : "")
                : "None";

            _output.WriteLine($"| {sample,-25} | {total,5} | {high,5} | {low,3} | {rulesStr} |");
        }

        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        results.Should().NotBeEmpty("FALSE_POSITIVES samples should be available when this test runs");

        var allowedHighSeveritySamples = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "BankApp.dll",
            "CustomTV.dll"
        };

        // Samples not currently in allow-list should have no High severity (or higher) findings
        results
            .Where(r => !allowedHighSeveritySamples.Contains(r.Sample))
            .Should()
            .AllSatisfy(r =>
                r.HighSeverity.Should().Be(0, $"{r.Sample} is a known false positive and should not trigger High+ severity findings"));

        // SuspiciousLocalVariableRule is supporting-signal only and should not emit standalone findings
        var lethalLizardResult = results.FirstOrDefault(r => r.Sample == "LethalLizard.ModManager.dll");
        if (lethalLizardResult.Sample != null)
        {
            lethalLizardResult.TotalFindings.Should().Be(0,
                "LethalLizard.ModManager.dll should have no standalone findings when only supporting signals are present");
        }
    }

    #endregion
}
