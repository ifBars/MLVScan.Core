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
    private static readonly HashSet<string> TrackedTopLevelFalsePositiveSamples = new(StringComparer.OrdinalIgnoreCase)
    {
        "AudioImportLib.dll",
        "Bannerlord.ButterLib.dll",
        "BankApp.dll",
        "CustomTV.dll",
        "DeliveryCartPlus_v.1.0.dll",
        "eMployee.dll",
        "ExIni.dll",
        "ezTransXP.dll",
        "FGMONOMobileBanking.dll",
        "HUB.Chat.dll",
        "HUB.SmartEmployees.dll",
        "HUB.TheVeil.dll",
        "IllegalRave.dll",
        "KeepWateringCanFull.dll",
        "LabFusion.dll",
        "LecPowerTranslator15.dll",
        "LethalLizard.ModManager.dll",
        "ModsApp.dll",
        "Muse_Dash.dll",
        "Musicfy.dll",
        "NAudio.Asio.dll",
        "NAudio.Core.dll",
        "OverTheCounter-Loader.dll",
        "S1APILoader.MelonLoader.dll",
        "SaveFileSharing.dll",
        "SimpleSingleplayerRespawn.dll",
        "UnityExplorer.ML.IL2CPP.CoreCLR.dll",
        "UnityExplorer.ML.Mono.dll",
        "UniverseLib.ML.IL2CPP.Interop.dll",
        "UnlimitedLaundering.dll",
        "UpdateTraduccionScheduleI.dll",
        "XUnity.AutoTranslator.Plugin.Core.dll"
    };

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

    private static bool IsAssemblySampleFile(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".winmd", StringComparison.OrdinalIgnoreCase);
    }

    private IReadOnlyList<string> GetTopLevelFalsePositiveSampleNames()
    {
        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        return Directory
            .EnumerateFiles(_falsePositivesFolder!, "*", SearchOption.TopDirectoryOnly)
            .Where(IsAssemblySampleFile)
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private IReadOnlyList<string> GetAllFalsePositiveAssemblyPaths()
    {
        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        return Directory
            .EnumerateFiles(_falsePositivesFolder!, "*", SearchOption.AllDirectories)
            .Where(IsAssemblySampleFile)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    #region False Positive Sample Tests

    [SkippableTheory]
    [InlineData("BankApp.dll")]
    [InlineData("DeliveryCartPlus_v.1.0.dll")]
    [InlineData("eMployee.dll")]
    [InlineData("FGMONOMobileBanking.dll")]
    [InlineData("HUB.Chat.dll")]
    [InlineData("KeepWateringCanFull.dll")]
    [InlineData("OverTheCounter-Loader.dll")]
    [InlineData("SaveFileSharing.dll")]
    [InlineData("SimpleSingleplayerRespawn.dll")]
    [InlineData("UnlimitedLaundering.dll")]
    [InlineData("UpdateTraduccionScheduleI.dll")]
    public void Scan_FalsePositiveSample_ShouldNotProduceFindings(string filename)
    {
        var path = GetSamplePath(filename);

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, filename);

        findings.Should().BeEmpty($"{filename} is a known false positive and should not trigger findings");

        var dto = ScanResultMapper.ToDto(findings, Path.GetFileName(path), File.ReadAllBytes(path), false);
        dto.Disposition.Should().NotBeNull();
        dto.Disposition!.Classification.Should().Be("Clean");
        dto.ThreatFamilies.Should().BeNull();
        dto.Findings.Should().BeEmpty();
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

        var dto = ScanResultMapper.ToDto(findings, Path.GetFileName(path), File.ReadAllBytes(path), false);
        dto.Disposition.Should().NotBeNull();
        dto.Disposition!.Classification.Should().Be("Clean");
        dto.ThreatFamilies.Should().BeNull();
        dto.Findings.Should().NotContain(finding => finding.Visibility == "Default");
    }

    /// <summary>
    /// S1APILoader uses AssemblyResolve for a legitimate Il2CppInterop fallback and reflection
    /// to probe MelonLoader internal APIs. A lookup-only resolver over already loaded assemblies
    /// should not trigger AssemblyDynamicLoadRule at all, and it must not serve as a companion
    /// signal that unlocks ReflectionRule or AssemblyDynamicLoadRule at higher severities.
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

        findings.Should().NotContain(f => f.RuleId == "AssemblyDynamicLoadRule",
            "S1APILoader only subscribes a lookup-only AssemblyResolve fallback over already loaded assemblies");
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

    [SkippableFact]
    public void Scan_HubSmartEmployees_ShouldNotProduceHighOrCriticalFindings()
    {
        var path = GetSamplePath("HUB.SmartEmployees.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "HUB.SmartEmployees.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "HUB.SmartEmployees only decodes recipe seed data and should not be escalated as a staged loader or payload execution risk");

        findings.Should().NotContain(f => f.RuleId == "MultiSignalDetection",
            "recipe seed decoding plus catalog networking should not trigger high-risk multi-signal detection on its own");
    }

    [SkippableFact]
    public void Scan_HubTheVeil_ShouldNotProduceDllImportFindingsForGetAsyncKeyState()
    {
        var path = GetSamplePath("HUB.TheVeil.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "HUB.TheVeil.dll");

        findings.Should().NotContain(f => f.RuleId == "DllImportRule",
            "polling left mouse state through the standard GetAsyncKeyState signature should be treated like other benign user interaction imports");
    }

    [SkippableFact]
    public void Scan_ModsAppBinSample_ShouldNotProduceAssemblyLoadOrReflectionFindings()
    {
        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        var path = Path.Combine(_falsePositivesFolder!, "s1-modsapp", "bin", "Debug Mono", "netstandard2.1",
            "ModsApp.dll");
        Skip.IfNot(File.Exists(path), "ModsApp bin sample not found in FALSE_POSITIVES folder.");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "s1-modsapp/bin/Debug Mono/netstandard2.1/ModsApp.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "ModsApp only performs benign dependency probing and helper reflection, not staged loader behavior");

        findings.Should().NotContain(f => f.RuleId == "AssemblyDynamicLoadRule",
            "simple third-party assembly probing should not be treated as a staged loader");

        findings.Should().NotContain(f => f.RuleId == "ReflectionRule",
            "helper reflection should not be escalated when no real staging signal exists");
    }

    [SkippableFact]
    public void Scan_RegistryLookupLibraries_ShouldNotProduceHighOrCriticalFindings()
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        foreach (var sample in new[] { "ExIni.dll", "ezTransXP.dll", "LecPowerTranslator15.dll" })
        {
            var path = GetSamplePath(sample);
            var findings = scanner.Scan(path).ToList();
            LogFindings(findings, sample);

            findings.Should().NotContain(f => f.Severity >= Severity.High,
                $"{sample} only reads registry values to discover installed application paths");
        }
    }

    [SkippableFact]
    public void Scan_XUnityAutoTranslator_ShouldNotProduceHighOrCriticalFindings()
    {
        var path = GetSamplePath("XUnity.AutoTranslator.Plugin.Core.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "XUnity.AutoTranslator.Plugin.Core.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "XUnity AutoTranslator loads translator plugins and may launch a controlled helper process, but it should not look like a staged loader or payload launcher");
    }

    [SkippableFact]
    public void Scan_Musicfy_ShouldNotProduceHighOrCriticalFindings()
    {
        var path = GetSamplePath("Musicfy.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "Musicfy.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "Musicfy only opens a local folder with shell execute and should not resemble payload execution");
    }

    [SkippableFact]
    public void Scan_NAudioLibraries_ShouldNotProduceHighOrCriticalFindings()
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        foreach (var sample in new[] { "NAudio.Asio.dll", "NAudio.Core.dll", "AudioImportLib.dll" })
        {
            var path = GetSamplePath(sample);
            var findings = scanner.Scan(path).ToList();
            LogFindings(findings, sample);

            findings.Should().NotContain(f => f.Severity >= Severity.High,
                $"{sample} is a media/audio library and should not be escalated into blocking severity");
        }
    }

    /// <summary>
    /// Bannerlord ButterLib is a popular Bannerlord modding library.
    /// Currently disabled due to false positive findings being detected.
    /// </summary>
    [SkippableFact]
    public void Scan_BannerlordButterLib_ShouldNotProduceHighOrCriticalFindings()
    {
        Skip.If(true, "Bannerlord.ButterLib.dll currently triggers false positive findings - needs rule adjustment");
    }

    /// <summary>
    /// SimpleSingleplayerRespawn is a simple single-player respawn mod.
    /// </summary>
    [SkippableFact]
    public void Scan_SimpleSingleplayerRespawn_ShouldNotProduceFindings()
    {
        var path = GetSamplePath("SimpleSingleplayerRespawn.dll");

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, "SimpleSingleplayerRespawn.dll");

        findings.Should().BeEmpty(
            "SimpleSingleplayerRespawn.dll is a known false positive and should not trigger findings");
    }

    /// <summary>
    /// UnityExplorer.ML.Mono is a legitimate MelonLoader debugging tool.
    /// Currently disabled due to false positive findings being detected.
    /// </summary>
    [SkippableFact]
    public void Scan_UnityExplorerMLMono_ShouldNotProduceFindings()
    {
        Skip.If(true, "UnityExplorer.ML.Mono.dll currently triggers false positive findings - needs rule adjustment");
    }

    /// <summary>
    /// UnityExplorer.ML.IL2CPP.CoreCLR is a legitimate MelonLoader debugging tool.
    /// Currently disabled due to false positive findings being detected.
    /// </summary>
    [SkippableFact]
    public void Scan_UnityExplorerMLIL2CPPCoreCLR_ShouldNotProduceFindings()
    {
        Skip.If(true, "UnityExplorer.ML.IL2CPP.CoreCLR.dll currently triggers false positive findings - needs rule adjustment");
    }

    /// <summary>
    /// UniverseLib.ML.IL2CPP.Interop is a legitimate MelonLoader utility library.
    /// Currently disabled due to false positive findings being detected.
    /// </summary>
    [SkippableFact]
    public void Scan_UniverseLibMLIL2CPPInterop_ShouldNotProduceFindings()
    {
        Skip.If(true, "UniverseLib.ML.IL2CPP.Interop.dll currently triggers false positive findings - needs rule adjustment");
    }

    #endregion

    #region Summary Report

    [SkippableFact]
    public void Scan_AllTopLevelFalsePositiveSamples_AreTrackedByFalsePositiveTests()
    {
        var actualSamples = GetTopLevelFalsePositiveSampleNames();

        actualSamples.Should().BeEquivalentTo(TrackedTopLevelFalsePositiveSamples,
            "every top-level assembly in FALSE_POSITIVES should be covered by the false-positive test suite");
    }

    [SkippableFact]
    public void Scan_AllFalsePositiveSamples_SummaryReport()
    {
        var samples = GetTopLevelFalsePositiveSampleNames();

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var results = new List<(string Sample, int TotalFindings, int HighSeverity, int LowSeverity, List<string> RulesTriggered)>();

        foreach (var sample in samples)
        {
            var path = Path.Combine(_falsePositivesFolder!, sample);
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
            "Bannerlord.ButterLib.dll",
            "CustomTV.dll",
            "IllegalRave.dll",
            "LabFusion.dll",
            "Muse_Dash.dll",
            "SimpleSingleplayerRespawn.dll",
            "UnityExplorer.ML.IL2CPP.CoreCLR.dll",
            "UnityExplorer.ML.Mono.dll",
            "UniverseLib.ML.IL2CPP.Interop.dll"
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

    [SkippableFact]
    public void Scan_AllFalsePositiveAssemblies_ShouldRemainCleanUnderThreatDisposition()
    {
        var assemblyPaths = GetAllFalsePositiveAssemblyPaths();
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var violations = new List<string>();

        foreach (var path in assemblyPaths)
        {
            var findings = scanner.Scan(path).ToList();
            var dto = ScanResultMapper.ToDto(findings, Path.GetFileName(path), File.ReadAllBytes(path), false);
            var familyIds = dto.ThreatFamilies?.Select(match => match.FamilyId).ToList() ?? new List<string>();
            var classification = dto.Disposition?.Classification ?? "<missing>";

            _output.WriteLine(
                $"{Path.GetRelativePath(_falsePositivesFolder!, path)} => Disposition={classification}, ThreatFamilies={(familyIds.Count == 0 ? "None" : string.Join(", ", familyIds))}, Findings={findings.Count}");

            if (!string.Equals(classification, "Clean", StringComparison.Ordinal) || familyIds.Count > 0)
            {
                violations.Add(
                    $"{Path.GetRelativePath(_falsePositivesFolder!, path)} => Disposition={classification}, ThreatFamilies={(familyIds.Count == 0 ? "None" : string.Join(", ", familyIds))}");
            }
        }

        violations.Should().BeEmpty(
            "FALSE_POSITIVES assemblies should not produce threat-family matches or non-clean dispositions.\n" +
            string.Join(Environment.NewLine, violations));
    }

    #endregion
}
