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
    [InlineData("BankApp.dll")]
    [InlineData("CustomTV.dll")]
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
            "NoMoreTrashMono.dll",
            "RecipeRandomizer.dll"
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var results = new List<(string Sample, int TotalFindings, int HighSeverity, List<string> RulesTriggered)>();

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
                rulesTriggered
            ));
        }

        _output.WriteLine("=== FALSE POSITIVE SCAN SUMMARY ===");
        _output.WriteLine("");
        _output.WriteLine("| Sample | Total | High+ | Rules Triggered |");
        _output.WriteLine("|--------|-------|-------|-----------------| ");

        foreach (var (sample, total, high, rules) in results)
        {
            var rulesStr = rules.Count > 0
                ? string.Join(", ", rules.Take(3)) + (rules.Count > 3 ? $" (+{rules.Count - 3})" : "")
                : "None";

            _output.WriteLine($"| {sample,-25} | {total,5} | {high,5} | {rulesStr} |");
        }

        Skip.If(_falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires samples which are not available in CI.");

        results.Should().NotBeEmpty("FALSE_POSITIVES samples should be available when this test runs");
        results.Should().AllSatisfy(r =>
            r.TotalFindings.Should().Be(0, $"{r.Sample} is a known false positive and should not trigger findings"));
    }

    #endregion
}
