using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Integration;

/// <summary>
/// Integration tests that verify data flow analysis works on real QUARANTINE malware samples.
/// Tests that data flow patterns are correctly identified in confirmed malicious assemblies.
/// </summary>
public class DataFlowQuarantineTests
{
    private readonly ITestOutputHelper _output;
    private readonly string? _quarantineFolder;

    public DataFlowQuarantineTests(ITestOutputHelper output)
    {
        _output = output;
        _quarantineFolder = FindQuarantineFolder();
    }

    private static string? FindQuarantineFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var quarantinePath = Path.Combine(currentDir, "QUARANTINE");
            if (Directory.Exists(quarantinePath))
            {
                return quarantinePath;
            }

            var mlvScanCorePath = Path.Combine(currentDir, "MLVScan.Core", "QUARANTINE");
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
        Skip.If(_quarantineFolder == null, "QUARANTINE folder not found. This test requires malware samples which are not available in CI.");

        var path = Path.Combine(_quarantineFolder, filename);
        Skip.IfNot(File.Exists(path), $"Sample {filename} not found in QUARANTINE folder.");

        return path;
    }

    private void LogFindings(List<ScanFinding> findings, string sampleName)
    {
        _output.WriteLine($"=== {sampleName} - Data Flow Analysis ===");
        _output.WriteLine($"Total findings: {findings.Count}");

        var dataFlowFindings = findings.Where(f => f.RuleId == "DataFlowAnalysis" || f.HasDataFlow).ToList();
        _output.WriteLine($"Data flow findings: {dataFlowFindings.Count}");
        _output.WriteLine("");

        foreach (var finding in dataFlowFindings)
        {
            _output.WriteLine($"[{finding.Severity}] {finding.RuleId ?? "Unknown"}");
            _output.WriteLine($"  Location: {finding.Location}");
            _output.WriteLine($"  Description: {finding.Description}");

            if (finding.HasDataFlow)
            {
                _output.WriteLine($"  Data Flow Pattern: {finding.DataFlowChain!.Pattern}");
                _output.WriteLine($"  Confidence: {finding.DataFlowChain.Confidence:P0}");
                _output.WriteLine($"  Operations in chain: {finding.DataFlowChain.Nodes.Count}");

                foreach (var node in finding.DataFlowChain.Nodes)
                {
                    _output.WriteLine($"    {node}");
                }
            }

            _output.WriteLine("");
        }
    }

    #region All Samples Analysis

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di")]
    [InlineData("CustomTV_IL2CPP.dll.di")]
    [InlineData("EndlessGraffiti.dll.di")]
    [InlineData("RealRadio.dll.di")]
    [InlineData("S1API.Il2Cpp.MelonLoader.dll.di")]
    [InlineData("ScheduleIMoreNpcs.dll.di")]
    public void Scan_QuarantineSample_ShouldAnalyzeDataFlows(string filename)
    {
        // Skip if QUARANTINE not available (CI environment)
        var path = GetSamplePath(filename);

        // Arrange
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        // Act
        var findings = scanner.Scan(path).ToList();
        LogFindings(findings, filename);

        // Assert - Malware samples should be scanned without errors
        // Data flow analysis runs on all methods, but may or may not find patterns
        findings.Should().NotBeNull();
    }

    [SkippableFact]
    public void Scan_AllQuarantineSamples_DataFlowAnalysisReport()
    {
        // Skip if QUARANTINE not available (CI environment)
        Skip.If(_quarantineFolder == null, "QUARANTINE folder not found. This test requires malware samples which are not available in CI.");

        var samples = new[]
        {
            "NoMoreTrash.dll.di",
            "CustomTV_IL2CPP.dll.di",
            "EndlessGraffiti.dll.di",
            "RealRadio.dll.di",
            "S1API.Il2Cpp.MelonLoader.dll.di",
            "ScheduleIMoreNpcs.dll.di"
        };

        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var results = new List<(string Sample, int TotalFindings, int DataFlowFindings, List<DataFlowPattern> Patterns, double AvgConfidence)>();

        foreach (var sample in samples)
        {
            var path = Path.Combine(_quarantineFolder, sample);
            if (!File.Exists(path))
            {
                _output.WriteLine($"SKIP: {sample} not found");
                continue;
            }

            var findings = scanner.Scan(path).ToList();
            var dataFlowFindings = findings.Where(f => f.RuleId == "DataFlowAnalysis" || f.HasDataFlow).ToList();
            var patterns = dataFlowFindings
                .Where(f => f.HasDataFlow)
                .Select(f => f.DataFlowChain!.Pattern)
                .Distinct()
                .ToList();

            var avgConfidence = dataFlowFindings
                .Where(f => f.HasDataFlow)
                .Select(f => f.DataFlowChain!.Confidence)
                .DefaultIfEmpty(0)
                .Average();

            results.Add((
                sample,
                findings.Count,
                dataFlowFindings.Count,
                patterns,
                avgConfidence
            ));
        }

        // Output summary
        _output.WriteLine("=== DATA FLOW ANALYSIS SUMMARY ===");
        _output.WriteLine("");
        _output.WriteLine("| Sample | Total Findings | Data Flow Findings | Patterns Detected | Avg Confidence |");
        _output.WriteLine("|--------|----------------|---------------------|-------------------|----------------|");

        foreach (var (sample, total, dataFlow, patterns, confidence) in results)
        {
            var patternsStr = patterns.Count > 0
                ? string.Join(", ", patterns.Take(2)) + (patterns.Count > 2 ? $" (+{patterns.Count - 2})" : "")
                : "None";

            _output.WriteLine($"| {sample,-30} | {total,14} | {dataFlow,19} | {patternsStr,-17} | {confidence,13:P0} |");
        }

        _output.WriteLine("");
        _output.WriteLine($"Total samples scanned: {results.Count}");
        _output.WriteLine($"Samples with data flow findings: {results.Count(r => r.DataFlowFindings > 0)}");

        var allPatterns = results.SelectMany(r => r.Patterns).Distinct().ToList();
        _output.WriteLine($"Unique patterns detected: {string.Join(", ", allPatterns)}");

        // All samples should be scanned successfully
        results.Should().NotBeEmpty();
    }

    #endregion

    #region Specific Pattern Detection Tests

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di")]
    [InlineData("CustomTV_IL2CPP.dll.di")]
    [InlineData("EndlessGraffiti.dll.di")]
    [InlineData("RealRadio.dll.di")]
    [InlineData("S1API.Il2Cpp.MelonLoader.dll.di")]
    [InlineData("ScheduleIMoreNpcs.dll.di")]
    public void Scan_QuarantineSample_ConfidenceScoresAreReasonable(string filename)
    {
        // Skip if QUARANTINE not available (CI environment)
        var path = GetSamplePath(filename);

        // Arrange
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        // Act
        var findings = scanner.Scan(path).ToList();
        var dataFlowFindings = findings.Where(f => f.HasDataFlow).ToList();

        // Assert - All confidence scores should be between 0 and 1
        foreach (var finding in dataFlowFindings)
        {
            finding.DataFlowChain!.Confidence.Should().BeInRange(0.0, 1.0);
        }
    }

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di")]
    [InlineData("CustomTV_IL2CPP.dll.di")]
    [InlineData("EndlessGraffiti.dll.di")]
    [InlineData("RealRadio.dll.di")]
    [InlineData("S1API.Il2Cpp.MelonLoader.dll.di")]
    [InlineData("ScheduleIMoreNpcs.dll.di")]
    public void Scan_QuarantineSample_DataFlowFindingsHaveRequiredProperties(string filename)
    {
        // Skip if QUARANTINE not available (CI environment)
        var path = GetSamplePath(filename);

        // Arrange
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        // Act
        var findings = scanner.Scan(path).ToList();
        var dataFlowFindings = findings.Where(f => f.RuleId == "DataFlowAnalysis").ToList();

        // Assert - All data flow findings should have required properties
        foreach (var finding in dataFlowFindings)
        {
            finding.Location.Should().NotBeNullOrEmpty();
            finding.Description.Should().NotBeNullOrEmpty();
            finding.Severity.Should().BeOneOf(Severity.Low, Severity.Medium, Severity.High, Severity.Critical);
            finding.RuleId.Should().Be("DataFlowAnalysis");
        }
    }

    #endregion

    #region Integration with Full Scanner

    [SkippableFact]
    public void Scan_QuarantineSample_DataFlowWorksAlongsideCallChains()
    {
        // Skip if QUARANTINE not available
        var path = GetSamplePath("NoMoreTrash.dll.di");

        // Arrange
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        // Act
        var findings = scanner.Scan(path).ToList();

        // Assert - Should have both call chain and potentially data flow findings
        var callChainFindings = findings.Where(f => f.HasCallChain).ToList();
        var dataFlowFindings = findings.Where(f => f.RuleId == "DataFlowAnalysis").ToList();

        // NoMoreTrash should have call chain findings (we know this from existing tests)
        callChainFindings.Should().NotBeEmpty();

        // Data flow analysis should run without interfering with call chain analysis
        _output.WriteLine($"Call chain findings: {callChainFindings.Count}");
        _output.WriteLine($"Data flow findings: {dataFlowFindings.Count}");
        _output.WriteLine($"Total findings: {findings.Count}");
    }

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di")]
    [InlineData("CustomTV_IL2CPP.dll.di")]
    [InlineData("EndlessGraffiti.dll.di")]
    [InlineData("RealRadio.dll.di")]
    [InlineData("S1API.Il2Cpp.MelonLoader.dll.di")]
    [InlineData("ScheduleIMoreNpcs.dll.di")]
    public void Scan_QuarantineSample_NoExceptionsThrown(string filename)
    {
        // Skip if QUARANTINE not available (CI environment)
        var path = GetSamplePath(filename);

        // Arrange
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        // Act & Assert - Should not throw any exceptions
        var act = () => scanner.Scan(path).ToList();
        act.Should().NotThrow();
    }

    #endregion

    #region Performance Tests

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di")]
    [InlineData("CustomTV_IL2CPP.dll.di")]
    public void Scan_QuarantineSample_CompletesInReasonableTime(string filename)
    {
        // Skip if QUARANTINE not available (CI environment)
        var path = GetSamplePath(filename);

        // Arrange
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var findings = scanner.Scan(path).ToList();
        sw.Stop();

        // Assert - Should complete within reasonable time (10 seconds)
        _output.WriteLine($"Scan time for {filename}: {sw.ElapsedMilliseconds}ms");
        sw.ElapsedMilliseconds.Should().BeLessThan(10000,
            "Data flow analysis should not significantly slow down scanning");
    }

    #endregion
}
