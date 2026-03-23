using System.Diagnostics;
using System.Text.Json;
using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.Performance;
using MLVScan.Services;
using MLVScan.Services.Diagnostics;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Performance;

public class FalsePositiveCorpusPerformanceTests
{
    private readonly ITestOutputHelper _output;

    public FalsePositiveCorpusPerformanceTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [SkippableFact]
    [Trait("Category", "Performance")]
    public void Scan_AllFalsePositiveAssemblies_ProducesStableBenchmark()
    {
        var falsePositivesFolder = FindFalsePositivesFolder();
        Skip.If(falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This benchmark requires local sample assemblies.");

        var assemblyPaths = Directory
            .EnumerateFiles(falsePositivesFolder!, "*", SearchOption.AllDirectories)
            .Where(IsAssemblySampleFile)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        assemblyPaths.Should().NotBeEmpty("FALSE_POSITIVES should contain benchmark assemblies");

        const int warmupRuns = 1;
        const int measuredRuns = 3;
        var findingCounts = new List<int>(measuredRuns);

        for (var run = 0; run < warmupRuns; run++)
        {
            RunCorpus(falsePositivesFolder!, assemblyPaths, captureProfiles: false);
        }

        var measurement = PerfMeasurement.Measure("FalsePositiveCorpus", 0, measuredRuns, () =>
        {
            var runResult = RunCorpus(falsePositivesFolder!, assemblyPaths, captureProfiles: false);
            findingCounts.Add(runResult.TotalFindings);
        });

        var baselineRun = RunCorpus(falsePositivesFolder!, assemblyPaths, captureProfiles: true);

        findingCounts.Should().OnlyContain(count => count == findingCounts[0],
            "benchmark runs should produce a stable finding count across the same corpus");

        _output.WriteLine($"Corpus root: {falsePositivesFolder}");
        _output.WriteLine($"Assemblies scanned: {assemblyPaths.Length}");
        _output.WriteLine($"Baseline findings: {baselineRun.TotalFindings}");
        _output.WriteLine($"Measured runs (ms): {string.Join(", ", measurement.DurationsMs)}");
        _output.WriteLine(
            $"Summary: min={measurement.MinMs} avg={measurement.AverageMs:F1} p95={measurement.P95Ms} max={measurement.MaxMs}");
        _output.WriteLine(
            $"Average per assembly: {(measurement.AverageMs / assemblyPaths.Length):F1}ms | findings per run: {findingCounts[0]}");

        var profileArtifactPath = TryWriteProfileArtifact(falsePositivesFolder!, baselineRun);
        if (profileArtifactPath != null)
        {
            _output.WriteLine($"Profile artifact: {profileArtifactPath}");

            foreach (var phase in SummarizePhases(baselineRun).Take(10))
            {
                _output.WriteLine(
                    $"Phase: {phase.Name} | total={phase.TotalMs:F1}ms | avg/assembly={phase.AverageMs:F2}ms | count={phase.Count}");
            }
        }

        foreach (var assembly in baselineRun.Assemblies
                     .OrderByDescending(result => result.DurationMs)
                     .Take(10))
        {
            _output.WriteLine(
                $"Slowest: {Path.GetFileName(assembly.Path)} | {assembly.DurationMs}ms | findings={assembly.Findings}");
        }
    }

    private static CorpusRunResult RunCorpus(string falsePositivesFolder, IReadOnlyList<string> assemblyPaths,
        bool captureProfiles)
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var stopwatch = Stopwatch.StartNew();
        var perAssembly = new List<AssemblyRunResult>(assemblyPaths.Count);
        var totalFindings = 0;

        foreach (var assemblyPath in assemblyPaths)
        {
            var assemblyStopwatch = Stopwatch.StartNew();
            var findings = scanner.Scan(assemblyPath).ToList();
            assemblyStopwatch.Stop();

            var assemblyId = Path.GetRelativePath(falsePositivesFolder, assemblyPath);
            totalFindings += findings.Count;
            perAssembly.Add(new AssemblyRunResult(
                assemblyId,
                assemblyStopwatch.ElapsedMilliseconds,
                findings.Count,
                captureProfiles ? scanner.GetLastProfileSnapshot() : null));
        }

        stopwatch.Stop();
        return new CorpusRunResult(stopwatch.ElapsedMilliseconds, totalFindings, perAssembly);
    }

    private static string? TryWriteProfileArtifact(string falsePositivesFolder, CorpusRunResult run)
    {
        if (run.Assemblies.All(static assembly => assembly.Profile == null))
        {
            return null;
        }

        var outputDirectory = GetPerformanceArtifactDirectory();
        Directory.CreateDirectory(outputDirectory);

        var outputPath = Path.Combine(outputDirectory,
            $"false-positive-corpus-profile-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}.json");

        var payload = new CorpusProfileArtifact
        {
            GeneratedUtc = DateTime.UtcNow,
            CorpusRoot = Path.GetFileName(falsePositivesFolder.TrimEnd(Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar)),
            AssemblyCount = run.Assemblies.Count,
            TotalDurationMs = run.TotalDurationMs,
            TotalFindings = run.TotalFindings,
            PhaseTotals = SummarizePhases(run).ToArray(),
            Assemblies = run.Assemblies
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(outputPath, json);
        return outputPath;
    }

    private static IEnumerable<PhaseSummary> SummarizePhases(CorpusRunResult run)
    {
        return run.Assemblies
            .Where(static assembly => assembly.Profile != null)
            .SelectMany(static assembly => assembly.Profile!.Phases)
            .GroupBy(static phase => phase.Name, StringComparer.Ordinal)
            .Select(group => new PhaseSummary(
                group.Key,
                group.Sum(phase => TicksToMilliseconds(phase.ElapsedTicks)),
                group.Average(phase => TicksToMilliseconds(phase.ElapsedTicks)),
                group.Sum(static phase => phase.Count)))
            .OrderByDescending(static phase => phase.TotalMs);
    }

    private static string GetPerformanceArtifactDirectory()
    {
        return Path.Combine(Path.GetTempPath(), "MLVScanTests", "TestResults", "Performance");
    }

    private static double TicksToMilliseconds(long ticks)
    {
        return ticks * 1000d / Stopwatch.Frequency;
    }

    private static bool IsAssemblySampleFile(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
               || extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
               || extension.Equals(".winmd", StringComparison.OrdinalIgnoreCase);
    }

    private static string? FindFalsePositivesFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var direct = Path.Combine(currentDir, "FALSE_POSITIVES");
            if (Directory.Exists(direct))
            {
                return direct;
            }

            var nested = Path.Combine(currentDir, "MLVScan.Core", "FALSE_POSITIVES");
            if (Directory.Exists(nested))
            {
                return nested;
            }

            currentDir = Directory.GetParent(currentDir)?.FullName;
        }

        return null;
    }

    private sealed record CorpusRunResult(long TotalDurationMs, int TotalFindings, IReadOnlyList<AssemblyRunResult> Assemblies);

    private sealed record AssemblyRunResult(string Path, long DurationMs, int Findings, ScanProfileSnapshot? Profile);

    private sealed record PhaseSummary(string Name, double TotalMs, double AverageMs, int Count);

    private sealed class CorpusProfileArtifact
    {
        public DateTime GeneratedUtc { get; init; }

        public string CorpusRoot { get; init; } = string.Empty;

        public int AssemblyCount { get; init; }

        public long TotalDurationMs { get; init; }

        public int TotalFindings { get; init; }

        public IReadOnlyList<PhaseSummary> PhaseTotals { get; init; } = Array.Empty<PhaseSummary>();

        public IReadOnlyList<AssemblyRunResult> Assemblies { get; init; } = Array.Empty<AssemblyRunResult>();
    }
}
