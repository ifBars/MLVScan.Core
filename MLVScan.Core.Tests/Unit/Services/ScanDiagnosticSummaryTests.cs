using System.Text.Json;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;
public class ScanDiagnosticSummaryTests
{
    [Fact]
    public void UntrustedTextIsNeverAPropertyAndGroupsAreBounded()
    {
        var summary = new ScanDiagnosticSummary();
        for (var i = 0; i < 500; i++)
            summary.Observe(new ScanResultDto {
                Input = new ScanInputDto { FileName = "private-canary.dll", Sha256Hash = "secret-hash" },
                Disposition = new ThreatDispositionDto { Classification = "Clean" },
                Findings = new() { new FindingDto { RuleId = "private-canary-" + i, Description = "private-canary", Location = "C:/private-canary", Severity = "private-canary", Visibility = "private-canary" } },
                ThreatFamilies = new() { new ThreatFamilyDto { FamilyId = "private-canary" } }
            });
        var json = JsonSerializer.Serialize(summary.Snapshot());
        Assert.DoesNotContain("private-canary", json);
        Assert.DoesNotContain("secret-hash", json);
        Assert.True(summary.Snapshot().Count <= ScanDiagnosticSummary.MaxGroups + 1);
        Assert.Equal(500, summary.Snapshot()["rule_other_Unknown_Unknown_Clean_results"]);
        var detached = summary.Copy().Snapshot();
        summary.Observe(new ScanResultDto());
        Assert.Equal(500, detached["fresh_result_count"]);
    }

    [Fact]
    public void HighAdvancedFindingDoesNotBecomeSuspiciousOrDefaultVisible()
    {
        var result = new ScanResultDto { Disposition = new ThreatDispositionDto { Classification = "Clean" },
            Findings = new() { new FindingDto { RuleId = "ReflectionRule", Severity = "High", Visibility = "Advanced" } } };
        var summary = new ScanDiagnosticSummary(); summary.Observe(result, cached: true);
        Assert.Equal(1, summary.Snapshot()["rule_ReflectionRule_High_Advanced_Clean_results"]);
        Assert.Equal(1, summary.Snapshot()["cached_result_count"]);
        Assert.DoesNotContain(summary.Snapshot().Keys, key => key.Contains("Suspicious"));
    }

    [Fact]
    public void FindingIdsCoverEveryRegisteredRule()
    {
        var missing = RuleFactory.CreateDefaultRules().Select(r => r.RuleId).Except(ScanDiagnosticSummary.FindingIds).ToList();
        Assert.Empty(missing);
        Assert.Equal(ScanDiagnosticSummary.FindingIds.Count, ScanDiagnosticSummary.FindingIds.Distinct().Count());
        Assert.All(ScanDiagnosticSummary.FindingIds, id => Assert.DoesNotContain("_", id));
    }

    [Fact]
    public void FindingIdsCoverEveryRuleIdLiteralInCoreSource()
    {
        // Scanner warnings and correlation findings set RuleId outside Models/Rules. Without this
        // guard they silently fall into "other" for every telemetry consumer.
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !File.Exists(Path.Combine(root.FullName, "Services", "ScanDiagnosticSummary.cs"))) root = root.Parent;
        Assert.NotNull(root);
        var literal = new System.Text.RegularExpressions.Regex("RuleId\\s*(?:=>|=)\\s*\"([^\"]+)\"");
        var emitted = new[] { "Models", "Services" }
            .SelectMany(dir => Directory.EnumerateFiles(Path.Combine(root!.FullName, dir), "*.cs", SearchOption.AllDirectories))
            .SelectMany(file => literal.Matches(File.ReadAllText(file)).Select(m => m.Groups[1].Value))
            .Distinct().OrderBy(id => id, StringComparer.Ordinal).ToList();
        Assert.Contains("MethodScanWarning", emitted);
        Assert.Empty(emitted.Except(ScanDiagnosticSummary.FindingIds));
    }

    [Fact]
    public void IncompleteAnalysisIsCountedOncePerResultBySourceFinding()
    {
        var result = new ScanResultDto
        {
            Disposition = new ThreatDispositionDto { Classification = "ManualReviewRequired" },
            AnalysisCompleteness = new AnalysisCompletenessDto { IsComplete = false, Reasons = new() {
                new AnalysisCompletenessReasonDto { ReasonId = "scanner-incomplete", RuleId = "MethodScanWarning" },
                new AnalysisCompletenessReasonDto { ReasonId = "scanner-incomplete", RuleId = "MethodScanWarning" },
                new AnalysisCompletenessReasonDto { ReasonId = "scanner-incomplete", RuleId = "private-canary" } } },
            Findings = new() { new FindingDto { RuleId = "AssemblyScanner", Severity = "Medium", Visibility = "Default" } }
        };
        var summary = new ScanDiagnosticSummary(); summary.Observe(result);
        var projection = summary.Snapshot();
        Assert.Equal(1, projection["incomplete_MethodScanWarning_count"]);
        Assert.Equal(1, projection["incomplete_other_count"]);
        Assert.Equal(1, projection["rule_AssemblyScanner_Medium_Default_ManualReviewRequired_findings"]);
        Assert.DoesNotContain("private-canary", JsonSerializer.Serialize(projection));
    }

    [Fact]
    public void HostFindingIdsAreAllowlistedValidatedAndCopied()
    {
        var summary = new ScanDiagnosticSummary(new[] { "OversizedAssembly" });
        summary.Observe(new ScanResultDto { AnalysisCompleteness = new AnalysisCompletenessDto { IsComplete = false,
            Reasons = new() { new AnalysisCompletenessReasonDto { RuleId = "OversizedAssembly" } } } });
        var copy = summary.Copy();
        copy.Observe(new ScanResultDto { AnalysisCompleteness = new AnalysisCompletenessDto { IsComplete = false,
            Reasons = new() { new AnalysisCompletenessReasonDto { RuleId = "OversizedAssembly" } } } });
        Assert.Equal(2, copy.Snapshot()["incomplete_OversizedAssembly_count"]);
        Assert.Throws<ArgumentException>(() => new ScanDiagnosticSummary(new[] { "bad_id" }));
        Assert.Throws<ArgumentException>(() => new ScanDiagnosticSummary(new[] { "1Bad" }));
    }

    [SkippableTheory]
    [InlineData("FALSE_POSITIVES", "Polyfill.Boot.dll")]
    [InlineData("FALSE_POSITIVES", "BoneLibUpdater.dll")]
    [InlineData("QUARANTINE", "RandomSkins.dll.di")]
    [InlineData("QUARANTINE", "ScheduleIMoreNpcs.dll.di")]
    [InlineData("BENIGN_CANDIDATES", "LethalNetworkAPI.dll")]
    [InlineData("BENIGN_CANDIDATES", "BankApp.dll")]
    public void CorpusProjectionRetainsDispositionWithoutSendingIdentity(string corpus, string basename)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !Directory.Exists(Path.Combine(root.FullName, corpus))) root = root.Parent;
        Skip.If(root == null, $"Optional local corpus {corpus} is not available.");
        var path = Directory.EnumerateFiles(Path.Combine(root!.FullName, corpus), basename, SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal).FirstOrDefault();
        Skip.If(path == null, $"Optional corpus sample {basename} is not available.");
        // Cecil static analysis only; sample assemblies are never loaded or executed.
        var findings = new AssemblyScanner(RuleFactory.CreateDefaultRules()).Scan(path).ToList();
        var result = ScanResultMapper.ToDto(findings, basename, File.ReadAllBytes(path));
        var summary = new ScanDiagnosticSummary(); summary.Observe(result);
        var projection = summary.Snapshot();
        Assert.Equal(1, projection["fresh_result_count"]);
        var json = JsonSerializer.Serialize(projection);
        Assert.DoesNotContain(basename, json);
        Assert.DoesNotContain(result.Input.Sha256Hash, json);
        Assert.DoesNotContain(root.FullName, json);
        Assert.Equal(result.Findings.Count, projection.Where(p => p.Key.StartsWith("rule_") && p.Key.EndsWith("_findings")).Sum(p => p.Value));
        Assert.Equal(result.AnalysisCompleteness.IsComplete ? 1 : 0, projection.GetValueOrDefault("complete_result_count"));
    }
}
