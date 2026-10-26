using FluentAssertions;
using FluentAssertions.Execution;
using MLVScan.Models.Dto;

namespace MLVScan.Core.Tests.TestUtilities;

// Test expectations only. These entries never suppress production findings or change a verdict.
internal static class FalsePositiveBacklog
{
    internal sealed record HighFinding(string RuleId, string Severity, string Location);

    internal sealed record Entry(string Id, string Sha256, string Disposition, string Reason,
        params HighFinding[] HighFindings);

    internal static IReadOnlyDictionary<string, Entry> Entries { get; } = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase)
    {
        ["BackpackInventoryQoL.dll"] = new("FP-001",
            "F3E5203638FAC1A7BF62814158D2DA11DB97F85E0F0A417A522CD7BC153A7156", "Clean",
            "Opening the framework-provided Mods folder is unresolved and retains a High process primitive.",
            new HighFinding("ProcessStartRule", "High", "Backpack.Compatibility.LegacyConflictGuard.OpenModsFolder:27")),
        ["Polyfill.Boot.dll"] = new("FP-002",
            "E451A9A795B1333422826C552FDF3EEF651457A48EE9271374336FB8A2CC0535", "Clean",
            "Local compatibility assembly probing retains a High dynamic-load primitive.",
            new HighFinding("AssemblyDynamicLoadRule", "High", "Polyfill.Dynamic.ReflectionFallback.BySimpleName:211")),
        ["Polyfill.dll"] = new("FP-003",
            "D0DB33DDA7C1ADC7B5EB2A32694B629F8D9F0DFBC69504B8772EA57A46A26254", "Clean",
            "Diagnostic member probes retain dynamic-load and reflection primitives without a suspicious disposition.",
            new("AssemblyDynamicLoadRule", "High", "Polyfill.Report.ConsoleCommands.Probe:260"),
            new("AssemblyDynamicLoadRule", "High", "Polyfill.Report.ConsoleCommands.ProbeMember:40"),
            new("ReflectionRule", "High", "Polyfill.Report.ConsoleCommands.ProbeMember:846"),
            new("ReflectionRule", "High", "Polyfill.Report.ConsoleCommands.ProbeMember:1086"),
            new("ReflectionRule", "High", "Polyfill.Report.ConsoleCommands.ProbeMember:1098")),
        ["Nexus Bannerlord/ButterLib-2.12.0/Modules/Bannerlord.ButterLib/bin/Win64_Shipping_Client/BUTR.CrashReport.dll"] = new("FP-004",
            "2934404B80FA2506191ABE21A822D2992B614E5EC24440BB5A0D40752F6C2B48", "ManualReviewRequired",
            "Cross-method data-flow analysis reaches its bounded work limit; a Clean verdict is not currently supported.")
    };

    internal static bool TryGet(string relativePath, out Entry entry) =>
        Entries.TryGetValue(relativePath.Replace('\\', '/'), out entry!);

    internal static void AssertExpectedProfile(ScanResultDto result, Entry entry)
    {
        using var scope = new AssertionScope($"{entry.Id}: {entry.Reason} See FALSE_POSITIVE_BACKLOG.md");
        result.Input.Sha256Hash.Should().Be(entry.Sha256.ToLowerInvariant(), "changed corpus bytes require a fresh review");
        result.Disposition.Should().NotBeNull();
        result.Disposition!.Classification.Should().Be(entry.Disposition, "a changed verdict must update or retire this backlog entry");
        result.ThreatFamilies.Should().BeNullOrEmpty("a backlog entry must not hide a new malware-family match");

        var highFindings = result.Findings.Where(finding => finding.Severity is "High" or "Critical").ToList();
        highFindings.Select(finding => new HighFinding(finding.RuleId ?? string.Empty, finding.Severity, finding.Location))
            .Should().BeEquivalentTo(entry.HighFindings, "only the documented High findings are expected");
        highFindings.Should().OnlyContain(finding => finding.Visibility == "Advanced");

        bool expectsCompleteAnalysis = entry.Disposition == "Clean";
        result.Disposition.BlockingRecommended.Should().Be(!expectsCompleteAnalysis);
        result.AnalysisCompleteness.IsComplete.Should().Be(expectsCompleteAnalysis);
        result.AnalysisCompleteness.ReviewRecommended.Should().Be(!expectsCompleteAnalysis);
        if (expectsCompleteAnalysis)
        {
            result.AnalysisCompleteness.Status.Should().Be("Complete");
            result.AnalysisCompleteness.Reasons.Should().BeEmpty();
        }
        else
        {
            result.AnalysisCompleteness.Status.Should().Be("Partial");
            var reason = result.AnalysisCompleteness.Reasons.Should().ContainSingle().Which;
            reason.ReasonId.Should().Be("scanner-incomplete");
            reason.RuleId.Should().Be("DataFlowScanWarning");
            reason.Location.Should().Be("Cross-method data flow analysis");
            reason.Summary.Should().Contain("bounded work limit");
        }
    }
}
