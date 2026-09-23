using MLVScan.Models;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Records exact, manually reviewed benign samples whose static behavior would otherwise require review.
/// </summary>
internal static class KnownBenignSampleCatalog
{
    private const string BoneLibUpdaterSha256 =
        "BAE327FACB187856E98F4A7997630762BAF0FE73962AAA0EEDB19F8235A9EA81";
    private const string DaffysHillsSha256 =
        "FC3E473DA2E2DBD9BB91F4794FCAC04C85316C0BD8B446AE75CFEBB45F35381B";

    /// <summary>
    /// Returns whether the exact sample and all of its retained High+ evidence match a reviewed benign profile.
    /// </summary>
    public static bool MatchesReviewedBehavior(string? sha256Hash, IReadOnlyList<ScanFinding> findings)
    {
        if (string.Equals(sha256Hash, DaffysHillsSha256, StringComparison.OrdinalIgnoreCase))
        {
            // The reviewed release includes a developer hot-reload path. Keep its findings visible,
            // and trust these exact bytes only while the retained High+ evidence is that local flow.
            var highFindings = findings.Where(finding => finding.Severity >= Severity.High).ToList();
            return highFindings.Count == 3 &&
                   highFindings.Count(finding =>
                       string.Equals(finding.RuleId, "DataFlowAnalysis", StringComparison.Ordinal) &&
                       finding.DataFlowChain?.Pattern == DataFlowPattern.DynamicCodeLoading &&
                       string.Equals(finding.Location, "ClifftopAccess.Core.RunDev", StringComparison.Ordinal)) == 1 &&
                   highFindings.Count(finding =>
                       string.Equals(finding.RuleId, "AssemblyDynamicLoadRule", StringComparison.Ordinal) &&
                       finding.Location.StartsWith("ClifftopAccess.Core.RunDev:", StringComparison.Ordinal)) == 1 &&
                   highFindings.Count(finding =>
                       string.Equals(finding.RuleId, "ReflectionRule", StringComparison.Ordinal) &&
                       finding.Location.StartsWith("ClifftopAccess.Core.RunDev:", StringComparison.Ordinal)) == 1;
        }

        if (!string.Equals(sha256Hash, BoneLibUpdaterSha256, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // BoneLibUpdater embeds its own updater executable, writes it locally, and launches it. Trust only
        // these exact bytes and only while every disposition-relevant finding remains that reviewed flow.
        return findings
            .Where(finding => finding.Severity >= Severity.High)
            .All(finding =>
                string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
                finding.DataFlowChain?.Pattern == DataFlowPattern.EmbeddedResourceDropAndExecute);
    }
}
