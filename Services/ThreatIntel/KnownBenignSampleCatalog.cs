using MLVScan.Models;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Records exact, manually reviewed benign samples whose static behavior would otherwise require review.
/// </summary>
internal static class KnownBenignSampleCatalog
{
    private const string BoneLibUpdaterSha256 =
        "BAE327FACB187856E98F4A7997630762BAF0FE73962AAA0EEDB19F8235A9EA81";

    /// <summary>
    /// Returns whether the exact sample and all of its retained High+ evidence match a reviewed benign profile.
    /// </summary>
    public static bool MatchesReviewedBehavior(string? sha256Hash, IReadOnlyList<ScanFinding> findings)
    {
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
