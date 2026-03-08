using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

internal sealed class ThreatFamilyDefinition
{
    public string FamilyId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<string> AdvisorySlugs { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> ExactSampleHashes { get; set; } = Array.Empty<string>();
    public IReadOnlyList<ThreatFamilyVariantDefinition> Variants { get; set; } = Array.Empty<ThreatFamilyVariantDefinition>();
}

internal sealed class ThreatFamilyVariantDefinition
{
    public string VariantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public Func<IReadOnlyList<ScanFinding>, ThreatFamilyVariantMatch?> Matcher { get; set; } = _ => null;
}

internal sealed class ThreatFamilyVariantMatch
{
    public IReadOnlyList<string> MatchedRules { get; set; } = Array.Empty<string>();
    public IReadOnlyList<ThreatFamilyEvidence> Evidence { get; set; } = Array.Empty<ThreatFamilyEvidence>();
}
