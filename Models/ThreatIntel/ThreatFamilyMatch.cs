namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Represents a malware family classification attached to a scan.
/// </summary>
public sealed class ThreatFamilyMatch
{
    public string FamilyId { get; set; } = string.Empty;
    public string VariantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public ThreatMatchKind MatchKind { get; set; }
    public double Confidence { get; set; }
    public bool ExactHashMatch { get; set; }
    public List<string> MatchedRules { get; set; } = new();
    public List<string> AdvisorySlugs { get; set; } = new();
    public List<ThreatFamilyEvidence> Evidence { get; set; } = new();
}
