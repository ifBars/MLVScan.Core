namespace MLVScan.Models.Dto;

/// <summary>
/// Malware family classification attached to a scan.
/// </summary>
public class ThreatFamilyDto
{
    public string FamilyId { get; set; } = string.Empty;
    public string VariantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string MatchKind { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public bool ExactHashMatch { get; set; }
    public List<string> MatchedRules { get; set; } = new();
    public List<string> AdvisorySlugs { get; set; } = new();
    public List<ThreatFamilyEvidenceDto> Evidence { get; set; } = new();
}
