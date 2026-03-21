namespace MLVScan.Models.Dto;

/// <summary>
/// Malware family classification attached to a scan.
/// </summary>
public class ThreatFamilyDto
{
    /// <summary>
    /// Stable identifier for the malware family.
    /// </summary>
    public string FamilyId { get; set; } = string.Empty;

    /// <summary>
    /// Stable identifier for the specific behavior or sample variant within the family.
    /// </summary>
    public string VariantId { get; set; } = string.Empty;

    /// <summary>
    /// User-facing family name.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Short human-readable summary of the family behavior.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Match type reported by the classifier, for example exact hash or behavior pattern.
    /// </summary>
    public string MatchKind { get; set; } = string.Empty;

    /// <summary>
    /// Confidence score for the match, normalized between 0 and 1.
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// True when the scanned file exactly matches a previously confirmed malicious sample hash.
    /// </summary>
    public bool ExactHashMatch { get; set; }

    /// <summary>
    /// Rule identifiers that contributed to the family match.
    /// </summary>
    public List<string> MatchedRules { get; set; } = new();

    /// <summary>
    /// Advisory slugs associated with the family for downstream linking.
    /// </summary>
    public List<string> AdvisorySlugs { get; set; } = new();

    /// <summary>
    /// Evidence records that explain why the classifier attached this family to the scan.
    /// </summary>
    public List<ThreatFamilyEvidenceDto> Evidence { get; set; } = new();
}
