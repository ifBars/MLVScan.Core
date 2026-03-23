namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Malware family classification attached to a scan.
/// </summary>
public sealed class ThreatFamilyMatch
{
    /// <summary>
    /// Stable identifier for the malware family.
    /// </summary>
    public string FamilyId { get; set; } = string.Empty;

    /// <summary>
    /// Stable identifier for the specific variant within the family.
    /// </summary>
    public string VariantId { get; set; } = string.Empty;

    /// <summary>
    /// Human-facing family name.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Short summary of the family behavior.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Match type reported by the classifier, such as exact hash or behavior variant.
    /// </summary>
    public ThreatMatchKind MatchKind { get; set; }

    /// <summary>
    /// Confidence score for the match, normalized between 0 and 1.
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// Indicates whether the scanned file exactly matched a confirmed malicious sample hash.
    /// </summary>
    public bool ExactHashMatch { get; set; }

    /// <summary>
    /// Rule identifiers that contributed to the family match.
    /// </summary>
    public List<string> MatchedRules { get; set; } = new();

    /// <summary>
    /// Advisory slugs associated with the family.
    /// </summary>
    public List<string> AdvisorySlugs { get; set; } = new();

    /// <summary>
    /// Evidence records explaining why the classifier attached this family.
    /// </summary>
    public List<ThreatFamilyEvidence> Evidence { get; set; } = new();
}
