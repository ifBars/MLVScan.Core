namespace MLVScan.Models.Dto;

/// <summary>
/// Malware family classification attached to a scan.
/// </summary>
/// <remarks>
/// Threat families provide the named, user-facing layer above individual rules. A family match can
/// combine exact sample hashes, rule identifiers, data-flow evidence, call-chain evidence, and
/// advisory links.
/// </remarks>
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
    /// Gets or sets the match type reported by the classifier.
    /// </summary>
    /// <remarks>
    /// Values are serialized from <see cref="MLVScan.Models.ThreatIntel.ThreatMatchKind"/>. Exact
    /// hash matches identify previously confirmed samples; behavior matches identify correlated
    /// scanner evidence.
    /// </remarks>
    public string MatchKind { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the confidence score for the match, normalized from 0.0 to 1.0.
    /// </summary>
    /// <remarks>
    /// Confidence is classifier evidence strength, not a probability that the file is safe or
    /// unsafe. Use <see cref="ScanResultDto.Disposition"/> for the final verdict.
    /// </remarks>
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
