namespace MLVScan.Models.Dto;

/// <summary>
/// Primary disposition for the scanned file after threat-intel correlation.
/// </summary>
/// <remarks>
/// This is the file-level product verdict. It may be based on retained rule findings, matched
/// threat-family evidence, or exact known-sample hashes.
/// </remarks>
public class ThreatDispositionDto
{
    /// <summary>
    /// Gets or sets the final classification for the file.
    /// </summary>
    /// <remarks>
    /// Current values are serialized from <see cref="MLVScan.Models.ThreatIntel.ThreatDispositionClassification"/>.
    /// Consumers should handle unknown future values conservatively.
    /// </remarks>
    public string Classification { get; set; } = string.Empty;

    /// <summary>
    /// Short headline suitable for the main verdict banner in a UI or report.
    /// </summary>
    public string Headline { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable summary explaining why this disposition was chosen.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether consumers should block or fail on this result by default.
    /// </summary>
    /// <remarks>
    /// This flag is the host-facing policy recommendation from Core. Hosts may apply their own
    /// consent or override workflows, but they should not infer blocking from severity labels alone.
    /// </remarks>
    public bool BlockingRecommended { get; set; }

    /// <summary>
    /// Identifier for the primary matched threat family, when the disposition is a known threat.
    /// </summary>
    public string? PrimaryThreatFamilyId { get; set; }

    /// <summary>
    /// Gets or sets identifiers of the findings that directly support the retained disposition.
    /// </summary>
    /// <remarks>
    /// Exact known-hash matches can produce a known-threat disposition without a one-to-one
    /// supporting rule finding. In that case this list may be empty even when blocking is
    /// recommended.
    /// </remarks>
    public List<string> RelatedFindingIds { get; set; } = new();
}
