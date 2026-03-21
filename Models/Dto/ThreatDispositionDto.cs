namespace MLVScan.Models.Dto;

/// <summary>
/// Primary disposition for the scanned file after family and correlated-behavior analysis.
/// </summary>
public class ThreatDispositionDto
{
    /// <summary>
    /// Final classification for the file, such as Clean, Suspicious, or KnownThreat.
    /// </summary>
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
    /// Indicates whether consumers should block or fail on this result by default.
    /// </summary>
    public bool BlockingRecommended { get; set; }

    /// <summary>
    /// Family identifier for the primary matched threat family, when the disposition is a known threat.
    /// </summary>
    public string? PrimaryThreatFamilyId { get; set; }

    /// <summary>
    /// Identifiers of the findings that directly support the retained disposition.
    /// </summary>
    public List<string> RelatedFindingIds { get; set; } = new();
}
