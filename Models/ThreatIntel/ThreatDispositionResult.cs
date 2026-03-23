using MLVScan.Models;

namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Final threat disposition together with the findings that support it.
/// </summary>
public sealed class ThreatDispositionResult
{
    /// <summary>
    /// Overall classification for the scanned file.
    /// </summary>
    public ThreatDispositionClassification Classification { get; set; }

    /// <summary>
    /// Short headline suitable for a verdict banner or CLI summary.
    /// </summary>
    public string Headline { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable explanation of why the disposition was assigned.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Indicates whether downstream consumers should block the file by default.
    /// </summary>
    public bool BlockingRecommended { get; set; }

    /// <summary>
    /// Identifier of the primary matched threat family, when one was identified.
    /// </summary>
    public string? PrimaryThreatFamilyId { get; set; }

    /// <summary>
    /// Primary matched family details, when available.
    /// </summary>
    public ThreatFamilyMatch? PrimaryThreatFamily { get; set; }

    /// <summary>
    /// Findings that directly support the retained disposition.
    /// </summary>
    public List<ScanFinding> RelatedFindings { get; set; } = new();
}
