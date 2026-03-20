using MLVScan.Models;

namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Primary threat disposition for a scan, with the findings that support it.
/// </summary>
public sealed class ThreatDispositionResult
{
    public ThreatDispositionClassification Classification { get; set; }

    public string Headline { get; set; } = string.Empty;

    public string Summary { get; set; } = string.Empty;

    public bool BlockingRecommended { get; set; }

    public string? PrimaryThreatFamilyId { get; set; }

    public ThreatFamilyMatch? PrimaryThreatFamily { get; set; }

    public List<ScanFinding> RelatedFindings { get; set; } = new();
}
