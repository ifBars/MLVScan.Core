namespace MLVScan.Models.Dto;

/// <summary>
/// Primary disposition for the scanned file after family and correlated-behavior analysis.
/// </summary>
public class ThreatDispositionDto
{
    public string Classification { get; set; } = string.Empty;

    public string Headline { get; set; } = string.Empty;

    public string Summary { get; set; } = string.Empty;

    public bool BlockingRecommended { get; set; }

    public string? PrimaryThreatFamilyId { get; set; }

    public List<string> RelatedFindingIds { get; set; } = new();
}
