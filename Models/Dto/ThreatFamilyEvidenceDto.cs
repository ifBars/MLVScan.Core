namespace MLVScan.Models.Dto;

/// <summary>
/// Evidence supporting a malware family match.
/// </summary>
public class ThreatFamilyEvidenceDto
{
    public string Kind { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}
