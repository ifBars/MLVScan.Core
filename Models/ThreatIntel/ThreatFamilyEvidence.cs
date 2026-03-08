namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Evidence captured while classifying a scan into a malware family.
/// </summary>
public sealed class ThreatFamilyEvidence
{
    public string Kind { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}
