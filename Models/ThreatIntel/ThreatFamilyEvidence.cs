namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Evidence captured while classifying a scan into a malware family.
/// </summary>
public sealed class ThreatFamilyEvidence
{
    public string Kind { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string? RuleId { get; set; }
    public string? Location { get; set; }
    public string? CallChainId { get; set; }
    public string? DataFlowChainId { get; set; }
    public string? Pattern { get; set; }
    public string? MethodLocation { get; set; }
    public double? Confidence { get; set; }
}
