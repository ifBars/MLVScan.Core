namespace MLVScan.Models.Dto;

/// <summary>
/// Evidence supporting a malware family match.
/// </summary>
public class ThreatFamilyEvidenceDto
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
