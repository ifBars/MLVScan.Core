namespace MLVScan.Models.Dto;

/// <summary>
/// Evidence supporting a malware family match.
/// </summary>
public class ThreatFamilyEvidenceDto
{
    /// <summary>
    /// Evidence category, such as rule, pattern, or execution path metadata.
    /// </summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable evidence value.
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// Rule identifier associated with this evidence, when available.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Method or location string associated with the evidence.
    /// </summary>
    public string? Location { get; set; }

    /// <summary>
    /// Call-chain identifier associated with the evidence, when available.
    /// </summary>
    public string? CallChainId { get; set; }

    /// <summary>
    /// Data-flow identifier associated with the evidence, when available.
    /// </summary>
    public string? DataFlowChainId { get; set; }

    /// <summary>
    /// Named pattern associated with the evidence, when available.
    /// </summary>
    public string? Pattern { get; set; }

    /// <summary>
    /// Method location that produced the family evidence, when available.
    /// </summary>
    public string? MethodLocation { get; set; }

    /// <summary>
    /// Optional confidence score for this individual evidence record.
    /// </summary>
    public double? Confidence { get; set; }
}
