namespace MLVScan.Models.Dto;

/// <summary>
/// Evidence supporting a malware family match.
/// </summary>
/// <remarks>
/// Evidence records are explanatory anchors for a family match. They may point to a rule, a
/// location, a call chain, a data-flow chain, or a named pattern depending on how the classifier
/// matched the family.
/// </remarks>
public class ThreatFamilyEvidenceDto
{
    /// <summary>
    /// Gets or sets the evidence category.
    /// </summary>
    /// <remarks>
    /// Examples include rule evidence, pattern evidence, exact-hash evidence, call-chain evidence,
    /// and data-flow evidence. Consumers should display unknown future categories as explanatory
    /// text rather than rejecting the payload.
    /// </remarks>
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
    /// Gets or sets an optional confidence score for this individual evidence record.
    /// </summary>
    /// <remarks>
    /// The value is normalized from 0.0 to 1.0 when present. It contributes to family explanation,
    /// but does not replace the aggregate <see cref="ThreatFamilyDto.Confidence"/> value.
    /// </remarks>
    public double? Confidence { get; set; }
}
