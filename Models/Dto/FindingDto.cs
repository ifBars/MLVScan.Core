namespace MLVScan.Models.Dto;

/// <summary>
/// Individual finding in the serialized scan result.
/// </summary>
/// <remarks>
/// Findings are low-level scanner signals. They explain what a rule observed, but the primary
/// file-level verdict is exposed through <see cref="ScanResultDto.Disposition"/> after threat-family
/// and disposition correlation.
/// </remarks>
public class FindingDto
{
    /// <summary>
    /// Gets or sets an identifier generated for this serialized result.
    /// </summary>
    /// <remarks>
    /// The identifier is stable within one payload and is used by related fields such as
    /// <see cref="ThreatDispositionDto.RelatedFindingIds"/>. Consumers should not treat it as a
    /// durable identifier across separate scans.
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// Gets or sets the stable rule identifier that produced the finding.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Human-readable description of the suspicious behavior.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Severity label serialized as <c>Low</c>, <c>Medium</c>, <c>High</c>, or <c>Critical</c>.
    /// </summary>
    public string Severity { get; set; } = "Low";

    /// <summary>
    /// Location string for display, typically a type and method signature or a metadata path.
    /// </summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// Optional source snippet showing the triggering IL or source-like context.
    /// </summary>
    public string? CodeSnippet { get; set; }

    /// <summary>
    /// Optional numeric score emitted by rules that use scoring models.
    /// </summary>
    public int? RiskScore { get; set; }

    /// <summary>
    /// Optional identifier of the related call chain.
    /// </summary>
    public string? CallChainId { get; set; }

    /// <summary>
    /// Optional identifier of the related data flow chain.
    /// </summary>
    public string? DataFlowChainId { get; set; }

    /// <summary>
    /// Optional developer guidance attached directly to the finding.
    /// </summary>
    public DeveloperGuidanceDto? DeveloperGuidance { get; set; }

    /// <summary>
    /// Optional inline call-chain payload for consumers that want a fully expanded result.
    /// </summary>
    public CallChainDto? CallChain { get; set; }

    /// <summary>
    /// Optional inline data-flow payload for consumers that want a fully expanded result.
    /// </summary>
    public DataFlowChainDto? DataFlowChain { get; set; }

    /// <summary>
    /// Gets or sets the visibility tier used by consumers to choose default or advanced display.
    /// </summary>
    /// <remarks>
    /// Findings that directly support the retained disposition are marked as default visibility.
    /// Supporting diagnostics that did not drive the final verdict may be marked advanced so user
    /// interfaces can stay concise without losing forensic detail.
    /// </remarks>
    public string? Visibility { get; set; }
}
