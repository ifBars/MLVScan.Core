namespace MLVScan.Models.Dto;

/// <summary>
/// Individual finding in the serialized scan result.
/// </summary>
public class FindingDto
{
    /// <summary>
    /// Optional stable identifier used by UIs to track or de-duplicate a finding.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Stable rule identifier that produced the finding.
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
    /// Visibility tier used by consumers to hide advanced diagnostics from default views.
    /// </summary>
    public string? Visibility { get; set; }
}
