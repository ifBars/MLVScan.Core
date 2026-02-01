namespace MLVScan.Models.Dto;

/// <summary>
/// Individual finding DTO.
/// </summary>
public class FindingDto
{
    /// <summary>
    /// Unique identifier for this finding (optional, for UI tracking).
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Rule ID that generated this finding (e.g., "Base64Rule").
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Human-readable description.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Severity: "Low", "Medium", "High", or "Critical".
    /// </summary>
    public string Severity { get; set; } = "Low";

    /// <summary>
    /// Location (e.g., "ClassName::MethodName").
    /// </summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// Optional code snippet showing the suspicious code.
    /// </summary>
    public string? CodeSnippet { get; set; }

    /// <summary>
    /// Optional call chain reference (ID or inline).
    /// </summary>
    public CallChainDto? CallChain { get; set; }

    /// <summary>
    /// Optional data flow chain reference.
    /// </summary>
    public DataFlowChainDto? DataFlowChain { get; set; }
}
