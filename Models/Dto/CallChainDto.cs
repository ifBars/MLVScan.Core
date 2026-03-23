namespace MLVScan.Models.Dto;

/// <summary>
/// Serialized call chain that shows how a suspicious declaration is reached.
/// </summary>
public class CallChainDto
{
    /// <summary>
    /// Optional stable identifier for the call chain.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Rule identifier that produced the chain.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Human-readable description of the chain or attack pattern.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Severity of the overall chain, serialized as a string label.
    /// </summary>
    public string Severity { get; set; } = "Low";

    /// <summary>
    /// Ordered nodes from entry point to suspicious declaration.
    /// </summary>
    public List<CallChainNodeDto> Nodes { get; set; } = new();
}
