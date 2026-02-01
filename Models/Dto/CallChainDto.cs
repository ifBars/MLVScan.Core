namespace MLVScan.Models.Dto;

/// <summary>
/// Call chain showing an attack path.
/// </summary>
public class CallChainDto
{
    /// <summary>
    /// Unique identifier for this call chain.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The rule that detected this suspicious pattern.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Description of the attack pattern.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Severity of the entire chain.
    /// </summary>
    public string Severity { get; set; } = "Low";

    /// <summary>
    /// Nodes in the call chain (ordered).
    /// </summary>
    public List<CallChainNodeDto> Nodes { get; set; } = new();
}
