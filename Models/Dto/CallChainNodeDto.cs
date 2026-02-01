namespace MLVScan.Models.Dto;

/// <summary>
/// Single node in a call chain.
/// </summary>
public class CallChainNodeDto
{
    /// <summary>
    /// Node type: "EntryPoint", "IntermediateCall", or "SuspiciousDeclaration".
    /// </summary>
    public string NodeType { get; set; } = string.Empty;

    /// <summary>
    /// Location of this node (method signature).
    /// </summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// Description of what happens at this node.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Optional code snippet at this node.
    /// </summary>
    public string? CodeSnippet { get; set; }
}
