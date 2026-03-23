namespace MLVScan.Models.Dto;

/// <summary>
/// Single node in a serialized call chain.
/// </summary>
public class CallChainNodeDto
{
    /// <summary>
    /// Node type label, such as <c>EntryPoint</c>, <c>IntermediateCall</c>, or <c>SuspiciousDeclaration</c>.
    /// </summary>
    public string NodeType { get; set; } = string.Empty;

    /// <summary>
    /// Location of the node, typically a method signature or declaration reference.
    /// </summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// Short explanation of what the node contributes to the call chain.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Optional source snippet captured for the node.
    /// </summary>
    public string? CodeSnippet { get; set; }
}
