namespace MLVScan.Models.Dto;

/// <summary>
/// Single node in a serialized data-flow chain.
/// </summary>
public class DataFlowNodeDto
{
    /// <summary>
    /// Node type label, such as <c>Source</c>, <c>Transform</c>, <c>Sink</c>, or <c>Intermediate</c>.
    /// </summary>
    public string NodeType { get; set; } = string.Empty;

    /// <summary>
    /// Location of the operation, typically formatted as method name plus IL offset.
    /// </summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// Operation name or API label associated with the node.
    /// </summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>
    /// Description of the data as it moves through the flow.
    /// </summary>
    public string DataDescription { get; set; } = string.Empty;

    /// <summary>
    /// IL instruction offset for the operation.
    /// </summary>
    public int InstructionOffset { get; set; }

    /// <summary>
    /// Optional method key used when the flow spans multiple methods.
    /// </summary>
    public string? MethodKey { get; set; }

    /// <summary>
    /// Indicates whether the node is a method boundary that forwards data to another method.
    /// </summary>
    public bool IsMethodBoundary { get; set; }

    /// <summary>
    /// Optional target method key when this node represents a method boundary.
    /// </summary>
    public string? TargetMethodKey { get; set; }

    /// <summary>
    /// Optional source snippet captured for the node.
    /// </summary>
    public string? CodeSnippet { get; set; }
}
