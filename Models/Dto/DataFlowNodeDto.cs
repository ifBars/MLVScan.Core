namespace MLVScan.Models.Dto;

/// <summary>
/// Single node in a data flow chain.
/// </summary>
public class DataFlowNodeDto
{
    /// <summary>
    /// Node type: "Source", "Transform", "Sink", or "Intermediate".
    /// </summary>
    public string NodeType { get; set; } = string.Empty;

    /// <summary>
    /// Location of this operation (method:offset).
    /// </summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// The operation being performed (e.g., "Base64.FromBase64String", "File.WriteAllBytes").
    /// </summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>
    /// Description of the data at this point (e.g., "byte[] (encoded payload)", "string URL").
    /// </summary>
    public string DataDescription { get; set; } = string.Empty;

    /// <summary>
    /// IL instruction offset.
    /// </summary>
    public int InstructionOffset { get; set; }

    /// <summary>
    /// The method key where this node occurs (for cross-method tracking).
    /// </summary>
    public string? MethodKey { get; set; }

    /// <summary>
    /// Whether this node represents a method call that passes data to another method.
    /// </summary>
    public bool IsMethodBoundary { get; set; }

    /// <summary>
    /// For method boundary nodes, the target method being called.
    /// </summary>
    public string? TargetMethodKey { get; set; }

    /// <summary>
    /// Optional code snippet.
    /// </summary>
    public string? CodeSnippet { get; set; }
}
