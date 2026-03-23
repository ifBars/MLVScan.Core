namespace MLVScan.Models.Dto;

/// <summary>
/// Serialized data-flow chain that explains how data moves from source to sink.
/// </summary>
public class DataFlowChainDto
{
    /// <summary>
    /// Optional stable identifier for the data-flow chain.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Human-readable description of the data-flow pattern.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Severity of the overall flow, serialized as a string label.
    /// </summary>
    public string Severity { get; set; } = "Low";

    /// <summary>
    /// Recognized pattern name, such as <c>DataExfiltration</c> or <c>DownloadAndExecute</c>.
    /// </summary>
    public string Pattern { get; set; } = "Unknown";

    /// <summary>
    /// Optional variable or stack slot name used as the original source handle.
    /// </summary>
    public string? SourceVariable { get; set; }

    /// <summary>
    /// Primary method location for single-method flows.
    /// </summary>
    public string? MethodLocation { get; set; }

    /// <summary>
    /// Indicates whether the flow spans more than one method.
    /// </summary>
    public bool IsCrossMethod { get; set; }

    /// <summary>
    /// Indicates whether the flow matches a suspicious pattern.
    /// </summary>
    public bool IsSuspicious { get; set; }

    /// <summary>
    /// Number of methods traversed by the flow.
    /// </summary>
    public int CallDepth { get; set; }

    /// <summary>
    /// Optional ordered list of methods involved in the flow.
    /// </summary>
    public List<string>? InvolvedMethods { get; set; }

    /// <summary>
    /// Ordered nodes that describe the flow from source to sink.
    /// </summary>
    public List<DataFlowNodeDto> Nodes { get; set; } = new();
}
