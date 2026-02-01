namespace MLVScan.Models.Dto;

/// <summary>
/// Data flow chain showing data movement.
/// </summary>
public class DataFlowChainDto
{
    /// <summary>
    /// Unique identifier for this data flow.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Description of the data flow pattern.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Severity of the entire flow.
    /// </summary>
    public string Severity { get; set; } = "Low";

    /// <summary>
    /// Recognized attack pattern (e.g., "DataExfiltration", "DownloadAndExecute").
    /// </summary>
    public string Pattern { get; set; } = "Unknown";

    /// <summary>
    /// Confidence score (0.0 - 1.0) in the pattern detection.
    /// </summary>
    public double Confidence { get; set; }

    /// <summary>
    /// The IL variable or stack slot being tracked (for debugging).
    /// </summary>
    public string? SourceVariable { get; set; }

    /// <summary>
    /// The method where this data flow occurs (primary method for single-method flows).
    /// </summary>
    public string? MethodLocation { get; set; }

    /// <summary>
    /// True if this data flow spans multiple methods.
    /// </summary>
    public bool IsCrossMethod { get; set; }

    /// <summary>
    /// All methods involved in this data flow (for cross-method flows).
    /// </summary>
    public List<string>? InvolvedMethods { get; set; }

    /// <summary>
    /// Nodes in the data flow (ordered).
    /// </summary>
    public List<DataFlowNodeDto> Nodes { get; set; } = new();
}
