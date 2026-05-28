namespace MLVScan.Models.Dto;

/// <summary>
/// A structured reason explaining why analysis was partial or incomplete.
/// </summary>
public class AnalysisCompletenessReasonDto
{
    /// <summary>
    /// Stable reason identifier for consumers and tests.
    /// </summary>
    public string ReasonId { get; set; } = string.Empty;

    /// <summary>
    /// Short human-readable summary of the limitation.
    /// </summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>
    /// Scanner phase or component associated with the limitation.
    /// </summary>
    public string? Phase { get; set; }

    /// <summary>
    /// Rule identifier that emitted the source warning, when available.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Location associated with the limitation.
    /// </summary>
    public string? Location { get; set; }
}
