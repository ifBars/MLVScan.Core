using MLVScan.Models;

namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Describes whether scanner analysis completed enough to trust a clean result.
/// </summary>
public sealed class AnalysisCompletenessResult
{
    /// <summary>
    /// Gets or sets the overall completeness status.
    /// </summary>
    public AnalysisCompletenessStatus Status { get; set; } = AnalysisCompletenessStatus.Complete;

    /// <summary>
    /// Gets or sets whether analysis completed without retained limitations.
    /// </summary>
    public bool IsComplete { get; set; } = true;

    /// <summary>
    /// Gets or sets whether a human should review the result before treating it as clean.
    /// </summary>
    public bool ReviewRecommended { get; set; }

    /// <summary>
    /// Gets or sets the findings that explain why analysis was not complete.
    /// </summary>
    public List<ScanFinding> RelatedFindings { get; set; } = new();

    /// <summary>
    /// Gets or sets structured reasons for the completeness status.
    /// </summary>
    public List<AnalysisCompletenessReason> Reasons { get; set; } = new();
}
