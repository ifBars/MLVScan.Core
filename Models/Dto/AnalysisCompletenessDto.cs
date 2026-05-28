using MLVScan.Models;

namespace MLVScan.Models.Dto;

/// <summary>
/// Shared contract section describing whether the scan completed enough to trust a clean result.
/// </summary>
public class AnalysisCompletenessDto
{
    /// <summary>
    /// Gets or sets the completeness status.
    /// </summary>
    public string Status { get; set; } = AnalysisCompletenessStatus.Complete.ToString();

    /// <summary>
    /// Gets or sets whether analysis completed without retained limitations.
    /// </summary>
    public bool IsComplete { get; set; } = true;

    /// <summary>
    /// Gets or sets whether consumers should show a manual-review warning.
    /// </summary>
    public bool ReviewRecommended { get; set; }

    /// <summary>
    /// Gets or sets structured reasons explaining incomplete or partial analysis.
    /// </summary>
    public List<AnalysisCompletenessReasonDto> Reasons { get; set; } = new();
}
