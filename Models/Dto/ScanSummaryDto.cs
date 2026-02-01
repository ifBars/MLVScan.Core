namespace MLVScan.Models.Dto;

/// <summary>
/// Summary statistics of the scan.
/// </summary>
public class ScanSummaryDto
{
    /// <summary>
    /// Total number of findings.
    /// </summary>
    public int TotalFindings { get; set; }

    /// <summary>
    /// Count by severity level.
    /// </summary>
    public Dictionary<string, int> CountBySeverity { get; set; } = new();

    /// <summary>
    /// Unique rule IDs that were triggered.
    /// </summary>
    public List<string> TriggeredRules { get; set; } = new();
}
