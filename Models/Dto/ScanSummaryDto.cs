namespace MLVScan.Models.Dto;

/// <summary>
/// Summary statistics for a scan result.
/// </summary>
public class ScanSummaryDto
{
    /// <summary>
    /// Total number of findings in the scan.
    /// </summary>
    public int TotalFindings { get; set; }

    /// <summary>
    /// Counts grouped by severity label.
    /// </summary>
    public Dictionary<string, int> CountBySeverity { get; set; } = new();

    /// <summary>
    /// Unique rule identifiers that were triggered during the scan.
    /// </summary>
    public List<string> TriggeredRules { get; set; } = new();
}
