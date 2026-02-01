namespace MLVScan.Models.Dto;

/// <summary>
/// Developer guidance for remediation.
/// </summary>
public class DeveloperGuidanceDto
{
    /// <summary>
    /// Rule ID this guidance applies to.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Remediation advice.
    /// </summary>
    public string Remediation { get; set; } = string.Empty;

    /// <summary>
    /// Optional documentation URL.
    /// </summary>
    public string? DocumentationUrl { get; set; }

    /// <summary>
    /// Alternative APIs to use instead.
    /// </summary>
    public string[]? AlternativeApis { get; set; }

    /// <summary>
    /// Whether this issue is remediable.
    /// </summary>
    public bool IsRemediable { get; set; }
}
