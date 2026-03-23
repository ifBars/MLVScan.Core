namespace MLVScan.Models.Dto;

/// <summary>
/// Developer guidance included in the serialized result when remediation details are requested.
/// </summary>
public class DeveloperGuidanceDto
{
    /// <summary>
    /// Rule identifier for single-rule guidance payloads.
    /// </summary>
    public string? RuleId { get; set; }

    /// <summary>
    /// Rule identifiers for aggregated guidance payloads.
    /// </summary>
    public List<string>? RuleIds { get; set; }

    /// <summary>
    /// Human-readable remediation guidance.
    /// </summary>
    public string Remediation { get; set; } = string.Empty;

    /// <summary>
    /// Optional documentation URL for the recommended approach.
    /// </summary>
    public string? DocumentationUrl { get; set; }

    /// <summary>
    /// Optional safer APIs or workflows that can be used instead.
    /// </summary>
    public string[]? AlternativeApis { get; set; }

    /// <summary>
    /// Indicates whether a practical safe alternative exists for the flagged pattern.
    /// </summary>
    public bool IsRemediable { get; set; }
}
