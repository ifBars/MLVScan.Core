namespace MLVScan.Models.Dto;

/// <summary>
/// Structured values a rule resolved while producing a finding.
/// </summary>
public class FindingAttributesDto
{
    /// <summary>
    /// The resolved target the call acts on, such as a launched program or URL.
    /// </summary>
    public string? Target { get; set; }

    /// <summary>
    /// Neutral category of the target: Executable, Script, Url, Path, or Unresolved.
    /// </summary>
    public string? TargetKind { get; set; }

    /// <summary>
    /// Concrete values the scanner considered possible when the target is ambiguous.
    /// </summary>
    public List<string>? TargetCandidates { get; set; }

    /// <summary>
    /// The resolved arguments passed with the target, when present.
    /// </summary>
    public string? Arguments { get; set; }

    /// <summary>
    /// Machine-readable indicators observed at the call site, such as WindowStyle=Hidden.
    /// </summary>
    public List<string>? Indicators { get; set; }

    /// <summary>
    /// Short reason the rule used to choose the finding severity.
    /// </summary>
    public string? RiskReason { get; set; }
}
