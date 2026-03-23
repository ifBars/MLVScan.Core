namespace MLVScan.Models.Dto;

/// <summary>
/// Root scan result object that matches the shared JSON schema.
/// </summary>
public class ScanResultDto
{
    /// <summary>
    /// Schema version for backward compatibility.
    /// </summary>
    public string SchemaVersion { get; set; } = MLVScanVersions.SchemaVersion;

    /// <summary>
    /// Metadata about the scan execution.
    /// </summary>
    public ScanMetadataDto Metadata { get; set; } = new();

    /// <summary>
    /// Information about the scanned input.
    /// </summary>
    public ScanInputDto Input { get; set; } = new();

    /// <summary>
    /// Summary statistics for the scan.
    /// </summary>
    public ScanSummaryDto Summary { get; set; } = new();

    /// <summary>
    /// Individual findings emitted by the scanner.
    /// </summary>
    public List<FindingDto> Findings { get; set; } = new();

    /// <summary>
    /// Optional call-chain expansions included when cross-method analysis is enabled.
    /// </summary>
    public List<CallChainDto>? CallChains { get; set; }

    /// <summary>
    /// Optional data-flow expansions included when data-flow analysis is enabled.
    /// </summary>
    public List<DataFlowChainDto>? DataFlows { get; set; }

    /// <summary>
    /// Optional developer guidance included when developer mode is enabled.
    /// </summary>
    public List<DeveloperGuidanceDto>? DeveloperGuidance { get; set; }

    /// <summary>
    /// Optional malware-family classifications derived from threat-intel matching.
    /// </summary>
    public List<ThreatFamilyDto>? ThreatFamilies { get; set; }

    /// <summary>
    /// Optional primary disposition derived from threat-intel correlation.
    /// </summary>
    public ThreatDispositionDto? Disposition { get; set; }
}
