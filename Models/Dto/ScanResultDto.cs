namespace MLVScan.Models.Dto;

/// <summary>
/// Root scan result DTO that matches the shared JSON schema v1.
/// This is the primary output format for all MLVScan implementations (CLI, WASM, Server, Desktop).
/// </summary>
public class ScanResultDto
{
    /// <summary>
    /// Schema version for backward compatibility (semver).
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
    /// Summary statistics of the scan.
    /// </summary>
    public ScanSummaryDto Summary { get; set; } = new();

    /// <summary>
    /// All individual findings.
    /// </summary>
    public List<FindingDto> Findings { get; set; } = new();

    /// <summary>
    /// Optional: Call chains showing attack paths.
    /// Only present when cross-method analysis is enabled.
    /// </summary>
    public List<CallChainDto>? CallChains { get; set; }

    /// <summary>
    /// Optional: Data flow chains showing data movement through suspicious operations.
    /// Only present when data flow analysis is enabled.
    /// </summary>
    public List<DataFlowChainDto>? DataFlows { get; set; }

    /// <summary>
    /// Optional: Developer guidance for remediation.
    /// Only present when developer mode is enabled.
    /// </summary>
    public List<DeveloperGuidanceDto>? DeveloperGuidance { get; set; }
}
