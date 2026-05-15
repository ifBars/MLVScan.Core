namespace MLVScan.Models.Dto;

/// <summary>
/// Root scan result object that matches the shared JSON schema.
/// </summary>
/// <remarks>
/// This type is the stable interchange contract emitted by MLVScan.Core and consumed by the CLI,
/// WASM scanner, API, web UI, MCP server, and inspector tooling. Keep this model
/// environment-neutral: loader-specific policy, consent, and install behavior belongs in the
/// host that consumes the result, not in this shared DTO.
/// </remarks>
public class ScanResultDto
{
    /// <summary>
    /// Gets or sets the shared result schema version used to interpret this payload.
    /// </summary>
    /// <remarks>
    /// Consumers should use this value for compatibility checks before assuming that optional
    /// contract sections are present or have the latest shape.
    /// </remarks>
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
    /// Generic assembly metadata extracted from the scanned binary when available.
    /// </summary>
    public AssemblyMetadataDto? Assembly { get; set; }

    /// <summary>
    /// Summary statistics for the scan.
    /// </summary>
    public ScanSummaryDto Summary { get; set; } = new();

    /// <summary>
    /// Individual findings emitted by the scanner.
    /// </summary>
    public List<FindingDto> Findings { get; set; } = new();

    /// <summary>
    /// Gets or sets optional call-chain expansions included when cross-method analysis is enabled.
    /// </summary>
    /// <remarks>
    /// A null value means no top-level call-chain collection was emitted. Individual findings may
    /// still include inline call-chain data when a host requests fully expanded findings.
    /// </remarks>
    public List<CallChainDto>? CallChains { get; set; }

    /// <summary>
    /// Gets or sets optional data-flow expansions included when data-flow analysis is enabled.
    /// </summary>
    /// <remarks>
    /// A null value means no top-level data-flow collection was emitted. Individual findings may
    /// still include inline data-flow data when a host requests fully expanded findings.
    /// </remarks>
    public List<DataFlowChainDto>? DataFlows { get; set; }

    /// <summary>
    /// Gets or sets optional remediation guidance included when developer mode is enabled.
    /// </summary>
    /// <remarks>
    /// Default user-facing scans normally omit this collection. Developer-mode consumers can use it
    /// to explain safer alternatives without changing the security classification itself.
    /// </remarks>
    public List<DeveloperGuidanceDto>? DeveloperGuidance { get; set; }

    /// <summary>
    /// Gets or sets optional malware-family classifications derived from threat-intel matching.
    /// </summary>
    /// <remarks>
    /// Family matches are higher-level correlations over rule findings, call chains, data flows, and
    /// known sample hashes. They do not replace the low-level finding list.
    /// </remarks>
    public List<ThreatFamilyDto>? ThreatFamilies { get; set; }

    /// <summary>
    /// Gets or sets the primary file-level disposition derived from threat-intel correlation.
    /// </summary>
    /// <remarks>
    /// The disposition is the recommended product verdict for consumers. Blocking decisions should
    /// prefer this value and its <see cref="ThreatDispositionDto.BlockingRecommended"/> flag over
    /// ad hoc checks against individual rule severities.
    /// </remarks>
    public ThreatDispositionDto? Disposition { get; set; }
}
