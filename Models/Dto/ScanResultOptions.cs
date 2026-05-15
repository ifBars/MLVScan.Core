namespace MLVScan.Models.Dto;

/// <summary>
/// Options for configuring scan result generation and output formatting.
/// </summary>
/// <remarks>
/// These options describe the host context and optional expansion sections for
/// <see cref="MLVScan.Services.ScanResultMapper"/>. They do not change rule execution or threat
/// classification behavior.
/// </remarks>
public class ScanResultOptions
{
    /// <summary>
    /// Gets or sets the logical platform identifier used in result metadata.
    /// </summary>
    /// <remarks>
    /// Use neutral host identifiers such as <c>core</c>, <c>cli</c>, <c>wasm</c>, <c>server</c>, or
    /// <c>desktop</c>. Loader-specific values should be applied by loader integration layers only
    /// when the result is no longer part of the environment-neutral Core contract.
    /// </remarks>
    public string Platform { get; set; } = "core";

    /// <summary>
    /// Scan mode to publish in the result metadata.
    /// </summary>
    public string ScanMode { get; set; } = "detailed";

    /// <summary>
    /// Core library version reported in the result metadata.
    /// </summary>
    public string CoreVersion { get; set; } = MLVScanVersions.CoreVersion;

    /// <summary>
    /// Host or platform version reported in the result metadata.
    /// </summary>
    public string PlatformVersion { get; set; } = "0.0.0";

    /// <summary>
    /// Shared JSON schema version reported in the result metadata.
    /// </summary>
    public string SchemaVersion { get; set; } = MLVScanVersions.SchemaVersion;

    /// <summary>
    /// Gets or sets a value indicating whether developer guidance should be included in the result.
    /// </summary>
    /// <remarks>
    /// Developer guidance can include remediation text and safer alternatives. It is useful for
    /// inspectors, CI reports, and advanced diagnostics, but can be omitted from default end-user
    /// scans to keep reports concise.
    /// </remarks>
    public bool IncludeDeveloperGuidance { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether top-level call chains should be included in the result.
    /// </summary>
    /// <remarks>
    /// Disabling this option suppresses the top-level <see cref="ScanResultDto.CallChains"/>
    /// collection. It does not change whether individual findings can carry call-chain identifiers
    /// or inline call-chain payloads.
    /// </remarks>
    public bool IncludeCallChains { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether top-level data-flow chains should be included in the result.
    /// </summary>
    /// <remarks>
    /// Disabling this option suppresses the top-level <see cref="ScanResultDto.DataFlows"/>
    /// collection. It does not change scanner analysis or the final disposition.
    /// </remarks>
    public bool IncludeDataFlows { get; set; } = true;

    /// <summary>
    /// Creates options for the WASM host.
    /// </summary>
    /// <param name="developerMode">Whether to include developer guidance.</param>
    /// <returns>Options configured for the WASM host.</returns>
    public static ScanResultOptions ForWasm(bool developerMode = false) => new()
    {
        Platform = "wasm",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };

    /// <summary>
    /// Creates options for the CLI host.
    /// </summary>
    /// <param name="developerMode">Whether to include developer guidance.</param>
    /// <returns>Options configured for the CLI host.</returns>
    public static ScanResultOptions ForCli(bool developerMode = false) => new()
    {
        Platform = "cli",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };

    /// <summary>
    /// Creates options for the server host.
    /// </summary>
    /// <param name="developerMode">Whether to include developer guidance.</param>
    /// <returns>Options configured for the server host.</returns>
    public static ScanResultOptions ForServer(bool developerMode = false) => new()
    {
        Platform = "server",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };

    /// <summary>
    /// Creates options for the desktop host.
    /// </summary>
    /// <param name="developerMode">Whether to include developer guidance.</param>
    /// <returns>Options configured for the desktop host.</returns>
    public static ScanResultOptions ForDesktop(bool developerMode = false) => new()
    {
        Platform = "desktop",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };
}
