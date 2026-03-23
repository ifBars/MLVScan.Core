namespace MLVScan.Models.Dto;

/// <summary>
/// Options for configuring scan result generation and output formatting.
/// </summary>
public class ScanResultOptions
{
    /// <summary>
    /// Logical platform identifier used in result metadata.
    /// </summary>
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
    /// Indicates whether developer guidance should be included in the result.
    /// </summary>
    public bool IncludeDeveloperGuidance { get; set; } = false;

    /// <summary>
    /// Indicates whether call chains should be included in the result.
    /// </summary>
    public bool IncludeCallChains { get; set; } = true;

    /// <summary>
    /// Indicates whether data-flow chains should be included in the result.
    /// </summary>
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
