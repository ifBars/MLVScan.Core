namespace MLVScan.Models.Dto;

/// <summary>
/// Options for configuring scan result generation and output formatting.
/// Allows platforms to customize metadata without hardcoding values in the mapper.
/// </summary>
public class ScanResultOptions
{
    /// <summary>
    /// The platform identifier (e.g., "wasm", "cli", "server", "desktop").
    /// Defaults to "core".
    /// </summary>
    public string Platform { get; set; } = "core";

    /// <summary>
    /// The scan mode: "summary", "detailed", or "developer".
    /// Defaults to "detailed".
    /// </summary>
    public string ScanMode { get; set; } = "detailed";

    /// <summary>
    /// The MLVScan.Core library version (semver).
    /// Defaults to the current Core version.
    /// </summary>
    public string CoreVersion { get; set; } = MLVScanVersions.CoreVersion;

    /// <summary>
    /// The platform implementation version (e.g., "1.0.2" for DevCLI, "0.1.0" for WASM).
    /// This represents the specific tool/version that executed the scan.
    /// </summary>
    public string PlatformVersion { get; set; } = "0.0.0";

    /// <summary>
    /// The schema version for the output.
    /// Defaults to the current schema version.
    /// </summary>
    public string SchemaVersion { get; set; } = MLVScanVersions.SchemaVersion;

    /// <summary>
    /// Whether to include developer guidance in the output.
    /// Automatically set to true when ScanMode is "developer".
    /// </summary>
    public bool IncludeDeveloperGuidance { get; set; } = false;

    /// <summary>
    /// Whether to include call chains in the output.
    /// </summary>
    public bool IncludeCallChains { get; set; } = true;

    /// <summary>
    /// Whether to include data flows in the output.
    /// </summary>
    public bool IncludeDataFlows { get; set; } = true;

    /// <summary>
    /// Creates options for WASM platform.
    /// </summary>
    public static ScanResultOptions ForWasm(bool developerMode = false) => new()
    {
        Platform = "wasm",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };

    /// <summary>
    /// Creates options for CLI platform.
    /// </summary>
    public static ScanResultOptions ForCli(bool developerMode = false) => new()
    {
        Platform = "cli",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };

    /// <summary>
    /// Creates options for Server platform.
    /// </summary>
    public static ScanResultOptions ForServer(bool developerMode = false) => new()
    {
        Platform = "server",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };

    /// <summary>
    /// Creates options for Desktop platform.
    /// </summary>
    public static ScanResultOptions ForDesktop(bool developerMode = false) => new()
    {
        Platform = "desktop",
        ScanMode = developerMode ? "developer" : "detailed",
        IncludeDeveloperGuidance = developerMode
    };
}
