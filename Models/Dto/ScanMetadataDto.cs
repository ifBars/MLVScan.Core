namespace MLVScan.Models.Dto;

/// <summary>
/// Metadata about the scan execution.
/// </summary>
public class ScanMetadataDto
{
    /// <summary>
    /// Version of the MLVScan.Core library (semver).
    /// </summary>
    public string CoreVersion { get; set; } = MLVScanVersions.CoreVersion;

    /// <summary>
    /// Version of the platform implementation (e.g., "1.0.2" for DevCLI, "0.1.0" for WASM).
    /// This represents the specific tool/version that executed the scan.
    /// </summary>
    public string PlatformVersion { get; set; } = "0.0.0";

    /// <summary>
    /// Timestamp when the scan was executed (ISO 8601).
    /// </summary>
    public string Timestamp { get; set; } = DateTime.UtcNow.ToString("o");

    /// <summary>
    /// Scan mode: "summary", "detailed", or "developer".
    /// </summary>
    public string ScanMode { get; set; } = "detailed";

    /// <summary>
    /// Platform where the scan was executed (e.g., "wasm", "cli", "server", "desktop").
    /// </summary>
    public string Platform { get; set; } = "core";

    /// <summary>
    /// Version of the scanner implementation (e.g., "1.0.2" for DevCLI, "0.1.0" for WASM).
    /// Used by frontend components to display the scanner version.
    /// </summary>
    public string ScannerVersion { get; set; } = "0.0.0";
}
