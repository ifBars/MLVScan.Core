namespace MLVScan.Models.Dto;

/// <summary>
/// Metadata that describes how a scan was executed.
/// </summary>
public class ScanMetadataDto
{
    /// <summary>
    /// Version of the MLVScan.Core library used for the scan.
    /// </summary>
    public string CoreVersion { get; set; } = MLVScanVersions.CoreVersion;

    /// <summary>
    /// Version of the host or platform implementation that invoked the scan.
    /// </summary>
    public string PlatformVersion { get; set; } = "0.0.0";

    /// <summary>
    /// Timestamp of the scan in ISO 8601 UTC format.
    /// </summary>
    public string Timestamp { get; set; } = DateTime.UtcNow.ToString("o");

    /// <summary>
    /// Scan mode used to generate the result, such as <c>summary</c>, <c>detailed</c>, or <c>developer</c>.
    /// </summary>
    public string ScanMode { get; set; } = "detailed";

    /// <summary>
    /// Logical platform identifier for the host that produced the result.
    /// </summary>
    public string Platform { get; set; } = "core";

    /// <summary>
    /// Version of the scanner implementation reported by the host.
    /// </summary>
    public string ScannerVersion { get; set; } = "0.0.0";
}
