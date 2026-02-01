namespace MLVScan.Models.Dto;

/// <summary>
/// Information about the scanned input.
/// </summary>
public class ScanInputDto
{
    /// <summary>
    /// File name of the scanned assembly.
    /// </summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>
    /// Size of the input in bytes.
    /// </summary>
    public long SizeBytes { get; set; }

    /// <summary>
    /// SHA256 hash of the input (hex string).
    /// </summary>
    public string? Sha256Hash { get; set; }
}
