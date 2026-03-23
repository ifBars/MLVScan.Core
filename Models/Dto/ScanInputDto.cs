namespace MLVScan.Models.Dto;

/// <summary>
/// Metadata about the scanned input file.
/// </summary>
public class ScanInputDto
{
    /// <summary>
    /// File name or display name associated with the scanned assembly.
    /// </summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>
    /// Size of the input in bytes.
    /// </summary>
    public long SizeBytes { get; set; }

    /// <summary>
    /// Optional SHA-256 hash of the input, encoded as a lowercase hex string.
    /// </summary>
    public string? Sha256Hash { get; set; }
}
