namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Final disposition assigned to a scan after threat-intel correlation.
/// </summary>
public enum ThreatDispositionClassification
{
    /// <summary>
    /// No meaningful threat signal was retained.
    /// </summary>
    Clean,

    /// <summary>
    /// Analysis did not complete enough to support a clean verdict.
    /// </summary>
    ManualReviewRequired,

    /// <summary>
    /// Suspicious behavior was found, but not enough to call the file a known threat.
    /// </summary>
    Suspicious,

    /// <summary>
    /// The file matched a known malicious family or sample with high confidence.
    /// </summary>
    KnownThreat
}
