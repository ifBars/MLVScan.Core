namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Describes how strongly a scan matched a known malware family.
/// </summary>
public enum ThreatMatchKind
{
    /// <summary>
    /// The scanned assembly hash exactly matches a known malicious sample.
    /// </summary>
    ExactSampleHash,

    /// <summary>
    /// The scanned assembly matches a known behavior variant for the family.
    /// </summary>
    BehaviorVariant
}
