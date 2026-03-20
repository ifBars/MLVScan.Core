namespace MLVScan.Models.ThreatIntel;

/// <summary>
/// Primary disposition for a scan after threat-intel correlation is applied.
/// </summary>
public enum ThreatDispositionClassification
{
    Clean,
    Suspicious,
    KnownThreat
}
