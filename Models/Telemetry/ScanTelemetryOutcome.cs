namespace MLVScan.Models.Telemetry;

/// <summary>Bounded outcome vocabulary for aggregate analytics, not a blocking policy.</summary>
public enum ScanTelemetryOutcome
{
    Unknown,
    Clean,
    ManualReviewRequired,
    Suspicious,
    KnownThreat,
    Failed
}
