#nullable enable
using System.Collections.ObjectModel;
using MLVScan.Models.Dto;
using MLVScan.Models.Telemetry;

namespace MLVScan.Services;

/// <summary>
/// Pure, versioned projection of scan outcomes into aggregate counts. Does not collect identity,
/// inspect input content, send events, measure time, or decide whether collection is permitted.
/// </summary>
public static class ScanTelemetrySummary
{
    /// <summary>The analytics contract version, independent of the scan-result schema.</summary>
    public const int SchemaVersion = 2;

    /// <summary>
    /// Projects the existing disposition without reclassifying findings. Missing or future
    /// classifications remain unknown; incomplete clean results require manual review.
    /// </summary>
    public static ScanTelemetryOutcome GetOutcome(ScanResultDto? result)
    {
        return result?.Disposition?.Classification switch
        {
            "KnownThreat" => ScanTelemetryOutcome.KnownThreat,
            "Suspicious" => ScanTelemetryOutcome.Suspicious,
            "ManualReviewRequired" => ScanTelemetryOutcome.ManualReviewRequired,
            "Clean" when result.AnalysisCompleteness is { IsComplete: true, ReviewRecommended: false,
                Status: "Complete" } => ScanTelemetryOutcome.Clean,
            "Clean" => ScanTelemetryOutcome.ManualReviewRequired,
            _ => ScanTelemetryOutcome.Unknown
        };
    }

    /// <summary>
    /// Returns a fresh immutable allowlist of numeric properties. Hosts count failures explicitly;
    /// skipped files are not clean outcomes. Cache reuse may be counted by hosts as an observation.
    /// Outcome keys are sparse: only non-zero counts are present, matching the browser consumer.
    /// <c>telemetry_schema_version</c> and <c>result_count</c> are always present.
    /// </summary>
    public static IReadOnlyDictionary<string, int> Create(IEnumerable<ScanTelemetryOutcome> outcomes)
    {
        if (outcomes == null) throw new ArgumentNullException(nameof(outcomes));
        var properties = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["telemetry_schema_version"] = SchemaVersion,
            ["result_count"] = 0
        };
        foreach (var outcome in outcomes)
        {
            var key = outcome switch
            {
                ScanTelemetryOutcome.Clean => "clean_count",
                ScanTelemetryOutcome.ManualReviewRequired => "manual_review_required_count",
                ScanTelemetryOutcome.Suspicious => "suspicious_count",
                ScanTelemetryOutcome.KnownThreat => "known_threat_count",
                ScanTelemetryOutcome.Failed => "failed_count",
                _ => "unknown_count"
            };
            properties.TryGetValue(key, out var count);
            checked { properties[key] = count + 1; properties["result_count"]++; }
        }
        return new ReadOnlyDictionary<string, int>(properties);
    }
}
