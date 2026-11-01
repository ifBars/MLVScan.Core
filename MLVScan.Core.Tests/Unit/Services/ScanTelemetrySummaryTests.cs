using System.Text.Json;
using MLVScan.Models.Dto;
using MLVScan.Models.Telemetry;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ScanTelemetrySummaryTests
{
    [Theory]
    [InlineData("KnownThreat", ScanTelemetryOutcome.KnownThreat)]
    [InlineData("Suspicious", ScanTelemetryOutcome.Suspicious)]
    [InlineData("ManualReviewRequired", ScanTelemetryOutcome.ManualReviewRequired)]
    [InlineData("Clean", ScanTelemetryOutcome.Clean)]
    [InlineData("future-or-private-value", ScanTelemetryOutcome.Unknown)]
    public void ProjectionUsesDispositionWithoutFindings(string classification, ScanTelemetryOutcome expected)
    {
        var result = new ScanResultDto { Disposition = new() { Classification = classification } };
        Assert.Equal(expected, ScanTelemetrySummary.GetOutcome(result));
    }

    [Fact]
    public void MissingAndIncompleteResultsCannotBecomeClean()
    {
        Assert.Equal(ScanTelemetryOutcome.Unknown, ScanTelemetrySummary.GetOutcome(null));
        Assert.Equal(ScanTelemetryOutcome.Unknown, ScanTelemetrySummary.GetOutcome(new()));
        var result = new ScanResultDto
        {
            Disposition = new() { Classification = "Clean" },
            AnalysisCompleteness = new() { IsComplete = false }
        };
        Assert.Equal(ScanTelemetryOutcome.ManualReviewRequired, ScanTelemetrySummary.GetOutcome(result));
    }

    [Fact]
    public void SummaryIsDeterministicAndContainsOnlyAllowlistedCounts()
    {
        var result = new ScanResultDto
        {
            Input = new() { FileName = "private.dll", Sha256Hash = "private-hash" },
            Disposition = new() { Classification = "KnownThreat", Summary = "private-evidence" }
        };
        var outcomes = new[] { ScanTelemetrySummary.GetOutcome(result), ScanTelemetryOutcome.Failed,
            ScanTelemetryOutcome.ManualReviewRequired, (ScanTelemetryOutcome)999 };
        var first = ScanTelemetrySummary.Create(outcomes);
        var second = ScanTelemetrySummary.Create(outcomes);
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Equal(4, first["result_count"]);
        Assert.Equal(1, first["known_threat_count"]);
        Assert.Equal(1, first["failed_count"]);
        Assert.Equal(1, first["manual_review_required_count"]);
        Assert.Equal(1, first["unknown_count"]);
        Assert.Equal(ScanTelemetrySummary.SchemaVersion, first["telemetry_schema_version"]);
        // Sparse: zero-count outcomes are omitted, matching the browser consumer's key set.
        Assert.Equal(new[] { "failed_count", "known_threat_count", "manual_review_required_count",
            "result_count", "telemetry_schema_version", "unknown_count" }, first.Keys.Order());
        Assert.DoesNotContain("private", JsonSerializer.Serialize(first));
        Assert.Equal("private.dll", result.Input.FileName);
    }

    [Fact]
    public void EmptyRunsHaveZeroResultsAndNoSharedMutableState()
    {
        var empty = ScanTelemetrySummary.Create(Array.Empty<ScanTelemetryOutcome>());
        ScanTelemetrySummary.Create(new[] { ScanTelemetryOutcome.Clean });
        Assert.Equal(0, empty["result_count"]);
        Assert.Equal(new[] { "result_count", "telemetry_schema_version" }, empty.Keys.Order());
        Assert.Throws<NotSupportedException>(() => ((IDictionary<string, int>)empty)["clean_count"] = 5);
    }
}
