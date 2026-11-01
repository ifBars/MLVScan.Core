using MLVScan.Models;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class AnalysisCompletenessEvaluatorTests
{
    [Fact]
    public void NoLimitingFindingsIsComplete()
    {
        var result = AnalysisCompletenessEvaluator.Evaluate(new[]
        {
            new ScanFinding("Type.Method", "Detected Process.Start call", Severity.High) { RuleId = "ProcessStartRule" }
        });
        Assert.True(result.IsComplete);
        Assert.False(result.ReviewRecommended);
        Assert.Equal(AnalysisCompletenessStatus.Complete, result.Status);
        Assert.Empty(result.Reasons);
    }

    [Fact]
    public void ScannerWarningMakesResultPartialWithReason()
    {
        var warning = new ScanFinding("Type.Method",
            "Warning: Could not complete full IL analysis for this method. Manual review is required.",
            Severity.Medium) { RuleId = "MethodScanWarning" };
        var result = AnalysisCompletenessEvaluator.Evaluate(new[]
        {
            warning,
            new ScanFinding("Type.Other", "Detected reflection", Severity.Low) { RuleId = "ReflectionRule" }
        });
        Assert.False(result.IsComplete);
        Assert.True(result.ReviewRecommended);
        Assert.Equal(AnalysisCompletenessStatus.Partial, result.Status);
        var reason = Assert.Single(result.Reasons);
        Assert.Equal("MethodScanWarning", reason.RuleId);
        Assert.Equal("analysis", reason.Phase);
        Assert.Same(warning, Assert.Single(result.RelatedFindings));
    }

    [Fact]
    public void UnscannableAssemblyIsIncomplete()
    {
        var result = AnalysisCompletenessEvaluator.Evaluate(new[]
        {
            new ScanFinding("Assembly scanning",
                "Warning: The assembly could not be scanned completely. Manual review is required before treating this input as clean.",
                Severity.Medium) { RuleId = "AssemblyScanner" }
        });
        Assert.Equal(AnalysisCompletenessStatus.Incomplete, result.Status);
        Assert.Equal("assembly-scan", Assert.Single(result.Reasons).Phase);
    }

    [Fact]
    public void NullOrEmptyInputIsComplete()
    {
        Assert.True(AnalysisCompletenessEvaluator.Evaluate(null).IsComplete);
        Assert.False(AnalysisCompletenessEvaluator.IsIncompleteFinding(null!));
    }
}
