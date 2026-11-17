using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DiagnosticReasonCategoryTests
{
    [Theory]
    [InlineData("AssemblyScanner", "Failure category: invalid_format.", "invalid_format")]
    [InlineData("AssemblyScanner", "C:/private/example.dll", "assembly_scan_unspecified")]
    [InlineData("DataFlowScanWarning", "Cross-method analysis reached its bounded work limit", "cross_method_work_limit")]
    [InlineData("DataFlowScanWarning", "bounded data-flow work limit was reached", "method_work_limit")]
    [InlineData("DataFlowScanWarning", "unknown private message", "data_flow_unspecified")]
    [InlineData("private-rule", "private-message", "other_incomplete")]
    public void ReasonsUseOnlyFixedCategories(string rule, string summary, string expected)
        => Assert.Equal(expected, AnalysisCompletenessEvaluator.GetDiagnosticReasonCategory(rule, summary));

    [Fact]
    public void AssemblyFailureDoesNotExposeExceptionText()
    {
        var summary = AnalysisCompletenessEvaluator.AssemblyFailureSummary(new BadImageFormatException("private-path.dll"));
        Assert.DoesNotContain("private-path", summary);
        Assert.Equal("invalid_format", AnalysisCompletenessEvaluator.GetDiagnosticReasonCategory("AssemblyScanner", summary));
    }
}
