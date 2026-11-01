using MLVScan.Models;

namespace MLVScan.Services.Helpers;

/// <summary>
/// Shared interpretation of scan limitations for DTO completeness and disposition decisions.
/// Delegates to the public <see cref="AnalysisCompletenessEvaluator"/> so hosts use the same rule.
/// </summary>
internal static class AnalysisCompletenessEvidence
{
    internal static bool IsIncompleteFinding(ScanFinding finding) =>
        AnalysisCompletenessEvaluator.IsIncompleteFinding(finding);
}
