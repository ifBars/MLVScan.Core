using MLVScan.Models;

namespace MLVScan.Services.Helpers;

/// <summary>
/// Shared interpretation of scan limitations for DTO completeness and disposition decisions.
/// </summary>
internal static class AnalysisCompletenessEvidence
{
    internal static bool IsIncompleteFinding(ScanFinding finding)
    {
        if (!string.IsNullOrWhiteSpace(finding.RuleId) &&
            (finding.RuleId.Contains("incomplete", StringComparison.OrdinalIgnoreCase) ||
             finding.RuleId.Contains("manualreview", StringComparison.OrdinalIgnoreCase) ||
             finding.RuleId.Contains("scanwarning", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (string.Equals(finding.RuleId, "AssemblyScanner", StringComparison.Ordinal) &&
            finding.Description.Contains("could not be scanned", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return finding.Description.Contains("could not complete full il analysis", StringComparison.OrdinalIgnoreCase) ||
               finding.Description.Contains("full il analysis was skipped", StringComparison.OrdinalIgnoreCase);
    }
}
