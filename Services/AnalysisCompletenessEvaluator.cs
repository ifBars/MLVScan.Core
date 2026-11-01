#nullable enable
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services;

/// <summary>
/// Decides whether scanner analysis completed enough to support a clean verdict. This is the single
/// interpretation used by result mapping, disposition, and hosts that build verdicts from findings.
/// Pure and deterministic: it reads only the supplied findings.
/// </summary>
public static class AnalysisCompletenessEvaluator
{
    /// <summary>
    /// Returns true when a finding records that some analysis could not complete, such as a
    /// scanner warning, a skipped assembly, or a skipped IL region.
    /// </summary>
    public static bool IsIncompleteFinding(ScanFinding finding)
    {
        if (finding == null) return false;
        var ruleId = finding.RuleId;
        var description = finding.Description ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(ruleId) &&
            (ruleId!.IndexOf("incomplete", StringComparison.OrdinalIgnoreCase) >= 0 ||
             ruleId.IndexOf("manualreview", StringComparison.OrdinalIgnoreCase) >= 0 ||
             ruleId.IndexOf("scanwarning", StringComparison.OrdinalIgnoreCase) >= 0))
        {
            return true;
        }

        if (string.Equals(ruleId, "AssemblyScanner", StringComparison.Ordinal) &&
            description.IndexOf("could not be scanned", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return true;
        }

        return description.IndexOf("could not complete full il analysis", StringComparison.OrdinalIgnoreCase) >= 0 ||
               description.IndexOf("full il analysis was skipped", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    /// <summary>
    /// Builds the completeness result for a set of findings. Incomplete results recommend review
    /// and carry one reason per finding that limited the analysis.
    /// </summary>
    public static AnalysisCompletenessResult Evaluate(IEnumerable<ScanFinding>? findings)
    {
        var findingsList = findings?.Where(f => f != null).ToList() ?? new List<ScanFinding>();
        var incompleteFindings = findingsList.Where(IsIncompleteFinding).ToList();

        if (incompleteFindings.Count == 0)
        {
            return new AnalysisCompletenessResult
            {
                Status = AnalysisCompletenessStatus.Complete,
                IsComplete = true,
                ReviewRecommended = false
            };
        }

        return new AnalysisCompletenessResult
        {
            Status = findingsList.Count > incompleteFindings.Count
                ? AnalysisCompletenessStatus.Partial
                : AnalysisCompletenessStatus.Incomplete,
            IsComplete = false,
            ReviewRecommended = true,
            RelatedFindings = incompleteFindings,
            Reasons = incompleteFindings.Select(ToReason).ToList()
        };
    }

    private static AnalysisCompletenessReason ToReason(ScanFinding finding)
    {
        return new AnalysisCompletenessReason
        {
            ReasonId = "scanner-incomplete",
            Summary = finding.Description ?? string.Empty,
            Phase = string.Equals(finding.RuleId, "AssemblyScanner", StringComparison.Ordinal)
                ? "assembly-scan"
                : "analysis",
            RuleId = finding.RuleId,
            Location = finding.Location
        };
    }
}
