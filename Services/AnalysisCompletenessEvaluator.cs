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
    /// <summary>True for format evidence outside the scope of managed analysis.</summary>
    public static bool IsNotApplicableFinding(ScanFinding finding) => finding?.RuleId is "NativePeInput" or "AppleDoubleInput";

    internal static string AssemblyFailureSummary(Exception error)
    {
        var category = error switch
        {
            BadImageFormatException => "invalid_format",
            UnauthorizedAccessException => "access_denied",
            System.IO.IOException => "io_error",
            ArgumentException => "invalid_metadata",
            InvalidOperationException => "invalid_operation",
            _ => "other_error"
        };
        // Never expose exception messages, type names, file paths, or assembly names.
        return $"Warning: The assembly could not be scanned completely. Failure category: {category}. Manual review is required before treating this input as clean.";
    }

    /// <summary>Maps retained diagnostic evidence to a fixed vocabulary, never arbitrary input text.</summary>
    public static string GetDiagnosticReasonCategory(string? ruleId, string? summary)
    {
        summary ??= string.Empty;
        if (ruleId == "DataFlowScanWarning")
            return summary.Contains("Cross-method analysis reached its bounded work limit", StringComparison.Ordinal)
                ? "cross_method_work_limit"
                : summary.Contains("bounded data-flow work limit was reached", StringComparison.Ordinal)
                    ? "method_work_limit" : "data_flow_unspecified";
        if (ruleId == "AssemblyScanner")
        {
            foreach (var category in new[] { "native_pe", "non_pe", "malformed_pe", "invalid_cli_metadata", "invalid_format", "access_denied", "io_error", "invalid_metadata", "invalid_operation", "other_error" })
                if (summary.Contains($"Failure category: {category}.", StringComparison.Ordinal)) return category;
            return "assembly_scan_unspecified";
        }
        return ruleId switch
        {
            "MethodScanWarning" => "method_analysis",
            "TypeScanWarning" => "type_analysis",
            "ExceptionHandlerScanWarning" => "exception_handler_analysis",
            "StaticRvaScanWarning" => "static_data_analysis",
            _ => "other_incomplete"
        };
    }
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
        if (findingsList.Count > 0 && findingsList.All(IsNotApplicableFinding))
        {
            return new AnalysisCompletenessResult
            {
                Status = AnalysisCompletenessStatus.NotApplicable,
                IsComplete = false,
                ReviewRecommended = false,
                Reasons = findingsList.Select(f => new AnalysisCompletenessReason
                {
                    ReasonId = f.RuleId == "NativePeInput" ? "native-pe" : "apple-double", Phase = "input-format", Location = f.Location, Summary = f.Description
                }).ToList()
            };
        }

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
