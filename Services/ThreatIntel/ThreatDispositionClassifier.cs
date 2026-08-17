using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Produces the primary user-facing disposition for a scan.
/// </summary>
public sealed class ThreatDispositionClassifier
{
    private static readonly HashSet<string> StrongStandaloneRuleIds = new(StringComparer.Ordinal)
    {
        "DataFlowAnalysis",
        "EmbeddedResourceScriptRule",
        "ObfuscatedReflectiveExecutionRule"
    };

    private static readonly HashSet<DataFlowPattern> SuspiciousDataFlowPatterns = new()
    {
        DataFlowPattern.DownloadAndExecute,
        DataFlowPattern.DataExfiltration,
        DataFlowPattern.DynamicCodeLoading,
        DataFlowPattern.CredentialTheft,
        DataFlowPattern.RemoteConfigLoad,
        DataFlowPattern.ObfuscatedPersistence,
        DataFlowPattern.EmbeddedResourceDropAndExecute
    };

    private static readonly string[] LolbinMarkers =
    [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe"
    ];

    private static readonly string[] HiddenExecutionMarkers =
    [
        "CreateNoWindow=true",
        "CreateNoWindow set",
        "WindowStyle=Hidden",
        "WindowStyle Hidden",
        "UseShellExecute=true",
        "UseShellExecute set"
    ];

    public ThreatDispositionResult Classify(
        IEnumerable<ScanFinding> findings,
        IEnumerable<ThreatFamilyMatch>? threatFamilies)
    {
        return Classify(findings, threatFamilies, null, null);
    }

    public ThreatDispositionResult Classify(
        IEnumerable<ScanFinding> findings,
        IEnumerable<ThreatFamilyMatch>? threatFamilies,
        AnalysisCompletenessResult? analysisCompleteness)
    {
        return Classify(findings, threatFamilies, analysisCompleteness, null);
    }

    public ThreatDispositionResult Classify(
        IEnumerable<ScanFinding> findings,
        IEnumerable<ThreatFamilyMatch>? threatFamilies,
        AnalysisCompletenessResult? analysisCompleteness,
        string? sha256Hash)
    {
        var findingsList = findings?.ToList() ?? new List<ScanFinding>();
        var threatFamilyList = threatFamilies?.ToList() ?? new List<ThreatFamilyMatch>();
        var primaryFamily = threatFamilyList
            .OrderByDescending(match => match.ExactHashMatch)
            .ThenByDescending(match => match.Confidence)
            .ThenBy(match => match.FamilyId, StringComparer.Ordinal)
            .FirstOrDefault();

        if (primaryFamily != null)
        {
            return BuildKnownThreatDisposition(findingsList, primaryFamily);
        }

        if (analysisCompleteness?.ReviewRecommended != true &&
            KnownBenignSampleCatalog.MatchesReviewedBehavior(sha256Hash, findingsList))
        {
            return BuildCleanDisposition();
        }

        var suspiciousSeeds = findingsList
            .Where(finding => IsSuspiciousSeedFinding(finding, findingsList))
            .ToList();

        if (suspiciousSeeds.Count > 0)
        {
            return BuildSuspiciousDisposition(findingsList, suspiciousSeeds);
        }

        if (analysisCompleteness?.ReviewRecommended == true)
        {
            return BuildManualReviewDisposition(analysisCompleteness);
        }

        return BuildCleanDisposition();
    }

    private static ThreatDispositionResult BuildCleanDisposition()
    {
        return new ThreatDispositionResult
        {
            Classification = ThreatDispositionClassification.Clean,
            Headline = "No known threats detected",
            Summary = "No known malware family matches or correlated suspicious behavior were retained.",
            BlockingRecommended = false
        };
    }

    private static ThreatDispositionResult BuildKnownThreatDisposition(
        IReadOnlyList<ScanFinding> findings,
        ThreatFamilyMatch primaryFamily)
    {
        var relatedFindings = ResolveKnownThreatFindings(findings, primaryFamily);
        var summary = primaryFamily.ExactHashMatch
            ? "This file exactly matches a previously confirmed malicious sample."
            : $"This file matches the previously analyzed malware family \"{primaryFamily.DisplayName}\".";

        return new ThreatDispositionResult
        {
            Classification = ThreatDispositionClassification.KnownThreat,
            Headline = "Likely malware detected",
            Summary = summary,
            BlockingRecommended = true,
            PrimaryThreatFamilyId = primaryFamily.FamilyId,
            PrimaryThreatFamily = primaryFamily,
            RelatedFindings = relatedFindings
        };
    }

    private static ThreatDispositionResult BuildSuspiciousDisposition(
        IReadOnlyList<ScanFinding> findings,
        IReadOnlyList<ScanFinding> suspiciousSeeds)
    {
        return new ThreatDispositionResult
        {
            Classification = ThreatDispositionClassification.Suspicious,
            Headline = "Suspicious behavior detected",
            Summary =
                "This file shows correlated suspicious behavior. It may be malicious, but it may also be a false positive and should be reviewed.",
            BlockingRecommended = true,
            RelatedFindings = ExpandCorrelatedFindings(findings, suspiciousSeeds)
        };
    }

    private static ThreatDispositionResult BuildManualReviewDisposition(
        AnalysisCompletenessResult analysisCompleteness)
    {
        return new ThreatDispositionResult
        {
            Classification = ThreatDispositionClassification.ManualReviewRequired,
            Headline = "Manual review required",
            Summary =
                "Analysis did not complete enough to support a clean verdict. Review the completeness reasons before trusting this result.",
            BlockingRecommended = true,
            RelatedFindings = analysisCompleteness.RelatedFindings
        };
    }

    private static List<ScanFinding> ResolveKnownThreatFindings(
        IReadOnlyList<ScanFinding> findings,
        ThreatFamilyMatch primaryFamily)
    {
        var matchedRules = primaryFamily.MatchedRules
            .Where(ruleId => !string.IsNullOrWhiteSpace(ruleId) && !string.Equals(ruleId, "DataFlowAnalysis", StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);
        var evidenceLocations = primaryFamily.Evidence
            .Where(evidence => !string.IsNullOrWhiteSpace(evidence.Location))
            .Select(evidence => evidence.Location!)
            .ToHashSet(StringComparer.Ordinal);
        var callChainIds = primaryFamily.Evidence
            .Where(evidence => !string.IsNullOrWhiteSpace(evidence.CallChainId))
            .Select(evidence => evidence.CallChainId!)
            .ToHashSet(StringComparer.Ordinal);
        var dataFlowIds = primaryFamily.Evidence
            .Where(evidence => !string.IsNullOrWhiteSpace(evidence.DataFlowChainId))
            .Select(evidence => evidence.DataFlowChainId!)
            .ToHashSet(StringComparer.Ordinal);

        var relatedFindings = findings
            .Where(finding =>
                evidenceLocations.Contains(finding.Location) ||
                (finding.HasCallChain && callChainIds.Contains(finding.CallChain!.ChainId)) ||
                (finding.HasDataFlow && dataFlowIds.Contains(finding.DataFlowChain!.ChainId)))
            .ToList();

        if (relatedFindings.Count == 0)
        {
            relatedFindings = findings
                .Where(finding => !string.IsNullOrWhiteSpace(finding.RuleId) && matchedRules.Contains(finding.RuleId))
                .ToList();
        }
        else if (matchedRules.Count > 0)
        {
            relatedFindings = ExpandCorrelatedFindings(
                findings,
                relatedFindings
                    .Concat(findings.Where(finding => !string.IsNullOrWhiteSpace(finding.RuleId) && matchedRules.Contains(finding.RuleId)))
                    .ToList());
        }

        return relatedFindings;
    }

    private static List<ScanFinding> ExpandCorrelatedFindings(
        IEnumerable<ScanFinding> findings,
        IReadOnlyCollection<ScanFinding> seeds)
    {
        var related = new HashSet<ScanFinding>(seeds);
        var callChainIds = seeds
            .Where(finding => finding.HasCallChain)
            .Select(finding => finding.CallChain!.ChainId)
            .ToHashSet(StringComparer.Ordinal);
        var dataFlowIds = seeds
            .Where(finding => finding.HasDataFlow)
            .Select(finding => finding.DataFlowChain!.ChainId)
            .ToHashSet(StringComparer.Ordinal);
        var locations = seeds
            .Select(finding => finding.Location)
            .Where(location => !string.IsNullOrWhiteSpace(location))
            .ToHashSet(StringComparer.Ordinal);

        foreach (var finding in findings)
        {
            if (related.Contains(finding))
            {
                continue;
            }

            if ((finding.HasCallChain && callChainIds.Contains(finding.CallChain!.ChainId)) ||
                (finding.HasDataFlow && dataFlowIds.Contains(finding.DataFlowChain!.ChainId)) ||
                locations.Contains(finding.Location))
            {
                related.Add(finding);
            }
        }

        return related
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId, StringComparer.Ordinal)
            .ThenBy(finding => finding.Location, StringComparer.Ordinal)
            .ToList();
    }

    private static bool IsSuspiciousSeedFinding(
        ScanFinding finding,
        IReadOnlyList<ScanFinding> allFindings)
    {
        if (finding == null || finding.Severity < Severity.High)
        {
            return false;
        }

        if (finding.Severity == Severity.Critical)
        {
            return true;
        }

        if (finding.HasDataFlow && IsSuspiciousDataFlowSeed(finding))
        {
            return true;
        }

        if (string.Equals(finding.RuleId, "DataFlowAnalysis", StringComparison.Ordinal))
        {
            return false;
        }

        if (StrongStandaloneRuleIds.Contains(finding.RuleId ?? string.Empty))
        {
            return true;
        }

        if (IsHiddenLolbinDownloadExecuteSeed(finding))
        {
            return true;
        }

        if (IsHiddenLolbinTempScriptSeed(finding))
        {
            return true;
        }

        if (IsKnownInfrastructureStagedExecutionSeed(finding, allFindings))
        {
            return true;
        }

        if (IsMultiSignalStagedExecutionSeed(finding, allFindings))
        {
            return true;
        }

        if (finding.HasCallChain && finding.HasDataFlow)
        {
            return true;
        }

        var correlatedFindings = ExpandCorrelatedFindings(allFindings, new[] { finding });
        var highSeverityCorrelatedCount = correlatedFindings.Count(relatedFinding => relatedFinding.Severity >= Severity.High);
        var highSeverityRuleCount = correlatedFindings
            .Where(relatedFinding => relatedFinding.Severity >= Severity.High && !string.IsNullOrWhiteSpace(relatedFinding.RuleId))
            .Select(relatedFinding => relatedFinding.RuleId!)
            .Distinct(StringComparer.Ordinal)
            .Count();

        if (string.Equals(finding.RuleId, "AssemblyDynamicLoadRule", StringComparison.Ordinal))
        {
            return finding.BypassCompanionCheck && highSeverityRuleCount >= 2;
        }

        return (finding.HasCallChain || finding.HasDataFlow) &&
               highSeverityCorrelatedCount >= 2 &&
               highSeverityRuleCount >= 2;
    }

    private static bool IsSuspiciousDataFlowSeed(ScanFinding finding)
    {
        return SuspiciousDataFlowPatterns.Contains(finding.DataFlowChain!.Pattern);
    }

    private static IEnumerable<string> EnumerateEmbeddedDataFlowTexts(ScanFinding finding)
    {
        yield return finding.Description;

        if (!string.IsNullOrWhiteSpace(finding.CodeSnippet))
        {
            yield return finding.CodeSnippet;
        }

        if (!finding.HasDataFlow)
        {
            yield break;
        }

        var dataFlow = finding.DataFlowChain!;
        yield return dataFlow.Summary;
        yield return dataFlow.MethodLocation;

        foreach (var node in dataFlow.Nodes)
        {
            yield return node.Location;
            yield return node.Operation;
            yield return node.DataDescription;

            if (!string.IsNullOrWhiteSpace(node.CodeSnippet))
            {
                yield return node.CodeSnippet;
            }
        }
    }

    private static bool IsHiddenLolbinDownloadExecuteSeed(ScanFinding finding)
    {
        if (!string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) ||
            !finding.HasDataFlow ||
            !IsSuspiciousDataFlowSeed(finding))
        {
            return false;
        }

        var texts = EnumerateEmbeddedDataFlowTexts(finding).ToList();
        return ContainsAny(texts, LolbinMarkers) && ContainsAny(texts, HiddenExecutionMarkers);
    }

    private static bool IsHiddenLolbinTempScriptSeed(ScanFinding finding)
    {
        if (!string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal))
        {
            return false;
        }

        var texts = EnumerateFindingTexts(finding).ToList();
        return ContainsAny(texts, LolbinMarkers) &&
               ContainsAny(texts, HiddenExecutionMarkers) &&
               ContainsAny(texts, ".bat", ".cmd", "%TEMP%", "WorkingDirectory=Temp", "GetTempPath");
    }

    private static bool IsKnownInfrastructureStagedExecutionSeed(ScanFinding finding, IReadOnlyList<ScanFinding> allFindings)
    {
        if (IsKnownInfrastructureFinding(finding))
        {
            return allFindings.Any(IsHiddenStagedExecutionFinding);
        }

        return IsHiddenStagedExecutionFinding(finding) && allFindings.Any(IsKnownInfrastructureFinding);
    }

    private static bool IsKnownInfrastructureFinding(ScanFinding finding)
    {
        return string.Equals(finding.RuleId, "DataInfiltrationRule", StringComparison.Ordinal) &&
               ContainsAny(EnumerateFindingTexts(finding), "known malicious domain", "confirmed payload delivery infrastructure");
    }

    private static bool IsMultiSignalStagedExecutionSeed(ScanFinding finding, IReadOnlyList<ScanFinding> allFindings)
    {
        if (!string.Equals(finding.RuleId, "MultiSignalDetection", StringComparison.Ordinal) ||
            !ContainsAny(EnumerateFindingTexts(finding), "process execution + Base64 decoding + file write"))
        {
            return false;
        }

        var methodLocation = NormalizeMethodLocation(finding.Location);
        return allFindings.Any(candidate =>
            IsHiddenStagedExecutionFinding(candidate) &&
            string.Equals(NormalizeMethodLocation(candidate.Location), methodLocation, StringComparison.Ordinal));
    }

    private static bool IsHiddenStagedExecutionFinding(ScanFinding finding)
    {
        if (!string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal))
        {
            return false;
        }

        var texts = EnumerateFindingTexts(finding).ToList();
        return ContainsAny(texts, HiddenExecutionMarkers) &&
               ContainsAny(texts, ".bat", ".cmd", ".exe", "%TEMP%", "WorkingDirectory=Temp", "GetTempPath", "Correlated data flow");
    }

    private static IEnumerable<string> EnumerateFindingTexts(ScanFinding finding)
    {
        yield return finding.Description;
        yield return finding.Location;

        if (!string.IsNullOrWhiteSpace(finding.CodeSnippet))
        {
            yield return finding.CodeSnippet;
        }
    }

    private static string NormalizeMethodLocation(string? location)
    {
        if (string.IsNullOrWhiteSpace(location))
        {
            return string.Empty;
        }

        var separator = location.IndexOf(':');
        return separator >= 0 ? location[..separator] : location;
    }

    private static bool ContainsAny(IEnumerable<string> haystacks, params string[] needles)
    {
        var haystackList = haystacks.Where(value => !string.IsNullOrWhiteSpace(value)).ToList();
        return needles.Any(needle => haystackList.Any(value => value.Contains(needle, StringComparison.OrdinalIgnoreCase)));
    }
}
