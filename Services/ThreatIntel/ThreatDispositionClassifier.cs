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

    public ThreatDispositionResult Classify(
        IEnumerable<ScanFinding> findings,
        IEnumerable<ThreatFamilyMatch>? threatFamilies)
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

        var suspiciousSeeds = findingsList
            .Where(finding => IsSuspiciousSeedFinding(finding, findingsList))
            .ToList();

        if (suspiciousSeeds.Count > 0)
        {
            return BuildSuspiciousDisposition(findingsList, suspiciousSeeds);
        }

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

        if (string.Equals(finding.RuleId, "DataFlowAnalysis", StringComparison.Ordinal))
        {
            return finding.HasDataFlow &&
                   SuspiciousDataFlowPatterns.Contains(finding.DataFlowChain!.Pattern);
        }

        if (StrongStandaloneRuleIds.Contains(finding.RuleId ?? string.Empty))
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
}
