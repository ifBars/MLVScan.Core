using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Classifies scan results into known malware families using exact hashes and behavior variants.
/// </summary>
public sealed class ThreatFamilyClassifier
{
    /// <summary>
    /// Matches a scan against the built-in malware family catalog.
    /// </summary>
    public IReadOnlyList<ThreatFamilyMatch> Classify(IEnumerable<ScanFinding> findings, string? sha256Hash)
    {
        return Classify(findings, callChains: null, dataFlows: null, sha256Hash);
    }

    /// <summary>
    /// Matches a scan against the built-in malware family catalog using structured call-chain and data-flow context.
    /// </summary>
    public IReadOnlyList<ThreatFamilyMatch> Classify(
        IEnumerable<ScanFinding> findings,
        IEnumerable<CallChain>? callChains,
        IEnumerable<DataFlowChain>? dataFlows,
        string? sha256Hash)
    {
        var context = new ThreatFamilyAnalysisContext(findings, callChains, dataFlows);
        var matches = new List<ThreatFamilyMatch>();

        foreach (var family in ThreatFamilyCatalog.Families)
        {
            if (!string.IsNullOrWhiteSpace(sha256Hash) && family.ExactSampleHashes.Contains(sha256Hash, StringComparer.OrdinalIgnoreCase))
            {
                matches.Add(new ThreatFamilyMatch
                {
                    FamilyId = family.FamilyId,
                    VariantId = "exact-known-sample",
                    DisplayName = family.DisplayName,
                    Summary = family.Summary,
                    MatchKind = ThreatMatchKind.ExactSampleHash,
                    Confidence = 1.0,
                    ExactHashMatch = true,
                    AdvisorySlugs = family.AdvisorySlugs.ToList(),
                    MatchedRules = context.Findings
                        .Select(f => f.RuleId)
                        .Where(ruleId => !string.IsNullOrWhiteSpace(ruleId))
                        .Distinct(StringComparer.Ordinal)
                        .Cast<string>()
                        .OrderBy(ruleId => ruleId, StringComparer.Ordinal)
                        .ToList(),
                    Evidence =
                    [
                        new ThreatFamilyEvidence { Kind = "hash", Value = sha256Hash },
                        new ThreatFamilyEvidence
                        {
                            Kind = "match",
                            Value = "Exact sample hash match",
                            Confidence = 1.0
                        }
                    ]
                });
                continue;
            }

            foreach (var variant in family.Variants)
            {
                var variantMatch = variant.Matcher(context);
                if (variantMatch == null)
                {
                    continue;
                }

                matches.Add(new ThreatFamilyMatch
                {
                    FamilyId = family.FamilyId,
                    VariantId = variant.VariantId,
                    DisplayName = variant.DisplayName,
                    Summary = variant.Summary,
                    MatchKind = ThreatMatchKind.BehaviorVariant,
                    Confidence = variant.Confidence,
                    ExactHashMatch = false,
                    AdvisorySlugs = family.AdvisorySlugs.ToList(),
                    MatchedRules = variantMatch.MatchedRules
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(ruleId => ruleId, StringComparer.Ordinal)
                        .ToList(),
                    Evidence = variantMatch.Evidence.ToList()
                });
                break;
            }
        }

        return matches
            .OrderByDescending(match => match.ExactHashMatch)
            .ThenByDescending(match => match.Confidence)
            .ThenBy(match => match.FamilyId, StringComparer.Ordinal)
            .ToList();
    }
}
