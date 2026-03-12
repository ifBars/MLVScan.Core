using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

internal sealed class ThreatFamilyAnalysisContext
{
    public ThreatFamilyAnalysisContext(
        IEnumerable<ScanFinding> findings,
        IEnumerable<CallChain>? callChains,
        IEnumerable<DataFlowChain>? dataFlows)
    {
        Findings = findings.ToList();
        CallChains = CollectUniqueChains(callChains, Findings.Where(f => f.HasCallChain).Select(f => f.CallChain!));
        DataFlows = CollectUniqueFlows(dataFlows, Findings.Where(f => f.HasDataFlow).Select(f => f.DataFlowChain!));
    }

    public IReadOnlyList<ScanFinding> Findings { get; }

    public IReadOnlyList<CallChain> CallChains { get; }

    public IReadOnlyList<DataFlowChain> DataFlows { get; }

    public bool HasRule(string ruleId)
    {
        return Findings.Any(f => string.Equals(f.RuleId, ruleId, StringComparison.Ordinal));
    }

    public ScanFinding? FindFinding(string ruleId, params string[] needles)
    {
        return Findings.FirstOrDefault(f =>
            string.Equals(f.RuleId, ruleId, StringComparison.Ordinal) &&
            (needles.Length == 0 || TextContainsAll(EnumerateFindingTexts(f), needles)));
    }

    public CallChain? FindCallChain(string ruleId, params string[] needles)
    {
        return CallChains.FirstOrDefault(chain =>
            string.Equals(chain.RuleId, ruleId, StringComparison.Ordinal) &&
            (needles.Length == 0 || TextContainsAll(EnumerateCallChainTexts(chain), needles)));
    }

    public DataFlowChain? FindDataFlow(DataFlowPattern pattern, params string[] needles)
    {
        return DataFlows.FirstOrDefault(flow =>
            flow.Pattern == pattern &&
            (needles.Length == 0 || TextContainsAll(EnumerateDataFlowTexts(flow), needles)));
    }

    public bool AnyFindingContainsAll(params string[] needles)
    {
        return Findings.Any(f => TextContainsAll(EnumerateFindingTexts(f), needles));
    }

    public bool AnyCallChainContainsAll(params string[] needles)
    {
        return CallChains.Any(chain => TextContainsAll(EnumerateCallChainTexts(chain), needles));
    }

    public bool AnyDataFlowContainsAll(params string[] needles)
    {
        return DataFlows.Any(flow => TextContainsAll(EnumerateDataFlowTexts(flow), needles));
    }

    public bool AnyContextContainsAll(params string[] needles)
    {
        return AnyFindingContainsAll(needles) || AnyCallChainContainsAll(needles) || AnyDataFlowContainsAll(needles);
    }

    public IReadOnlyList<string> BuildMatchedRules(params string[] rules)
    {
        return rules
            .Where(rule => !string.IsNullOrWhiteSpace(rule))
            .Distinct(StringComparer.Ordinal)
            .Where(rule => rule == "DataFlowAnalysis" || HasRule(rule) || CallChains.Any(c => string.Equals(c.RuleId, rule, StringComparison.Ordinal)))
            .OrderBy(rule => rule, StringComparer.Ordinal)
            .ToList();
    }

    public ThreatFamilyEvidence CreateRuleEvidence(string kind, string value, ScanFinding? finding)
    {
        return new ThreatFamilyEvidence
        {
            Kind = kind,
            Value = value,
            RuleId = finding?.RuleId,
            Location = finding?.Location,
            CallChainId = finding?.CallChain?.ChainId,
            DataFlowChainId = finding?.DataFlowChain?.ChainId,
            Pattern = finding?.DataFlowChain?.Pattern.ToString(),
            MethodLocation = finding?.DataFlowChain?.MethodLocation
        };
    }

    public ThreatFamilyEvidence CreateCallChainEvidence(string kind, string value, CallChain? chain)
    {
        return new ThreatFamilyEvidence
        {
            Kind = kind,
            Value = value,
            RuleId = chain?.RuleId,
            Location = chain?.Nodes.LastOrDefault()?.Location,
            CallChainId = chain?.ChainId
        };
    }

    public ThreatFamilyEvidence CreateDataFlowEvidence(string kind, string value, DataFlowChain? flow)
    {
        return new ThreatFamilyEvidence
        {
            Kind = kind,
            Value = value,
            DataFlowChainId = flow?.ChainId,
            Pattern = flow?.Pattern.ToString(),
            MethodLocation = flow?.MethodLocation,
            Confidence = flow?.Confidence,
            Location = flow?.Nodes.LastOrDefault()?.Location
        };
    }

    private static IReadOnlyList<CallChain> CollectUniqueChains(
        IEnumerable<CallChain>? explicitCallChains,
        IEnumerable<CallChain> findingCallChains)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var chains = new List<CallChain>();

        foreach (var chain in explicitCallChains ?? Enumerable.Empty<CallChain>())
        {
            AddChain(chain, seen, chains);
        }

        foreach (var chain in findingCallChains)
        {
            AddChain(chain, seen, chains);
        }

        return chains;
    }

    private static IReadOnlyList<DataFlowChain> CollectUniqueFlows(
        IEnumerable<DataFlowChain>? explicitDataFlows,
        IEnumerable<DataFlowChain> findingDataFlows)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var flows = new List<DataFlowChain>();

        foreach (var flow in explicitDataFlows ?? Enumerable.Empty<DataFlowChain>())
        {
            AddFlow(flow, seen, flows);
        }

        foreach (var flow in findingDataFlows)
        {
            AddFlow(flow, seen, flows);
        }

        return flows;
    }

    private static void AddChain(CallChain chain, ISet<string> seen, ICollection<CallChain> chains)
    {
        if (seen.Add(chain.ChainId))
        {
            chains.Add(chain);
        }
    }

    private static void AddFlow(DataFlowChain flow, ISet<string> seen, ICollection<DataFlowChain> flows)
    {
        if (seen.Add(flow.ChainId))
        {
            flows.Add(flow);
        }
    }

    private static bool TextContainsAll(IEnumerable<string> haystacks, IEnumerable<string> needles)
    {
        var haystackList = haystacks.Where(value => !string.IsNullOrWhiteSpace(value)).ToList();
        return needles.All(needle =>
            haystackList.Any(value => value.Contains(needle, StringComparison.OrdinalIgnoreCase)));
    }

    private static IEnumerable<string> EnumerateFindingTexts(ScanFinding finding)
    {
        yield return finding.Location;
        yield return finding.Description;

        if (!string.IsNullOrWhiteSpace(finding.CodeSnippet))
        {
            yield return finding.CodeSnippet;
        }
    }

    private static IEnumerable<string> EnumerateCallChainTexts(CallChain chain)
    {
        yield return chain.Summary;
        yield return chain.RuleId;

        foreach (var node in chain.Nodes)
        {
            yield return node.Location;
            yield return node.Description;

            if (!string.IsNullOrWhiteSpace(node.CodeSnippet))
            {
                yield return node.CodeSnippet;
            }
        }
    }

    private static IEnumerable<string> EnumerateDataFlowTexts(DataFlowChain flow)
    {
        yield return flow.Summary;
        yield return flow.MethodLocation;
        yield return flow.Pattern.ToString();

        foreach (var node in flow.Nodes)
        {
            yield return node.Location;
            yield return node.Operation;
            yield return node.DataDescription;

            if (!string.IsNullOrWhiteSpace(node.MethodKey))
            {
                yield return node.MethodKey;
            }

            if (!string.IsNullOrWhiteSpace(node.TargetMethodKey))
            {
                yield return node.TargetMethodKey;
            }

            if (!string.IsNullOrWhiteSpace(node.CodeSnippet))
            {
                yield return node.CodeSnippet;
            }
        }
    }
}
