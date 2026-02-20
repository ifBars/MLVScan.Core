using System.Diagnostics;
using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Services.DeepBehavior;

public sealed class DeepBehaviorOrchestrator
{
    private readonly DeepBehaviorAnalysisConfig _config;
    private readonly List<DeepBehaviorAnalyzer> _analyzers;
    private readonly HashSet<string> _seenMethods = new(StringComparer.Ordinal);

    private int _deepMethodCount;

    public DeepBehaviorOrchestrator(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));

        _analyzers =
        [
            new NativeInteropCorrelationAnalyzer(config, snippetBuilder),
            new ExecutionChainAnalyzer(config, snippetBuilder),
            new StringDecodeFlowAnalyzer(config, snippetBuilder),
            new ResourcePayloadAnalyzer(config, snippetBuilder),
            new DynamicLoadCorrelationAnalyzer(config, snippetBuilder),
            new ScriptHostLaunchAnalyzer(config, snippetBuilder),
            new EnvironmentPivotAnalyzer(config, snippetBuilder)
        ];
    }

    public int DeepMethodCount => _deepMethodCount;

    public void Reset()
    {
        _seenMethods.Clear();
        _deepMethodCount = 0;
    }

    public bool ShouldDeepScan(MethodDefinition method, MethodSignals signals, IReadOnlyList<ScanFinding> methodFindings)
    {
        if (!_config.EnableDeepAnalysis || method.Body == null)
        {
            return false;
        }

        if (_deepMethodCount >= _config.MaxDeepMethodsPerAssembly)
        {
            return false;
        }

        if (!_config.DeepScanOnlyFlaggedMethods)
        {
            return true;
        }

        if (methodFindings.Any(f => f.RuleId != null && DeepBehaviorRuleSets.SeedRuleIds.Contains(f.RuleId)))
        {
            return true;
        }

        if (signals.IsCriticalCombination() || signals.IsHighRiskCombination())
        {
            return true;
        }

        if (signals.SignalCount >= 3)
        {
            return true;
        }

        return IsLikelyEntrypoint(method) && methodFindings.Count > 0;
    }

    public IEnumerable<ScanFinding> AnalyzeMethod(
        MethodDefinition method,
        MethodSignals signals,
        IReadOnlyList<ScanFinding> methodFindings,
        IReadOnlyList<ScanFinding> typeFindings,
        IReadOnlyList<ScanFinding> namespaceFindings)
    {
        if (method.Body == null)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var methodKey = BuildMethodKey(method);
        if (!_seenMethods.Add(methodKey))
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = signals,
            MethodFindings = methodFindings,
            TypeFindings = typeFindings,
            NamespaceFindings = namespaceFindings
        };

        var findings = new List<ScanFinding>();
        var stopwatch = Stopwatch.StartNew();

        foreach (var analyzer in _analyzers)
        {
            if (stopwatch.ElapsedMilliseconds > _config.MaxAnalysisTimeMsPerMethod)
            {
                break;
            }

            findings.AddRange(analyzer.Analyze(context));
        }

        _deepMethodCount++;
        return findings
            .GroupBy(finding => $"{finding.RuleId}|{finding.Location}|{finding.Description}|{finding.Severity}", StringComparer.Ordinal)
            .Select(group => group.First())
            .ToList();
    }

    private static string BuildMethodKey(MethodDefinition method)
    {
        return $"{method.DeclaringType?.FullName}:{method.Name}:{method.MetadataToken.ToInt32()}";
    }

    private static bool IsLikelyEntrypoint(MethodDefinition method)
    {
        var name = method.Name ?? string.Empty;
        return name.StartsWith("OnInitializeMelon", StringComparison.Ordinal) ||
               name.StartsWith("OnApplicationStart", StringComparison.Ordinal) ||
               name.StartsWith("Awake", StringComparison.Ordinal) ||
               name.StartsWith("Start", StringComparison.Ordinal) ||
               name.StartsWith("Initialize", StringComparison.Ordinal) ||
               name.Contains("Patch", StringComparison.Ordinal) ||
               name.StartsWith("OnEnable", StringComparison.Ordinal);
    }
}
