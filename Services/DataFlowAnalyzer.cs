using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.DataFlow;
using MLVScan.Services.Diagnostics;
using Mono.Cecil;
using System.ComponentModel;

namespace MLVScan.Services
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    [Obsolete("Use ScanConfig to control data flow behavior. DataFlowAnalyzerConfig is an internal pipeline detail and will be removed in v2.0.")]
    public class DataFlowAnalyzerConfig
    {
        public bool EnableCrossMethodAnalysis { get; set; } = true;

        public int MaxCallChainDepth { get; set; } = 5;

        public bool EnableReturnValueTracking { get; set; } = true;
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    public class DataFlowAnalyzer
    {
        private readonly DataFlowAnalysisState _state = new();
        private readonly DataFlowMethodAnalyzer _methodAnalyzer;
        private readonly CrossMethodDataFlowAnalyzer _crossMethodAnalyzer;
        private readonly DataFlowPatternEvaluator _patternEvaluator;
        private readonly ScanTelemetryHub _telemetry;

#pragma warning disable CS0618
        public DataFlowAnalyzer(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder)
            : this(rules, snippetBuilder, new DataFlowAnalyzerConfig(), new ScanTelemetryHub())
        {
        }
#pragma warning restore CS0618

        [Obsolete("Use the overloads that rely on ScanConfig-driven behavior. DataFlowAnalyzerConfig is an internal pipeline detail and will be removed in v2.0.")]
        public DataFlowAnalyzer(
            IEnumerable<IScanRule> rules,
            CodeSnippetBuilder snippetBuilder,
            DataFlowAnalyzerConfig config)
            : this(rules, snippetBuilder, config, new ScanTelemetryHub())
        {
        }

        internal DataFlowAnalyzer(
            IEnumerable<IScanRule> rules,
            CodeSnippetBuilder snippetBuilder,
            ScanTelemetryHub telemetry)
            : this(rules, snippetBuilder, new DataFlowAnalyzerConfig(), telemetry)
        {
        }

        internal DataFlowAnalyzer(
            IEnumerable<IScanRule> rules,
            CodeSnippetBuilder snippetBuilder,
            DataFlowAnalyzerConfig config,
            ScanTelemetryHub telemetry)
        {
            if (rules == null)
            {
                throw new ArgumentNullException(nameof(rules));
            }

            if (snippetBuilder == null)
            {
                throw new ArgumentNullException(nameof(snippetBuilder));
            }

            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));

            var operationClassifier = new DataFlowOperationClassifier();
            var nodeFactory = new DataFlowNodeFactory(snippetBuilder);

            _patternEvaluator = new DataFlowPatternEvaluator();
            _methodAnalyzer = new DataFlowMethodAnalyzer(operationClassifier, _patternEvaluator, nodeFactory);
#pragma warning disable CS0618
            _crossMethodAnalyzer = new CrossMethodDataFlowAnalyzer(_patternEvaluator, nodeFactory, config);
#pragma warning restore CS0618
        }

        public void Clear()
        {
            _state.Clear();
        }

        public List<DataFlowChain> AnalyzeMethod(MethodDefinition method)
        {
            if (method?.Body == null || method.Body.Instructions.Count == 0)
            {
                _telemetry.IncrementCounter("DataFlowAnalyzer.MethodsSkipped");
                return new List<DataFlowChain>();
            }

            var analysisStart = _telemetry.StartTimestamp();
            var analysis = _methodAnalyzer.AnalyzeMethod(method);
            _telemetry.AddPhaseElapsed("DataFlowAnalyzer.AnalyzeMethod", analysisStart);
            _state.StoreMethodAnalysis(analysis);
            _telemetry.IncrementCounter("DataFlowAnalyzer.MethodsAnalyzed");
            _telemetry.IncrementCounter("DataFlowAnalyzer.MethodChainsBuilt", analysis.Chains.Count);
            _telemetry.IncrementCounter("DataFlowAnalyzer.SuspiciousMethodChains",
                analysis.Chains.Count(static chain => chain.IsSuspicious));

            return analysis.Chains;
        }

        public void AnalyzeCrossMethodFlows()
        {
            var crossMethodStart = _telemetry.StartTimestamp();
            var chains = _crossMethodAnalyzer.Analyze(_state);
            _telemetry.AddPhaseElapsed("DataFlowAnalyzer.AnalyzeCrossMethodFlows", crossMethodStart);
            _telemetry.IncrementCounter("DataFlowAnalyzer.CrossMethodChainsBuilt", chains.Count);

            foreach (var chain in chains)
            {
                if (chain.IsSuspicious)
                {
                    _state.CrossMethodChains.Add(chain);
                }
            }

            _telemetry.IncrementCounter("DataFlowAnalyzer.SuspiciousCrossMethodChains",
                _state.CrossMethodChains.Count(static chain => chain.IsSuspicious));
        }

        public IEnumerable<ScanFinding> BuildDataFlowFindings()
        {
            var buildFindingsStart = _telemetry.StartTimestamp();
            var findings = new List<ScanFinding>();

            foreach (var chain in _state.MethodDataFlows.Values.SelectMany(static list => list))
            {
                if (chain.IsSuspicious && _patternEvaluator.ShouldEmitFinding(chain.Pattern))
                {
                    findings.Add(_patternEvaluator.CreateFinding(chain));
                }
            }

            foreach (var chain in _state.CrossMethodChains)
            {
                if (chain.IsSuspicious && _patternEvaluator.ShouldEmitFinding(chain.Pattern))
                {
                    findings.Add(_patternEvaluator.CreateFinding(chain));
                }
            }

            _telemetry.AddPhaseElapsed("DataFlowAnalyzer.BuildDataFlowFindings", buildFindingsStart);
            _telemetry.IncrementCounter("DataFlowAnalyzer.FindingsEmitted", findings.Count);
            return findings;
        }

        public int DataFlowChainCount => _state.MethodDataFlows.Values.Sum(static list => list.Count);

        public int SuspiciousChainCount => _state.MethodDataFlows.Values
            .SelectMany(static list => list)
            .Count(static chain => chain.IsSuspicious);

        public int CrossMethodChainCount => _state.CrossMethodChains.Count;

        public int SuspiciousCrossMethodChainCount => _state.CrossMethodChains.Count(static chain => chain.IsSuspicious);
    }
}
