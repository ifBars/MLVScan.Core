using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.DataFlow;
using MLVScan.Services.Diagnostics;
using Mono.Cecil;
using System.ComponentModel;

namespace MLVScan.Services
{
    /// <summary>
    /// Legacy configuration for the data-flow analysis pipeline.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    [Obsolete("Use ScanConfig to control data flow behavior. DataFlowAnalyzerConfig is an internal pipeline detail and will be removed in v2.0.")]
    public class DataFlowAnalyzerConfig
    {
        /// <summary>
        /// Gets or sets a value indicating whether inter-procedural flow analysis is enabled.
        /// </summary>
        public bool EnableCrossMethodAnalysis { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum depth explored when following call chains.
        /// </summary>
        public int MaxCallChainDepth { get; set; } = 5;

        /// <summary>
        /// Gets or sets a value indicating whether return values should be tracked through the flow graph.
        /// </summary>
        public bool EnableReturnValueTracking { get; set; } = true;
    }

    /// <summary>
    /// Builds method and cross-method data-flow chains for suspicious operations.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class DataFlowAnalyzer
    {
        private readonly DataFlowAnalysisState _state = new();
        private readonly DataFlowMethodAnalyzer _methodAnalyzer;
        private readonly CrossMethodDataFlowAnalyzer _crossMethodAnalyzer;
        private readonly DataFlowPatternEvaluator _patternEvaluator;
        private readonly ScanTelemetryHub _telemetry;

#pragma warning disable CS0618
        /// <summary>
        /// Initializes the analyzer with the default legacy configuration.
        /// </summary>
        /// <param name="rules">The scan rules used when translating chains into findings.</param>
        /// <param name="snippetBuilder">Builds code snippets for emitted findings.</param>
        public DataFlowAnalyzer(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder)
            : this(rules, snippetBuilder, new DataFlowAnalyzerConfig(), new ScanTelemetryHub())
        {
        }
#pragma warning restore CS0618

        /// <summary>
        /// Initializes the analyzer with an explicit legacy configuration.
        /// </summary>
        /// <param name="rules">The scan rules used when translating chains into findings.</param>
        /// <param name="snippetBuilder">Builds code snippets for emitted findings.</param>
        /// <param name="config">The legacy data-flow configuration to apply.</param>
        [Obsolete("Use the overloads that rely on ScanConfig-driven behavior. DataFlowAnalyzerConfig is an internal pipeline detail and will be removed in v2.0.")]
        public DataFlowAnalyzer(
            IEnumerable<IScanRule> rules,
            CodeSnippetBuilder snippetBuilder,
            DataFlowAnalyzerConfig config)
            : this(rules, snippetBuilder, config, new ScanTelemetryHub())
        {
        }

#pragma warning disable CS0618
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
            _crossMethodAnalyzer = new CrossMethodDataFlowAnalyzer(_patternEvaluator, nodeFactory, config);
        }
#pragma warning restore CS0618

        /// <summary>
        /// Clears any previously collected flow state.
        /// </summary>
        public void Clear()
        {
            _state.Clear();
        }

        /// <summary>
        /// Analyzes a single method and records the discovered data-flow chains.
        /// </summary>
        /// <param name="method">The method to analyze.</param>
        /// <returns>The chains discovered within the method body.</returns>
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

        /// <summary>
        /// Expands the recorded method flows across call boundaries.
        /// </summary>
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

        /// <summary>
        /// Materializes findings from the recorded flow chains.
        /// </summary>
        /// <returns>The findings emitted from suspicious data-flow patterns.</returns>
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

        /// <summary>
        /// Gets the number of intra-method chains currently stored.
        /// </summary>
        public int DataFlowChainCount => _state.MethodDataFlows.Values.Sum(static list => list.Count);

        /// <summary>
        /// Gets the number of suspicious intra-method chains currently stored.
        /// </summary>
        public int SuspiciousChainCount => _state.MethodDataFlows.Values
            .SelectMany(static list => list)
            .Count(static chain => chain.IsSuspicious);

        /// <summary>
        /// Gets the number of cross-method chains currently stored.
        /// </summary>
        public int CrossMethodChainCount => _state.CrossMethodChains.Count;

        /// <summary>
        /// Gets the number of suspicious cross-method chains currently stored.
        /// </summary>
        public int SuspiciousCrossMethodChainCount => _state.CrossMethodChains.Count(static chain => chain.IsSuspicious);
    }
}
