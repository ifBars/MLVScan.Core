using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.DataFlow;
using Mono.Cecil;

namespace MLVScan.Services
{
    public class DataFlowAnalyzerConfig
    {
        public bool EnableCrossMethodAnalysis { get; set; } = true;

        public int MaxCallChainDepth { get; set; } = 5;

        public bool EnableReturnValueTracking { get; set; } = true;
    }

    public class DataFlowAnalyzer
    {
        private readonly DataFlowAnalysisState _state = new();
        private readonly DataFlowMethodAnalyzer _methodAnalyzer;
        private readonly CrossMethodDataFlowAnalyzer _crossMethodAnalyzer;
        private readonly DataFlowPatternEvaluator _patternEvaluator;

        public DataFlowAnalyzer(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder)
            : this(rules, snippetBuilder, new DataFlowAnalyzerConfig())
        {
        }

        public DataFlowAnalyzer(
            IEnumerable<IScanRule> rules,
            CodeSnippetBuilder snippetBuilder,
            DataFlowAnalyzerConfig config)
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

            var operationClassifier = new DataFlowOperationClassifier();
            var nodeFactory = new DataFlowNodeFactory(snippetBuilder);

            _patternEvaluator = new DataFlowPatternEvaluator();
            _methodAnalyzer = new DataFlowMethodAnalyzer(operationClassifier, _patternEvaluator, nodeFactory);
            _crossMethodAnalyzer = new CrossMethodDataFlowAnalyzer(_patternEvaluator, nodeFactory, config);
        }

        public void Clear()
        {
            _state.Clear();
        }

        public List<DataFlowChain> AnalyzeMethod(MethodDefinition method)
        {
            if (method?.Body == null || method.Body.Instructions.Count == 0)
            {
                return new List<DataFlowChain>();
            }

            var analysis = _methodAnalyzer.AnalyzeMethod(method);
            _state.StoreMethodAnalysis(analysis);

            return analysis.Chains;
        }

        public void AnalyzeCrossMethodFlows()
        {
            foreach (var chain in _crossMethodAnalyzer.Analyze(_state))
            {
                if (chain.IsSuspicious)
                {
                    _state.CrossMethodChains.Add(chain);
                }
            }
        }

        public IEnumerable<ScanFinding> BuildDataFlowFindings()
        {
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
