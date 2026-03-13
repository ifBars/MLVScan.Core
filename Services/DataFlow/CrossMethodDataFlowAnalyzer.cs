using MLVScan.Models;
using MLVScan.Models.DataFlow;

namespace MLVScan.Services.DataFlow
{
    internal sealed class CrossMethodDataFlowAnalyzer
    {
        private readonly DataFlowPatternEvaluator _patternEvaluator;
        private readonly DataFlowNodeFactory _nodeFactory;
        private readonly DataFlowAnalyzerConfig _config;
        private readonly DeepCallChainAnalyzer _deepCallChainAnalyzer;

        public CrossMethodDataFlowAnalyzer(
            DataFlowPatternEvaluator patternEvaluator,
            DataFlowNodeFactory nodeFactory,
            DataFlowAnalyzerConfig config)
        {
            _patternEvaluator = patternEvaluator ?? throw new ArgumentNullException(nameof(patternEvaluator));
            _nodeFactory = nodeFactory ?? throw new ArgumentNullException(nameof(nodeFactory));
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _deepCallChainAnalyzer = new DeepCallChainAnalyzer(patternEvaluator, nodeFactory, config.MaxCallChainDepth);
        }

        public IReadOnlyList<DataFlowChain> Analyze(DataFlowAnalysisState state)
        {
            if (!_config.EnableCrossMethodAnalysis)
            {
                return Array.Empty<DataFlowChain>();
            }

            var chains = new List<DataFlowChain>();

            foreach (var callerInfo in state.MethodFlowInfos.Values)
            {
                foreach (var callSite in callerInfo.OutgoingCalls)
                {
                    if (!state.MethodFlowInfos.TryGetValue(callSite.TargetMethodKey, out var calleeInfo))
                    {
                        continue;
                    }

                    var crossMethodChain = TryBuildCrossMethodChain(state, callerInfo, callSite, calleeInfo);
                    if (crossMethodChain != null)
                    {
                        chains.Add(crossMethodChain);
                    }

                    if (_config.EnableReturnValueTracking && callSite.CalledMethodReturnsData && callSite.ReturnValueUsed)
                    {
                        var returnValueChain = TryBuildReturnValueChain(state, callerInfo, callSite, calleeInfo);
                        if (returnValueChain != null)
                        {
                            chains.Add(returnValueChain);
                        }
                    }
                }
            }

            if (_config.MaxCallChainDepth > 2)
            {
                chains.AddRange(_deepCallChainAnalyzer.Analyze(state));
            }

            return chains;
        }

        private DataFlowChain? TryBuildCrossMethodChain(
            DataFlowAnalysisState state,
            DataFlowMethodFlowInfo callerInfo,
            DataFlowMethodCallSite callSite,
            DataFlowMethodFlowInfo calleeInfo)
        {
            if ((!callerInfo.HasSource && !callerInfo.HasTransform) || !calleeInfo.HasSink)
            {
                return null;
            }

            var callerFlowOperations = GetCallerOpsPassedIntoCall(callerInfo, callSite);
            if (callerFlowOperations.Count == 0)
            {
                return null;
            }

            var combinedOperations = callerFlowOperations
                .Concat(calleeInfo.Operations.Where(static operation => operation.NodeType == DataFlowNodeType.Sink))
                .OrderBy(static operation => operation.InstructionIndex)
                .ToList();

            var pattern = _patternEvaluator.RecognizePattern(combinedOperations);
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
            {
                return null;
            }

            var chain = new DataFlowChain(
                $"cross:{callerInfo.MethodKey}->{calleeInfo.MethodKey}",
                pattern,
                _patternEvaluator.DetermineSeverity(pattern),
                BuildCrossMethodSummary(pattern, callerInfo, calleeInfo),
                callerInfo.MethodKey)
            {
                IsCrossMethod = true,
                InvolvedMethods = new List<string> { callerInfo.MethodKey, calleeInfo.MethodKey }
            };

            foreach (var operation in callerFlowOperations)
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(
                    callerInfo.MethodKey,
                    callerInfo.DisplayName,
                    state.GetInstructionsForMethod(callerInfo.MethodKey),
                    operation));
            }

            chain.AppendNode(_nodeFactory.CreateBoundaryNode(
                callerInfo.MethodKey,
                callerInfo.DisplayName,
                state.GetInstructionsForMethod(callerInfo.MethodKey),
                callSite.InstructionIndex,
                callSite.InstructionOffset,
                $"calls {calleeInfo.DisplayName}",
                "data passed via parameter",
                calleeInfo.MethodKey));

            foreach (var operation in calleeInfo.Operations.Where(static operation => operation.NodeType == DataFlowNodeType.Sink))
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(
                    calleeInfo.MethodKey,
                    calleeInfo.DisplayName,
                    state.GetInstructionsForMethod(calleeInfo.MethodKey),
                    operation));
            }

            return chain;
        }

        private DataFlowChain? TryBuildReturnValueChain(
            DataFlowAnalysisState state,
            DataFlowMethodFlowInfo callerInfo,
            DataFlowMethodCallSite callSite,
            DataFlowMethodFlowInfo calleeInfo)
        {
            if ((!calleeInfo.ReturnsData && calleeInfo.ReturnProducingOperations.Count == 0) ||
                !callerInfo.Operations.Any(operation => operation.NodeType == DataFlowNodeType.Sink && operation.InstructionIndex > callSite.InstructionIndex))
            {
                return null;
            }

            var callerSinksAfterCall = callerInfo.Operations
                .Where(operation => operation.NodeType == DataFlowNodeType.Sink && operation.InstructionIndex > callSite.InstructionIndex)
                .OrderBy(static operation => operation.InstructionIndex)
                .ToList();

            var combinedOperations = calleeInfo.ReturnProducingOperations
                .OrderBy(static operation => operation.InstructionIndex)
                .Concat(callerSinksAfterCall)
                .ToList();

            var pattern = _patternEvaluator.RecognizePattern(combinedOperations);
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
            {
                return null;
            }

            var chain = new DataFlowChain(
                $"return:{calleeInfo.MethodKey}->{callerInfo.MethodKey}",
                pattern,
                _patternEvaluator.DetermineSeverity(pattern),
                BuildReturnValueSummary(pattern, callerInfo, calleeInfo),
                calleeInfo.MethodKey)
            {
                IsCrossMethod = true,
                InvolvedMethods = new List<string> { calleeInfo.MethodKey, callerInfo.MethodKey }
            };

            foreach (var operation in calleeInfo.ReturnProducingOperations)
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(
                    calleeInfo.MethodKey,
                    calleeInfo.DisplayName,
                    state.GetInstructionsForMethod(calleeInfo.MethodKey),
                    operation,
                    $"returns {operation.DataDescription}"));
            }

            chain.AppendNode(_nodeFactory.CreateBoundaryNode(
                callerInfo.MethodKey,
                callerInfo.DisplayName,
                state.GetInstructionsForMethod(callerInfo.MethodKey),
                callSite.InstructionIndex,
                callSite.InstructionOffset,
                $"receives return from {calleeInfo.DisplayName}",
                "return value passed to caller",
                calleeInfo.MethodKey));

            foreach (var operation in callerSinksAfterCall)
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(
                    callerInfo.MethodKey,
                    callerInfo.DisplayName,
                    state.GetInstructionsForMethod(callerInfo.MethodKey),
                    operation));
            }

            return chain;
        }

        private static string BuildCrossMethodSummary(
            DataFlowPattern pattern,
            DataFlowMethodFlowInfo callerInfo,
            DataFlowMethodFlowInfo calleeInfo)
        {
            var description = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => "Embedded resource drop-and-execute pattern",
                DataFlowPattern.DownloadAndExecute => "Download and execute pattern",
                DataFlowPattern.DataExfiltration => "Data exfiltration pattern",
                DataFlowPattern.DynamicCodeLoading => "Dynamic code loading pattern",
                DataFlowPattern.CredentialTheft => "Credential theft pattern",
                DataFlowPattern.ObfuscatedPersistence => "Obfuscated persistence pattern",
                _ => "Suspicious data flow"
            };

            return $"Cross-method {description}: {callerInfo.DisplayName} -> {calleeInfo.DisplayName}";
        }

        private static string BuildReturnValueSummary(
            DataFlowPattern pattern,
            DataFlowMethodFlowInfo callerInfo,
            DataFlowMethodFlowInfo calleeInfo)
        {
            var description = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => "Return-value embedded resource execution",
                DataFlowPattern.DownloadAndExecute => "Return-value download and execute",
                DataFlowPattern.DataExfiltration => "Return-value exfiltration",
                DataFlowPattern.DynamicCodeLoading => "Return-value code loading",
                DataFlowPattern.CredentialTheft => "Return-value credential theft",
                DataFlowPattern.ObfuscatedPersistence => "Return-value persistence",
                _ => "Return-value suspicious flow"
            };

            return $"{description}: {calleeInfo.DisplayName} returns -> {callerInfo.DisplayName}";
        }

        private static List<DataFlowInterestingOperation> GetCallerOpsPassedIntoCall(
            DataFlowMethodFlowInfo callerInfo,
            DataFlowMethodCallSite callSite)
        {
            if (callSite.ParameterMapping.Count == 0)
            {
                return new List<DataFlowInterestingOperation>();
            }

            var passedLocalIndexes = new HashSet<int>(callSite.ParameterMapping.Values);

            return callerInfo.Operations
                .Where(operation =>
                    (operation.NodeType == DataFlowNodeType.Source || operation.NodeType == DataFlowNodeType.Transform) &&
                    operation.LocalVariableIndex.HasValue &&
                    operation.InstructionIndex < callSite.InstructionIndex &&
                    passedLocalIndexes.Contains(operation.LocalVariableIndex.Value))
                .OrderBy(static operation => operation.InstructionIndex)
                .ToList();
        }
    }
}
