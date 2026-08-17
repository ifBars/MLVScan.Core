using MLVScan.Models;
using MLVScan.Models.DataFlow;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DeepCallChainAnalyzer
    {
        private readonly DataFlowPatternEvaluator _patternEvaluator;
        private readonly DataFlowNodeFactory _nodeFactory;
        private readonly int _maxCallChainDepth;

        public DeepCallChainAnalyzer(
            DataFlowPatternEvaluator patternEvaluator,
            DataFlowNodeFactory nodeFactory,
            int maxCallChainDepth)
        {
            _patternEvaluator = patternEvaluator ?? throw new ArgumentNullException(nameof(patternEvaluator));
            _nodeFactory = nodeFactory ?? throw new ArgumentNullException(nameof(nodeFactory));
            _maxCallChainDepth = maxCallChainDepth;
        }

        public IReadOnlyList<DataFlowChain> Analyze(
            DataFlowAnalysisState state,
            CrossMethodAnalysisBudget budget)
        {
            var chains = new List<DataFlowChain>();

            foreach (var pair in state.MethodFlowInfos)
            {
                foreach (var callSite in pair.Value.OutgoingCalls)
                {
                    if (!state.MethodFlowInfos.TryGetValue(callSite.TargetMethodKey, out var targetInfo))
                    {
                        continue;
                    }

                    if (!HasRootFlowIntoCall(pair.Value, callSite))
                        continue;

                    if (!budget.TryConsumeDeepEdge())
                        return chains;

                    var rootNode = new DataFlowCallChainNode
                    {
                        MethodInfo = pair.Value,
                        VisitedMethods = new HashSet<string>(StringComparer.Ordinal) { pair.Key, callSite.TargetMethodKey }
                    };

                    var targetNode = new DataFlowCallChainNode
                    {
                        MethodInfo = targetInfo,
                        IncomingCallSite = callSite,
                        VisitedMethods = rootNode.VisitedMethods
                    };

                    rootNode.ChildNodes.Add(targetNode);
                    ExploreCallChain(state, targetNode, targetInfo, 2, budget);

                    if (!budget.IsComplete)
                        return chains;

                    var deepChain = TryBuildDeepCallChain(state, rootNode, targetNode);
                    if (deepChain != null)
                    {
                        if (!budget.TryReserveChain())
                            return chains;

                        chains.Add(deepChain);
                    }
                }
            }

            return chains;
        }

        private static bool HasRootFlowIntoCall(
            DataFlowMethodFlowInfo rootInfo,
            DataFlowMethodCallSite callSite)
        {
            if (callSite.ParameterMapping.Count == 0)
                return false;

            var passedLocals = new HashSet<int>(callSite.ParameterMapping.Values);
            return rootInfo.Operations.Any(operation =>
                (operation.NodeType == DataFlowNodeType.Source ||
                 operation.NodeType == DataFlowNodeType.Transform) &&
                operation.LocalVariableIndex.HasValue &&
                operation.InstructionIndex < callSite.InstructionIndex &&
                passedLocals.Contains(operation.LocalVariableIndex.Value));
        }

        private void ExploreCallChain(
            DataFlowAnalysisState state,
            DataFlowCallChainNode currentNode,
            DataFlowMethodFlowInfo currentInfo,
            int currentDepth,
            CrossMethodAnalysisBudget budget)
        {
            if (currentDepth >= _maxCallChainDepth)
            {
                return;
            }

            foreach (var callSite in currentInfo.OutgoingCalls)
            {
                if (currentNode.VisitedMethods.Contains(callSite.TargetMethodKey) ||
                    !state.MethodFlowInfos.TryGetValue(callSite.TargetMethodKey, out var nextInfo))
                {
                    continue;
                }

                if (!budget.TryConsumeDeepEdge())
                    return;

                var childNode = new DataFlowCallChainNode
                {
                    MethodInfo = nextInfo,
                    IncomingCallSite = callSite,
                    VisitedMethods = new HashSet<string>(currentNode.VisitedMethods, StringComparer.Ordinal)
                    {
                        callSite.TargetMethodKey
                    }
                };

                currentNode.ChildNodes.Add(childNode);
                ExploreCallChain(state, childNode, nextInfo, currentDepth + 1, budget);

                if (!budget.IsComplete)
                    return;
            }
        }

        private DataFlowChain? TryBuildDeepCallChain(
            DataFlowAnalysisState state,
            DataFlowCallChainNode rootNode,
            DataFlowCallChainNode targetNode)
        {
            if (targetNode.IncomingCallSite == null)
            {
                return null;
            }

            var rootFlowOperations = rootNode.MethodInfo.Operations
                .Where(operation =>
                    (operation.NodeType == DataFlowNodeType.Source || operation.NodeType == DataFlowNodeType.Transform) &&
                    operation.LocalVariableIndex.HasValue &&
                    targetNode.IncomingCallSite.ParameterMapping.Values.Contains(operation.LocalVariableIndex.Value))
                .OrderBy(static operation => operation.InstructionIndex)
                .ToList();

            if (rootFlowOperations.Count == 0)
            {
                return null;
            }

            var sources = new List<(DataFlowMethodFlowInfo Info, DataFlowInterestingOperation Operation)>();
            var sinks = new List<(DataFlowMethodFlowInfo Info, DataFlowInterestingOperation Operation)>();
            var transforms = new List<(DataFlowMethodFlowInfo Info, DataFlowInterestingOperation Operation)>();
            var callSites = new List<(DataFlowMethodFlowInfo Caller, DataFlowMethodCallSite Site)>();

            CollectChainOperations(rootNode, sources, sinks, transforms, callSites);

            if (sources.Count == 0 || sinks.Count == 0)
            {
                return null;
            }

            var combinedOperations = new List<DataFlowInterestingOperation>();
            combinedOperations.AddRange(rootFlowOperations);
            combinedOperations.AddRange(transforms.Select(static entry => entry.Operation));
            combinedOperations.AddRange(sinks.Select(static entry => entry.Operation));
            var identityMappedOperations = CloneOperationsWithCallSitePathMappings(rootNode, combinedOperations);

            var pattern = _patternEvaluator.RecognizePattern(identityMappedOperations);
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
            {
                return null;
            }

            var involvedMethods = rootNode.VisitedMethods.ToList();
            var chain = new DataFlowChain(
                $"deep:{string.Join("->", involvedMethods)}",
                pattern,
                _patternEvaluator.DetermineSeverity(pattern),
                BuildDeepChainSummary(pattern, involvedMethods),
                rootNode.MethodInfo.MethodKey)
            {
                IsCrossMethod = true,
                InvolvedMethods = involvedMethods
            };

            foreach (var (info, operation) in sources)
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(
                    info.MethodKey,
                    info.DisplayName,
                    state.GetInstructionsForMethod(info.MethodKey),
                    operation));
            }

            foreach (var (caller, site) in callSites)
            {
                if (!state.MethodFlowInfos.TryGetValue(site.TargetMethodKey, out var targetInfo))
                {
                    continue;
                }

                chain.AppendNode(_nodeFactory.CreateBoundaryNode(
                    caller.MethodKey,
                    caller.DisplayName,
                    state.GetInstructionsForMethod(caller.MethodKey),
                    site.InstructionIndex,
                    site.InstructionOffset,
                    $"calls {targetInfo.DisplayName}",
                    "data passed via parameter",
                    targetInfo.MethodKey));
            }

            foreach (var (info, operation) in sinks)
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(
                    info.MethodKey,
                    info.DisplayName,
                    state.GetInstructionsForMethod(info.MethodKey),
                    operation));
            }

            return chain;
        }

        private static List<DataFlowInterestingOperation> CloneOperationsWithCallSitePathMappings(
            DataFlowCallChainNode rootNode,
            IEnumerable<DataFlowInterestingOperation> operations)
        {
            var clones = operations.Select(static operation => new DataFlowInterestingOperation
            {
                Instruction = operation.Instruction,
                InstructionIndex = operation.InstructionIndex,
                MethodReference = operation.MethodReference,
                NodeType = operation.NodeType,
                Operation = operation.Operation,
                DataDescription = operation.DataDescription,
                LocalVariableIndex = operation.LocalVariableIndex,
                PayloadPathIdentities = new HashSet<string>(
                    operation.PayloadPathIdentities, StringComparer.Ordinal)
            }).ToList();

            ApplyCallSitePathMappings(rootNode, clones);
            return clones;
        }

        private static void ApplyCallSitePathMappings(
            DataFlowCallChainNode callerNode,
            IReadOnlyCollection<DataFlowInterestingOperation> operations)
        {
            foreach (var calleeNode in callerNode.ChildNodes)
            {
                var callSite = calleeNode.IncomingCallSite;
                if (callSite != null)
                {
                    foreach (var (parameterIndex, localIndex) in callSite.ParameterMapping)
                    {
                        var callerLocalPrefix =
                            $"{callerNode.MethodInfo.MethodKey}::local:{localIndex}@";
                        var reachingStores = callSite.ParameterReachingStoreIndexes.TryGetValue(
                            parameterIndex, out var mappedStores)
                            ? mappedStores
                            : new HashSet<int>();
                        var callerPathIdentities = reachingStores.Count == 0
                            ? new HashSet<string>(StringComparer.Ordinal)
                            {
                                $"{callerLocalPrefix}parameter"
                            }
                            : reachingStores
                                .Select(index => $"{callerLocalPrefix}instruction:{index}")
                                .ToHashSet(StringComparer.Ordinal);
                        var calleeArgumentIdentity =
                            $"{calleeNode.MethodInfo.MethodKey}::argument:{parameterIndex}";
                        var callerOperations = operations
                            .Where(operation => operation.PayloadPathIdentities.Overlaps(callerPathIdentities))
                            .ToList();
                        var calleeOperations = operations
                            .Where(operation => operation.PayloadPathIdentities.Contains(calleeArgumentIdentity))
                            .ToList();
                        if (callerOperations.Count == 0 || calleeOperations.Count == 0)
                        {
                            continue;
                        }

                        var bridgeIdentity =
                            $"call:{callerNode.MethodInfo.MethodKey}@{callSite.InstructionIndex}:argument:{parameterIndex}";
                        foreach (var operation in callerOperations.Concat(calleeOperations))
                        {
                            operation.PayloadPathIdentities.Add(bridgeIdentity);
                        }
                    }

                    foreach (var (parameterIndex, callerParameterIndex) in callSite.ForwardedParameterMapping)
                    {
                        var callerArgumentIdentity =
                            $"{callerNode.MethodInfo.MethodKey}::argument:{callerParameterIndex}";
                        var calleeArgumentIdentity =
                            $"{calleeNode.MethodInfo.MethodKey}::argument:{parameterIndex}";
                        var callerOperations = operations
                            .Where(operation => operation.PayloadPathIdentities.Contains(callerArgumentIdentity))
                            .ToList();
                        var calleeOperations = operations
                            .Where(operation => operation.PayloadPathIdentities.Contains(calleeArgumentIdentity))
                            .ToList();
                        if (callerOperations.Count == 0 || calleeOperations.Count == 0)
                        {
                            continue;
                        }

                        var bridgeIdentity =
                            $"call:{callerNode.MethodInfo.MethodKey}@{callSite.InstructionIndex}:argument:{parameterIndex}";
                        foreach (var operation in callerOperations.Concat(calleeOperations))
                        {
                            operation.PayloadPathIdentities.Add(bridgeIdentity);
                        }
                    }
                }

                ApplyCallSitePathMappings(calleeNode, operations);
            }
        }

        private static void CollectChainOperations(
            DataFlowCallChainNode node,
            List<(DataFlowMethodFlowInfo Info, DataFlowInterestingOperation Operation)> sources,
            List<(DataFlowMethodFlowInfo Info, DataFlowInterestingOperation Operation)> sinks,
            List<(DataFlowMethodFlowInfo Info, DataFlowInterestingOperation Operation)> transforms,
            List<(DataFlowMethodFlowInfo Caller, DataFlowMethodCallSite Site)> callSites)
        {
            foreach (var operation in node.MethodInfo.Operations)
            {
                switch (operation.NodeType)
                {
                    case DataFlowNodeType.Source:
                        sources.Add((node.MethodInfo, operation));
                        break;
                    case DataFlowNodeType.Sink:
                        sinks.Add((node.MethodInfo, operation));
                        break;
                    case DataFlowNodeType.Transform:
                        transforms.Add((node.MethodInfo, operation));
                        break;
                }
            }

            if (node.IncomingCallSite != null)
            {
                callSites.Add((node.MethodInfo, node.IncomingCallSite));
            }

            foreach (var child in node.ChildNodes)
            {
                CollectChainOperations(child, sources, sinks, transforms, callSites);
            }
        }

        private static string BuildDeepChainSummary(DataFlowPattern pattern, IReadOnlyList<string> involvedMethods)
        {
            var description = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => "Multi-method embedded resource drop-and-execute pattern",
                DataFlowPattern.DownloadAndExecute => "Multi-method download and execute pattern",
                DataFlowPattern.DataExfiltration => "Multi-method data exfiltration pattern",
                DataFlowPattern.DynamicCodeLoading => "Multi-method dynamic code loading pattern",
                DataFlowPattern.CredentialTheft => "Multi-method credential theft pattern",
                DataFlowPattern.ObfuscatedPersistence => "Multi-method obfuscated persistence pattern",
                _ => "Multi-method suspicious data flow"
            };

            var methods = string.Join(" -> ", involvedMethods.Select(static method =>
            {
                var lastDot = method.LastIndexOf('.');
                return lastDot > 0 ? method[(lastDot + 1)..] : method;
            }));

            return $"{description}: {methods}";
        }
    }
}
