using MLVScan.Models;
using MLVScan.Models.DataFlow;
using MLVScan.Services.Helpers;
using Mono.Collections.Generic;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
#pragma warning disable CS0618
    internal sealed class DataFlowMethodAnalyzer
    {
        private readonly DataFlowPatternEvaluator _patternEvaluator;
        private readonly DataFlowNodeFactory _nodeFactory;
        private readonly DataFlowAnalyzerConfig _config;

        public DataFlowMethodAnalyzer(
            DataFlowPatternEvaluator patternEvaluator,
            DataFlowNodeFactory nodeFactory,
            DataFlowAnalyzerConfig config)
        {
            _patternEvaluator = patternEvaluator ?? throw new ArgumentNullException(nameof(patternEvaluator));
            _nodeFactory = nodeFactory ?? throw new ArgumentNullException(nameof(nodeFactory));
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public DataFlowMethodAnalysisResult AnalyzeMethod(MethodDefinition method)
        {
            var instructions = method.Body.Instructions;
            var instructionHelper = new DataFlowInstructionHelper(instructions);
            var reachingDefinitionAnalysis = instructionHelper.GetReachingDefinitionAnalysis(instructions);
            var operationClassifier = new DataFlowOperationClassifier(instructionHelper);
            var identifiedOperations = operationClassifier.IdentifyInterestingOperations(method, instructions);
            var operations = identifiedOperations
                .Take(_config.MaxDataFlowOperationsPerMethod)
                .ToList();
            bool operationsComplete = identifiedOperations.Count <= _config.MaxDataFlowOperationsPerMethod;
            var flowInfo = BuildMethodFlowInfo(method, instructions, operations, instructionHelper);
            bool chainsComplete = true;
            var chains = operations.Count < 2
                ? new List<DataFlowChain>()
                : BuildDataFlowChains(method, instructions, operations, out chainsComplete);

            return new DataFlowMethodAnalysisResult
            {
                MethodKey = method.GetMethodKey(),
                Instructions = instructions,
                FlowInfo = flowInfo,
                Chains = chains,
                AnalysisComplete = reachingDefinitionAnalysis.IsComplete && operationsComplete && chainsComplete
            };
        }

        private DataFlowMethodFlowInfo BuildMethodFlowInfo(
            MethodDefinition method,
            Collection<Instruction> instructions,
            List<DataFlowInterestingOperation> operations,
            DataFlowInstructionHelper instructionHelper)
        {
            var returnTypeName = method.ReturnType.FullName == "System.Void" ? null : method.ReturnType.FullName;
            var returnsData = returnTypeName != null && operations.Any(static operation =>
                operation.NodeType == DataFlowNodeType.Source || operation.NodeType == DataFlowNodeType.Transform);

            var info = new DataFlowMethodFlowInfo
            {
                MethodKey = method.GetMethodKey(),
                DisplayName = $"{method.DeclaringType?.Name}.{method.Name}",
                HasSource = operations.Any(static operation => operation.NodeType == DataFlowNodeType.Source),
                HasSink = operations.Any(static operation => operation.NodeType == DataFlowNodeType.Sink),
                HasTransform = operations.Any(static operation => operation.NodeType == DataFlowNodeType.Transform),
                ReturnsData = returnsData,
                ReturnTypeName = returnTypeName,
                Operations = operations,
                ReturnProducingOperations = operations
                    .Where(static operation => operation.NodeType == DataFlowNodeType.Source || operation.NodeType == DataFlowNodeType.Transform)
                    .ToList()
            };

            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];
                if (!instruction.IsCallOrCallvirt() ||
                    instruction.Operand is not MethodReference calledMethod)
                {
                    continue;
                }

                var parameterMapping = instructionHelper.TryGetParameterMapping(
                    instructions, index, calledMethod);
                var parameterReachingStoreIndexes = new Dictionary<int, HashSet<int>>();
                var forwardedParameterMapping = new Dictionary<int, int>();
                foreach (var (parameterIndex, localIndex) in parameterMapping)
                {
                    if (!instructionHelper.TryGetCallArgumentProducerIndex(
                            instructions, index, calledMethod, parameterIndex, out var producerIndex))
                    {
                        continue;
                    }

                    parameterReachingStoreIndexes[parameterIndex] = instructionHelper
                        .GetReachingLocalStoreIndexes(instructions, producerIndex, localIndex)
                        .ToHashSet();
                }
                for (var parameterIndex = 0; parameterIndex < calledMethod.Parameters.Count; parameterIndex++)
                {
                    if (instructionHelper.TryGetCallArgumentProducerIndex(
                            instructions, index, calledMethod, parameterIndex, out var producerIndex) &&
                        instructionHelper.TryGetMethodParameterIndex(
                            method, instructions[producerIndex], out var callerParameterIndex))
                    {
                        forwardedParameterMapping[parameterIndex] = callerParameterIndex;
                    }
                }

                info.OutgoingCalls.Add(new DataFlowMethodCallSite
                {
                    TargetMethodKey = calledMethod.GetMethodKey(),
                    TargetDisplayName = calledMethod.GetDisplayName(),
                    InstructionOffset = instruction.Offset,
                    InstructionIndex = index,
                    ParameterMapping = parameterMapping,
                    ParameterReachingStoreIndexes = parameterReachingStoreIndexes,
                    ForwardedParameterMapping = forwardedParameterMapping,
                    ReturnValueUsed = instructionHelper.IsReturnValueUsed(instructions, index),
                    CalledMethodReturnsData = calledMethod.ReturnType.FullName != "System.Void"
                });
            }

            return info;
        }

        private List<DataFlowChain> BuildDataFlowChains(
            MethodDefinition method,
            Collection<Instruction> instructions,
            List<DataFlowInterestingOperation> operations,
            out bool analysisComplete)
        {
            var chains = new List<DataFlowChain>();
            analysisComplete = true;

            var operationsByVariable = operations
                .Where(static operation => operation.LocalVariableIndex.HasValue)
                .GroupBy(static operation => operation.LocalVariableIndex!.Value)
                .Where(static group => group.Count() > 1)
                .ToList();

            foreach (var group in operationsByVariable)
            {
                var orderedOperations = group.OrderBy(static operation => operation.InstructionIndex).ToList();
                var hasSource = orderedOperations.Any(static operation => operation.NodeType == DataFlowNodeType.Source);
                var hasTransform = orderedOperations.Any(static operation => operation.NodeType == DataFlowNodeType.Transform);
                var hasSink = orderedOperations.Any(static operation => operation.NodeType == DataFlowNodeType.Sink);

                if ((hasSource || hasTransform) && hasSink)
                {
                    if (chains.Count >= _config.MaxDataFlowChainsPerMethod)
                    {
                        analysisComplete = false;
                        return chains;
                    }

                    chains.Add(BuildChain(method, instructions, orderedOperations));
                }
            }

            if (!AppendSequentialChains(method, instructions, operations, chains))
            {
                analysisComplete = false;
                return chains;
            }

            var directDownloadChain = BuildDirectDownloadToExecuteChain(method, instructions, operations);
            if (directDownloadChain != null)
            {
                if (chains.Count >= _config.MaxDataFlowChainsPerMethod)
                {
                    analysisComplete = false;
                    return chains;
                }

                chains.Add(directDownloadChain);
            }

            return chains;
        }

        private DataFlowChain? BuildDirectDownloadToExecuteChain(
            MethodDefinition method,
            Collection<Instruction> instructions,
            List<DataFlowInterestingOperation> operations)
        {
            var downloadSource = operations.FirstOrDefault(static operation =>
                operation.NodeType == DataFlowNodeType.Source &&
                (operation.MethodReference.Name.Equals("DownloadFile", StringComparison.OrdinalIgnoreCase) ||
                 operation.MethodReference.Name.Equals("DownloadFileTaskAsync", StringComparison.OrdinalIgnoreCase)));

            if (downloadSource == null)
            {
                return null;
            }

            var downloadSink = operations.FirstOrDefault(operation =>
                operation.NodeType == DataFlowNodeType.Sink &&
                operation.InstructionIndex == downloadSource.InstructionIndex &&
                operation.MethodReference.FullName == downloadSource.MethodReference.FullName);

            var processStart = operations.FirstOrDefault(operation =>
                operation.NodeType == DataFlowNodeType.Sink &&
                operation.InstructionIndex > downloadSource.InstructionIndex &&
                operation.Operation.Contains("Process.Start", StringComparison.OrdinalIgnoreCase));

            if (downloadSink == null || processStart == null)
            {
                return null;
            }

            return BuildChain(method, instructions, new List<DataFlowInterestingOperation>
            {
                downloadSource,
                downloadSink,
                processStart
            });
        }

        private bool AppendSequentialChains(
            MethodDefinition method,
            Collection<Instruction> instructions,
            List<DataFlowInterestingOperation> operations,
            List<DataFlowChain> chains)
        {
            const int maxInstructionDistance = 250;

            for (var index = 0; index < operations.Count - 1; index++)
            {
                var operation = operations[index];
                var chainOperations = new List<DataFlowInterestingOperation>(6) { operation };
                for (int candidateIndex = index + 1;
                     candidateIndex < operations.Count && chainOperations.Count < 6;
                     candidateIndex++)
                {
                    var candidate = operations[candidateIndex];
                    if (candidate.InstructionIndex - operation.InstructionIndex > maxInstructionDistance)
                        break;

                    chainOperations.Add(candidate);
                }

                if (chainOperations.Count == 1 ||
                    !chainOperations.Any(static candidate => candidate.NodeType == DataFlowNodeType.Sink))
                {
                    continue;
                }

                var pattern = _patternEvaluator.RecognizePattern(chainOperations);
                if (pattern != DataFlowPattern.Legitimate && pattern != DataFlowPattern.Unknown)
                {
                    if (chains.Count >= _config.MaxDataFlowChainsPerMethod)
                        return false;

                    chains.Add(BuildChain(method, instructions, chainOperations));
                }
            }

            return true;
        }

        private DataFlowChain BuildChain(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            List<DataFlowInterestingOperation> operations)
        {
            var pattern = _patternEvaluator.RecognizePattern(operations);
            var severity = _patternEvaluator.DetermineSeverity(pattern);
            var methodLocation = method.GetMethodLocation();
            var chainId = $"{methodLocation}:{string.Join("-", operations.Select(static operation => operation.Instruction.Offset))}";
            var chain = new DataFlowChain(
                chainId,
                pattern,
                severity,
                _patternEvaluator.BuildSummary(pattern, operations.Count),
                methodLocation);

            foreach (var operation in operations)
            {
                chain.AppendNode(_nodeFactory.CreateOperationNode(methodLocation, methodLocation, instructions, operation));
            }

            return chain;
        }
    }
#pragma warning restore CS0618
}
