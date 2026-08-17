using MLVScan.Models;
using MLVScan.Models.DataFlow;
using MLVScan.Services.Helpers;
using Mono.Collections.Generic;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DataFlowMethodAnalyzer
    {
        private readonly DataFlowPatternEvaluator _patternEvaluator;
        private readonly DataFlowNodeFactory _nodeFactory;

        public DataFlowMethodAnalyzer(
            DataFlowPatternEvaluator patternEvaluator,
            DataFlowNodeFactory nodeFactory)
        {
            _patternEvaluator = patternEvaluator ?? throw new ArgumentNullException(nameof(patternEvaluator));
            _nodeFactory = nodeFactory ?? throw new ArgumentNullException(nameof(nodeFactory));
        }

        public DataFlowMethodAnalysisResult AnalyzeMethod(MethodDefinition method)
        {
            var instructions = method.Body.Instructions;
            var instructionHelper = new DataFlowInstructionHelper(instructions);
            var reachingDefinitionAnalysis = instructionHelper.GetReachingDefinitionAnalysis(instructions);
            var operationClassifier = new DataFlowOperationClassifier(instructionHelper);
            var operations = operationClassifier.IdentifyInterestingOperations(method, instructions);
            var flowInfo = BuildMethodFlowInfo(method, instructions, operations, instructionHelper);
            var chains = operations.Count < 2 ? new List<DataFlowChain>() : BuildDataFlowChains(method, instructions, operations);

            return new DataFlowMethodAnalysisResult
            {
                MethodKey = method.GetMethodKey(),
                Instructions = instructions,
                FlowInfo = flowInfo,
                Chains = chains,
                AnalysisComplete = reachingDefinitionAnalysis.IsComplete
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
            List<DataFlowInterestingOperation> operations)
        {
            var chains = new List<DataFlowChain>();

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
                    chains.Add(BuildChain(method, instructions, orderedOperations));
                }
            }

            chains.AddRange(BuildSequentialChains(method, instructions, operations));

            var directDownloadChain = BuildDirectDownloadToExecuteChain(method, instructions, operations);
            if (directDownloadChain != null)
            {
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

        private List<DataFlowChain> BuildSequentialChains(
            MethodDefinition method,
            Collection<Instruction> instructions,
            List<DataFlowInterestingOperation> operations)
        {
            const int maxInstructionDistance = 250;
            var chains = new List<DataFlowChain>();

            for (var index = 0; index < operations.Count - 1; index++)
            {
                var operation = operations[index];
                var subsequentOperations = operations
                    .Skip(index + 1)
                    .Where(candidate => candidate.InstructionIndex - operation.InstructionIndex <= maxInstructionDistance)
                    .ToList();

                if (subsequentOperations.Count == 0)
                {
                    continue;
                }

                var chainOperations = new List<DataFlowInterestingOperation> { operation };
                chainOperations.AddRange(subsequentOperations.Take(5));

                if (!chainOperations.Any(static candidate => candidate.NodeType == DataFlowNodeType.Sink))
                {
                    continue;
                }

                var pattern = _patternEvaluator.RecognizePattern(chainOperations);
                if (pattern != DataFlowPattern.Legitimate && pattern != DataFlowPattern.Unknown)
                {
                    chains.Add(BuildChain(method, instructions, chainOperations));
                }
            }

            return chains;
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
}
