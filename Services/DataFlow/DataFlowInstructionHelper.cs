using MLVScan.Services.Helpers;
using Mono.Collections.Generic;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DataFlowInstructionHelper
    {
        private readonly Collection<Instruction> _instructions;
        private readonly DataFlowReachingDefinitionAnalysis _reachingDefinitionAnalysis;

        public DataFlowInstructionHelper(Collection<Instruction> instructions)
        {
            _instructions = instructions ?? throw new ArgumentNullException(nameof(instructions));
            _reachingDefinitionAnalysis = new DataFlowReachingDefinitionAnalysis(instructions);
        }

        public int? TryGetTargetLocalVariable(Collection<Instruction> instructions, int callIndex)
        {
            if (callIndex + 1 >= instructions.Count)
            {
                return null;
            }

            return instructions[callIndex + 1].TryGetStoredLocalIndex(out var localIndex) ? localIndex : null;
        }

        public Dictionary<int, int> TryGetParameterMapping(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod)
        {
            var mapping = new Dictionary<int, int>();
            for (var parameterIndex = 0; parameterIndex < calledMethod.Parameters.Count; parameterIndex++)
            {
                if (TryGetCallArgumentLocalVariable(
                        instructions, callIndex, calledMethod, parameterIndex, out var localIndex))
                {
                    mapping[parameterIndex] = localIndex;
                }
            }

            return mapping;
        }

        public bool IsReturnValueUsed(Collection<Instruction> instructions, int callIndex)
        {
            if (callIndex + 1 >= instructions.Count)
            {
                return false;
            }

            var nextInstruction = instructions[callIndex + 1];

            if (nextInstruction.TryGetStoredLocalIndex(out _))
            {
                return true;
            }

            return nextInstruction.OpCode == OpCodes.Call ||
                   nextInstruction.OpCode == OpCodes.Callvirt ||
                   nextInstruction.OpCode == OpCodes.Stfld ||
                   nextInstruction.OpCode == OpCodes.Stsfld;
        }

        public bool TryGetCallArgumentLocalVariable(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            int argumentIndex,
            out int localIndex)
        {
            return TryGetCallArgumentLocalVariable(
                instructions, callIndex, calledMethod, argumentIndex, out localIndex, out _);
        }

        public bool TryGetCallArgumentLocalVariable(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            int argumentIndex,
            out int localIndex,
            out int producerIndex)
        {
            localIndex = -1;
            producerIndex = -1;
            return TryGetCallArgumentProducerIndex(
                       instructions, callIndex, calledMethod, argumentIndex, out producerIndex) &&
                   TryGetLocalOrAddressedLocalIndex(instructions[producerIndex], out localIndex);
        }

        public bool TryGetMethodParameterIndex(
            MethodDefinition method,
            Instruction instruction,
            out int parameterIndex)
        {
            parameterIndex = -1;
            if (!instruction.TryGetArgumentIndex(out var rawIndex))
            {
                return false;
            }

            parameterIndex = instruction.Operand is ParameterDefinition parameter
                ? parameter.Index
                : rawIndex - (method.HasThis ? 1 : 0);
            return parameterIndex >= 0 && parameterIndex < method.Parameters.Count;
        }

        public bool TryGetCallReceiverLocalVariable(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            out int localIndex)
        {
            localIndex = -1;
            return TryGetCallReceiverProducerIndex(instructions, callIndex, calledMethod, out var producerIndex) &&
                   TryGetLocalOrAddressedLocalIndex(instructions[producerIndex], out localIndex);
        }

        public bool TryGetFieldStoreReceiverLocalVariable(
            Collection<Instruction> instructions,
            int fieldStoreIndex,
            out int localIndex)
        {
            localIndex = -1;
            if (fieldStoreIndex <= 0 ||
                !TryFindTopValueProducer(instructions, fieldStoreIndex - 1, out var valueProducerIndex) ||
                !TryFindTopValueProducer(instructions, valueProducerIndex - 1, out var receiverProducerIndex))
            {
                return false;
            }

            return TryGetLocalOrAddressedLocalIndex(instructions[receiverProducerIndex], out localIndex);
        }

        public IReadOnlyCollection<int> GetReachingLocalStoreIndexes(
            Collection<Instruction> instructions,
            int localLoadIndex,
            int localIndex)
        {
            return GetReachingDefinitionAnalysis(instructions).TryGetReachingLocalStoreIndexes(
                localLoadIndex,
                localIndex,
                out var definitionIndexes)
                    ? definitionIndexes
                    : Array.Empty<int>();
        }

        public IReadOnlyCollection<int> GetReachingInstructionIndexes(
            Collection<Instruction> instructions,
            int consumerIndex,
            Func<int, bool> isDefinition)
        {
            return GetReachingDefinitionAnalysis(instructions).TryGetReachingInstructionIndexes(
                consumerIndex,
                isDefinition,
                out var definitionIndexes)
                    ? definitionIndexes
                    : Array.Empty<int>();
        }

        public DataFlowReachingDefinitionAnalysis GetReachingDefinitionAnalysis(
            Collection<Instruction> instructions)
        {
            if (!ReferenceEquals(instructions, _instructions))
            {
                throw new ArgumentException(
                    "The instruction collection must match this method analysis.",
                    nameof(instructions));
            }

            return _reachingDefinitionAnalysis;
        }

        public bool TryGetCallReceiverProducerIndex(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            out int producerIndex)
        {
            producerIndex = -1;
            if (!calledMethod.HasThis || callIndex <= 0)
            {
                return false;
            }

            var cursor = callIndex - 1;
            for (var argumentIndex = calledMethod.Parameters.Count - 1; argumentIndex >= 0; argumentIndex--)
            {
                if (!TryFindTopValueProducer(instructions, cursor, out var argumentProducer) ||
                    !TryFindValueExpressionStart(instructions, argumentProducer, out var argumentStart))
                {
                    return false;
                }

                cursor = argumentStart - 1;
            }

            return TryFindTopValueProducer(instructions, cursor, out producerIndex);
        }

        public bool TryGetConsumedValueProducerIndex(
            Collection<Instruction> instructions,
            int consumerIndex,
            out int producerIndex)
        {
            producerIndex = -1;
            return consumerIndex > 0 &&
                   TryFindTopValueProducer(instructions, consumerIndex - 1, out producerIndex);
        }

        public bool TryGetCallArgumentProducerIndex(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            int argumentIndex,
            out int producerIndex)
        {
            producerIndex = -1;
            if (argumentIndex < 0 || argumentIndex >= calledMethod.Parameters.Count || callIndex <= 0)
            {
                return false;
            }

            var cursor = callIndex - 1;
            for (var currentArgument = calledMethod.Parameters.Count - 1; currentArgument >= 0; currentArgument--)
            {
                if (!TryFindTopValueProducer(instructions, cursor, out var currentProducer))
                {
                    return false;
                }

                if (currentArgument == argumentIndex)
                {
                    producerIndex = currentProducer;
                    return true;
                }

                if (!TryFindValueExpressionStart(instructions, currentProducer, out var expressionStart))
                {
                    return false;
                }

                cursor = expressionStart - 1;
            }

            return false;
        }

        private bool TryFindTopValueProducer(
            Collection<Instruction> instructions,
            int beforeIndex,
            out int producerIndex)
        {
            return GetReachingDefinitionAnalysis(instructions)
                .TryFindTopValueProducer(beforeIndex, out producerIndex);
        }

        private bool TryFindValueExpressionStart(
            Collection<Instruction> instructions,
            int producerIndex,
            out int expressionStart)
        {
            return GetReachingDefinitionAnalysis(instructions)
                .TryFindValueExpressionStart(producerIndex, out expressionStart);
        }

        private bool TryGetLocalOrAddressedLocalIndex(Instruction instruction, out int localIndex)
        {
            if (instruction.TryGetLocalIndex(out localIndex))
            {
                return true;
            }

            if ((instruction.OpCode == OpCodes.Ldloca || instruction.OpCode == OpCodes.Ldloca_S) &&
                instruction.Operand is VariableDefinition local)
            {
                localIndex = local.Index;
                return true;
            }

            localIndex = -1;
            return false;
        }

    }
}
