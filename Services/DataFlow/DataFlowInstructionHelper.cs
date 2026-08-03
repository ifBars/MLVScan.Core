using MLVScan.Services.Helpers;
using Mono.Collections.Generic;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    internal static class DataFlowInstructionHelper
    {
        public static int? TryGetTargetLocalVariable(Collection<Instruction> instructions, int callIndex)
        {
            if (callIndex + 1 >= instructions.Count)
            {
                return null;
            }

            return instructions[callIndex + 1].TryGetStoredLocalIndex(out var localIndex) ? localIndex : null;
        }

        public static Dictionary<int, int> TryGetParameterMapping(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod)
        {
            var mapping = new Dictionary<int, int>();
            var paramCount = calledMethod.Parameters.Count;
            var foundParams = 0;

            for (var index = callIndex - 1; index >= 0 && foundParams < paramCount; index--)
            {
                var instruction = instructions[index];
                if (instruction.TryGetLocalIndex(out var localIndex))
                {
                    mapping[paramCount - 1 - foundParams] = localIndex;
                    foundParams++;
                    continue;
                }

                if (instruction.IsArgumentLoad() || instruction.IsSimpleConstantLoad())
                {
                    foundParams++;
                }
            }

            return mapping;
        }

        public static bool IsReturnValueUsed(Collection<Instruction> instructions, int callIndex)
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

        public static bool TryGetCallArgumentLocalVariable(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            int argumentIndex,
            out int localIndex)
        {
            localIndex = -1;
            return TryGetCallArgumentProducerIndex(
                       instructions, callIndex, calledMethod, argumentIndex, out var producerIndex) &&
                   instructions[producerIndex].TryGetLocalIndex(out localIndex);
        }

        public static bool TryGetCallReceiverLocalVariable(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            out int localIndex)
        {
            localIndex = -1;
            return TryGetCallReceiverProducerIndex(instructions, callIndex, calledMethod, out var producerIndex) &&
                   instructions[producerIndex].TryGetLocalIndex(out localIndex);
        }

        public static bool TryGetCallReceiverProducerIndex(
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
                if (!TryFindTopValueProducer(instructions, cursor, out var argumentProducer))
                {
                    return false;
                }

                cursor = argumentProducer - 1;
            }

            return TryFindTopValueProducer(instructions, cursor, out producerIndex);
        }

        private static bool TryGetCallArgumentProducerIndex(
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

                cursor = currentProducer - 1;
            }

            return false;
        }

        private static bool TryFindTopValueProducer(
            Collection<Instruction> instructions,
            int beforeIndex,
            out int producerIndex)
        {
            producerIndex = -1;
            var needed = 1;

            for (var index = beforeIndex; index >= 0; index--)
            {
                var instruction = instructions[index];
                needed -= instruction.GetPushCount();
                if (needed <= 0)
                {
                    producerIndex = index;
                    return true;
                }

                needed += instruction.GetPopCount();
            }

            return false;
        }

    }
}
