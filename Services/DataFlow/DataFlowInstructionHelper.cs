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
            return TryGetCallArgumentLocalVariable(
                instructions, callIndex, calledMethod, argumentIndex, out localIndex, out _);
        }

        public static bool TryGetCallArgumentLocalVariable(
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

        public static bool TryGetCallReceiverLocalVariable(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            out int localIndex)
        {
            localIndex = -1;
            return TryGetCallReceiverProducerIndex(instructions, callIndex, calledMethod, out var producerIndex) &&
                   TryGetLocalOrAddressedLocalIndex(instructions[producerIndex], out localIndex);
        }

        public static bool TryGetFieldStoreReceiverLocalVariable(
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

        public static IReadOnlyCollection<int> GetReachingLocalStoreIndexes(
            Collection<Instruction> instructions,
            int localLoadIndex,
            int localIndex)
        {
            if (localLoadIndex < 0 || localLoadIndex >= instructions.Count)
            {
                return Array.Empty<int>();
            }

            var instructionIndexes = instructions
                .Select((instruction, index) => (instruction, index))
                .ToDictionary(static entry => entry.instruction, static entry => entry.index);
            var predecessors = Enumerable.Range(0, instructions.Count)
                .Select(_ => new List<int>())
                .ToArray();

            for (var index = 0; index < instructions.Count; index++)
            {
                foreach (var successor in GetSuccessorIndexes(instructions, instructionIndexes, index))
                {
                    predecessors[successor].Add(index);
                }
            }

            var offsets = new HashSet<int>();
            var pending = new Stack<int>(predecessors[localLoadIndex]);
            var visited = new HashSet<int>();
            while (pending.Count > 0)
            {
                var index = pending.Pop();
                if (!visited.Add(index))
                {
                    continue;
                }

                if (instructions[index].TryGetStoredLocalIndex(out var storedLocalIndex) &&
                    storedLocalIndex == localIndex)
                {
                    offsets.Add(index);
                    continue;
                }

                foreach (var predecessor in predecessors[index])
                {
                    pending.Push(predecessor);
                }
            }

            return offsets;
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

        private static IEnumerable<int> GetSuccessorIndexes(
            Collection<Instruction> instructions,
            IReadOnlyDictionary<Instruction, int> instructionIndexes,
            int index)
        {
            var instruction = instructions[index];
            if (instruction.Operand is Instruction target)
            {
                yield return instructionIndexes[target];
            }
            else if (instruction.Operand is Instruction[] targets)
            {
                foreach (var switchTarget in targets)
                {
                    yield return instructionIndexes[switchTarget];
                }
            }

            if (index + 1 >= instructions.Count ||
                instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Return or FlowControl.Throw)
            {
                yield break;
            }

            yield return index + 1;
        }

        private static bool TryGetLocalOrAddressedLocalIndex(Instruction instruction, out int localIndex)
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
