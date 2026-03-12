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

    }
}
