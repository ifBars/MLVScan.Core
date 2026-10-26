using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers;

/// <summary>
/// Follows argument identities to execution targets without treating unrelated transforms or reflection as execution.
/// </summary>
internal static class ExecutionTargetMatcher
{
    internal static bool TryGetArgumentSource(MethodDefinition method, int callIndex, int argument, out int source)
    {
        source = -1;
        return method.Body.Instructions[callIndex].Operand is MethodReference called &&
               InstructionValueResolver.TryResolveCallArgumentIdentity(called, method.Body.Instructions, callIndex,
                   argument, method.Body.ExceptionHandlers.ToArray(), out string identity) &&
               TryGetSource(identity, method.Body.Instructions.Count, out source);
    }

    internal static bool TryGetReceiverSource(MethodDefinition method, int callIndex, out int source)
    {
        source = -1;
        return InstructionValueResolver.TryResolveCallReceiverIdentity(method.Body.Instructions, callIndex,
                   method.Body.ExceptionHandlers.ToArray(), out string identity) &&
               TryGetSource(identity, method.Body.Instructions.Count, out source);
    }

    private static bool TryGetSource(string identity, int count, out int source)
    {
        source = -1;
        int separator = identity.IndexOf(':');
        return separator > 0 && identity[..separator] is "call" or "new" or "array" or "literal" &&
               int.TryParse(identity[(separator + 1)..], out source) && source >= 0 && source < count;
    }

    internal static bool IsReflectedProcessStart(MethodDefinition method, int useIndex, bool emitted)
    {
        if (!(emitted
                ? TryGetArgumentSource(method, useIndex, 1, out int getMethod)
                : TryGetReceiverSource(method, useIndex, out getMethod)))
        {
            return false;
        }

        var instructions = method.Body.Instructions;
        if (!IsCall(instructions[getMethod], "System.Type", "GetMethod") ||
            !InstructionValueResolver.TryResolveCallArgumentDisplay(method,
                (MethodReference)instructions[getMethod].Operand, instructions, getMethod, 0, out string member) ||
            member != "Start" || !TryGetReceiverSource(method, getMethod, out int getType))
        {
            return false;
        }

        return getType > 0 && IsCall(instructions[getType], "System.Type", "GetTypeFromHandle") &&
               instructions[getType - 1].OpCode == OpCodes.Ldtoken &&
               instructions[getType - 1].Operand is TypeReference { FullName: "System.Diagnostics.Process" };
    }

    internal static bool TryMatchReconstructedTarget(MethodDefinition method, int useIndex, out string transform)
    {
        transform = string.Empty;
        if (!TryGetArgumentSource(method, useIndex, 0, out int source))
        {
            return false;
        }

        var instructions = method.Body.Instructions;
        if (IsCall(instructions[source], "System.Text.Encoding", "GetString") &&
            TryGetArgumentSource(method, source, 0, out int bytes) &&
            (IsCall(instructions[bytes], "System.Convert", "FromBase64String") ||
             IsCall(instructions[bytes], "System.Convert", "FromHexString")))
        {
            transform = "decoded bytes → string → process target";
            return true;
        }

        if (instructions[source].OpCode != OpCodes.Newobj ||
            instructions[source].Operand is not MethodReference constructor ||
            constructor.DeclaringType.FullName != "System.String" ||
            constructor.Parameters.Count == 0 || constructor.Parameters[0].ParameterType.FullName != "System.Char[]" ||
            !TryGetArgumentSource(method, source, 0, out int array))
        {
            return false;
        }

        int copies = 0;
        for (int index = array + 1; index < source; index++)
        {
            if (IsCall(instructions[index], "System.Array", "Reverse") &&
                TryGetArgumentSource(method, index, 0, out int reversed) && reversed == array)
            {
                transform = "reversed character array → string → process target";
                return true;
            }

            if (IsCall(instructions[index], "System.String", "CopyTo") &&
                TryGetArgumentSource(method, index, 1, out int destination) && destination == array)
            {
                copies++;
            }
        }

        if (copies >= 2)
        {
            transform = "string fragments → character array → process target";
            return true;
        }

        return false;
    }

    internal static bool HasXorReconstructedAssemblyLoad(MethodDefinition method)
    {
        var instructions = method.Body.Instructions;
        var handlers = method.Body.ExceptionHandlers.ToArray();
        for (int loadIndex = 0; loadIndex < instructions.Count; loadIndex++)
        {
            if (instructions[loadIndex].Operand is not MethodReference load || load.Parameters.Count == 0 ||
                load.Parameters[0].ParameterType.FullName != "System.Byte[]" ||
                !ObfuscatedSinkMatcher.IsAssemblyLoadSink(load.DeclaringType.FullName, load.Name) ||
                !InstructionValueResolver.TryResolveCallArgumentIdentity(load, instructions, loadIndex, 0, handlers, out string loadedArray))
            {
                continue;
            }

            for (int index = 0; index < loadIndex; index++)
            {
                if (instructions[index].OpCode != OpCodes.Stelem_I1 ||
                    !InstructionValueResolver.TryResolveArrayStore(instructions, index, handlers, out string writtenArray, out int value) ||
                    loadedArray != writtenArray || value < 0)
                {
                    continue;
                }
                if (instructions[value].OpCode == OpCodes.Conv_U1)
                {
                    value--;
                }
                if (value >= 0 && instructions[value].OpCode == OpCodes.Xor)
                {
                    return true;
                }
            }
        }
        return false;
    }

    internal static bool IsCall(Instruction instruction, string type, string name) =>
        instruction.OpCode.Code is Code.Call or Code.Callvirt &&
        instruction.Operand is MethodReference method && method.DeclaringType.FullName == type && method.Name == name;
}
