using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.Helpers
{
    /// <summary>
    /// Extension methods for Mono.Cecil.Cil.Instruction to provide low-level IL analysis utilities.
    /// </summary>
    public static class InstructionExtensions
    {
        /// <summary>
        /// Gets the number of values pushed onto the stack by this instruction.
        /// </summary>
        public static int GetPushCount(this Instruction instruction)
        {
            if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                instruction.Operand is MethodReference method)
                return method.ReturnType?.FullName == "System.Void" ? 0 : 1;

            if (instruction.OpCode == OpCodes.Newobj)
                return 1;

            return instruction.OpCode.StackBehaviourPush switch
            {
                StackBehaviour.Push0 => 0,
                StackBehaviour.Push1 => 1,
                StackBehaviour.Pushi => 1,
                StackBehaviour.Pushi8 => 1,
                StackBehaviour.Pushr4 => 1,
                StackBehaviour.Pushr8 => 1,
                StackBehaviour.Pushref => 1,
                StackBehaviour.Push1_push1 => 2,
                _ => 0
            };
        }

        /// <summary>
        /// Gets the number of values popped from the stack by this instruction.
        /// </summary>
        public static int GetPopCount(this Instruction instruction)
        {
            if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                instruction.Operand is MethodReference method)
            {
                int count = method.Parameters.Count;
                if (method.HasThis)
                    count++;

                return count;
            }

            if (instruction.OpCode == OpCodes.Newobj && instruction.Operand is MethodReference ctor)
                return ctor.Parameters.Count;

            return instruction.OpCode.StackBehaviourPop switch
            {
                StackBehaviour.Pop0 => 0,
                StackBehaviour.Pop1 => 1,
                StackBehaviour.Popi => 1,
                StackBehaviour.Popref => 1,
                StackBehaviour.Pop1_pop1 => 2,
                StackBehaviour.Popi_pop1 => 2,
                StackBehaviour.Popi_popi => 2,
                StackBehaviour.Popi_popi8 => 2,
                StackBehaviour.Popi_popr4 => 2,
                StackBehaviour.Popi_popr8 => 2,
                StackBehaviour.Popi_popi_popi => 3,
                _ => 0
            };
        }

        /// <summary>
        /// Attempts to extract an Int32 literal value from this instruction.
        /// Returns true if successful, false otherwise.
        /// </summary>
        public static bool TryResolveInt32Literal(this Instruction instruction, out int value)
        {
            value = instruction.OpCode.Code switch
            {
                Code.Ldc_I4_M1 => -1,
                Code.Ldc_I4_0 => 0,
                Code.Ldc_I4_1 => 1,
                Code.Ldc_I4_2 => 2,
                Code.Ldc_I4_3 => 3,
                Code.Ldc_I4_4 => 4,
                Code.Ldc_I4_5 => 5,
                Code.Ldc_I4_6 => 6,
                Code.Ldc_I4_7 => 7,
                Code.Ldc_I4_8 => 8,
                _ => int.MinValue
            };

            if (value != int.MinValue)
                return true;

            if (instruction.OpCode == OpCodes.Ldc_I4 && instruction.Operand is int intOperand)
            {
                value = intOperand;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_S && instruction.Operand is sbyte shortOperand)
            {
                value = shortOperand;
                return true;
            }

            value = 0;
            return false;
        }

        /// <summary>
        /// Attempts to get the local variable index loaded by this instruction.
        /// Works for ldloc, ldloc_S, ldloc_0-3.
        /// </summary>
        public static bool TryGetLocalIndex(this Instruction instruction, out int index)
        {
            index = instruction.OpCode.Code switch
            {
                Code.Ldloc_0 => 0,
                Code.Ldloc_1 => 1,
                Code.Ldloc_2 => 2,
                Code.Ldloc_3 => 3,
                _ => -1
            };

            if (index >= 0)
                return true;

            if (instruction.OpCode.Code == Code.Ldloc_S && instruction.Operand is VariableDefinition localS)
            {
                index = localS.Index;
                return true;
            }

            if (instruction.OpCode.Code == Code.Ldloc && instruction.Operand is VariableDefinition local)
            {
                index = local.Index;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Attempts to get the local variable index stored by this instruction.
        /// Works for stloc, stloc_S, stloc_0-3.
        /// </summary>
        public static bool TryGetStoredLocalIndex(this Instruction instruction, out int index)
        {
            index = instruction.OpCode.Code switch
            {
                Code.Stloc_0 => 0,
                Code.Stloc_1 => 1,
                Code.Stloc_2 => 2,
                Code.Stloc_3 => 3,
                _ => -1
            };

            if (index >= 0)
                return true;

            if (instruction.OpCode.Code == Code.Stloc_S && instruction.Operand is VariableDefinition localS)
            {
                index = localS.Index;
                return true;
            }

            if (instruction.OpCode.Code == Code.Stloc && instruction.Operand is VariableDefinition local)
            {
                index = local.Index;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Attempts to get the argument index loaded by this instruction.
        /// Works for ldarg, ldarg_S, ldarg_0-3.
        /// </summary>
        public static bool TryGetArgumentIndex(this Instruction instruction, out int index)
        {
            index = instruction.OpCode.Code switch
            {
                Code.Ldarg_0 => 0,
                Code.Ldarg_1 => 1,
                Code.Ldarg_2 => 2,
                Code.Ldarg_3 => 3,
                _ => -1
            };

            if (index >= 0)
                return true;

            if (instruction.OpCode.Code == Code.Ldarg_S && instruction.Operand is ParameterDefinition parameterS)
            {
                index = parameterS.Index;
                return true;
            }

            if (instruction.OpCode.Code == Code.Ldarg && instruction.Operand is ParameterDefinition parameter)
            {
                index = parameter.Index;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if this instruction pushes a value onto the evaluation stack.
        /// </summary>
        public static bool IsValueProducer(this Instruction instruction)
        {
            return instruction.GetPushCount() > 0;
        }

        /// <summary>
        /// Checks if this instruction consumes values from the evaluation stack.
        /// </summary>
        public static bool IsValueConsumer(this Instruction instruction)
        {
            return instruction.GetPopCount() > 0;
        }

        /// <summary>
        /// Checks if this instruction is a method call (call, callvirt, or newobj).
        /// </summary>
        public static bool IsMethodCall(this Instruction instruction)
        {
            return instruction.OpCode == OpCodes.Call ||
                   instruction.OpCode == OpCodes.Callvirt ||
                   instruction.OpCode == OpCodes.Newobj;
        }

        /// <summary>
        /// Gets the method reference from a call instruction, or null if not a method call.
        /// </summary>
        public static MethodReference? GetMethodReference(this Instruction instruction)
        {
            if (instruction.IsMethodCall() && instruction.Operand is MethodReference methodRef)
                return methodRef;

            return null;
        }

        /// <summary>
        /// Checks if this instruction is a conditional or unconditional branch.
        /// </summary>
        public static bool IsBranch(this Instruction instruction)
        {
            return instruction.OpCode.Code == Code.Br ||
                   instruction.OpCode.Code == Code.Br_S ||
                   instruction.OpCode.Code == Code.Beq ||
                   instruction.OpCode.Code == Code.Beq_S ||
                   instruction.OpCode.Code == Code.Bne_Un ||
                   instruction.OpCode.Code == Code.Bne_Un_S ||
                   instruction.OpCode.Code == Code.Bgt ||
                   instruction.OpCode.Code == Code.Bgt_S ||
                   instruction.OpCode.Code == Code.Bge ||
                   instruction.OpCode.Code == Code.Bge_S ||
                   instruction.OpCode.Code == Code.Blt ||
                   instruction.OpCode.Code == Code.Blt_S ||
                   instruction.OpCode.Code == Code.Ble ||
                   instruction.OpCode.Code == Code.Ble_S ||
                   instruction.OpCode.Code == Code.Brfalse ||
                   instruction.OpCode.Code == Code.Brfalse_S ||
                   instruction.OpCode.Code == Code.Brtrue ||
                   instruction.OpCode.Code == Code.Brtrue_S ||
                   instruction.OpCode.Code == Code.Bge_Un ||
                   instruction.OpCode.Code == Code.Bge_Un_S ||
                   instruction.OpCode.Code == Code.Bgt_Un ||
                   instruction.OpCode.Code == Code.Bgt_Un_S ||
                   instruction.OpCode.Code == Code.Ble_Un ||
                   instruction.OpCode.Code == Code.Ble_Un_S ||
                   instruction.OpCode.Code == Code.Blt_Un ||
                   instruction.OpCode.Code == Code.Blt_Un_S;
        }
    }
}
