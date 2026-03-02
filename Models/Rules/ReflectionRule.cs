using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects reflection invocation and obfuscated reflection patterns.
    /// Flags methods that:
    /// 1. Use reflection invocation (MethodInfo.Invoke, etc.)
    /// 2. Pass sequential integer constants (ldc.i4) before reflection or dynamic calls
    ///    (typical of obfuscated loaders like ScheduleIMoreNpcs)
    /// </summary>
    public class ReflectionRule : IScanRule
    {
        public string Description => "Detected reflection invocation without determinable target method (potential bypass).";
        public Severity Severity => Severity.High;
        public string RuleId => "ReflectionRule";
        public bool RequiresCompanionFinding => true;

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            bool isReflectionInvoke =
                (typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke");

            return isReflectionInvoke;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (!method.HasBody || !method.Body.HasVariables)
                return findings;

            // Only trigger on local variables if companion findings exist
            if (methodSignals == null || !methodSignals.HasTriggeredRuleOtherThan(RuleId))
                return findings;

            var reflectionTypes = new List<string>();

            foreach (var variable in method.Body.Variables)
            {
                var variableType = variable.VariableType.FullName;

                // Check for reflection types used for invocation
                if (IsReflectionInvocationType(variableType))
                {
                    reflectionTypes.Add($"{variableType} (var_{variable.Index})");
                }
            }

            if (reflectionTypes.Count > 0)
            {
                var finding = new ScanFinding(
                    $"{method.DeclaringType?.FullName}.{method.Name}",
                    Description + $" - uses reflection types: {string.Join(", ", reflectionTypes.Take(3))}{(reflectionTypes.Count > 3 ? $" and {reflectionTypes.Count - 3} more" : "")}",
                    Severity,
                    $"Reflection variable types detected: {string.Join(", ", reflectionTypes)}");

                findings.Add(finding);
            }

            return findings;
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method, Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            // Skip findings at the framework/BCL method level - we only want findings at the caller level
            // This prevents duplicate findings and false positives on legitimate IL2CPP interop
            var declaringType = method.DeclaringType;
            if (declaringType?.Scope != null)
            {
                var assemblyName = declaringType.Scope.Name;
                if (IsSystemAssembly(assemblyName))
                {
                    yield break;
                }
            }

            // Check for obfuscated reflection pattern:
            // Multiple sequential ldc.i4 loads before reflection/dynamic invocation calls
            // This pattern was seen in ScheduleIMoreNpcs.dll.di where integer constants
            // are passed to a central decoding method to dynamically resolve APIs

            bool isDynamicCall =
                (method.DeclaringType.FullName == "System.Reflection.MethodInfo" && method.Name == "Invoke") ||
                (method.DeclaringType.FullName == "System.Reflection.MethodBase" && method.Name == "Invoke") ||
                (method.DeclaringType.FullName == "System.Activator" && method.Name.StartsWith("CreateInstance")) ||
                (method.DeclaringType.FullName.Contains("Delegate") && method.Name == "DynamicInvoke");

            if (!isDynamicCall)
                yield break;

            // Look backward for sequential ldc.i4 (integer constant) loads
            int ldc4Count = 0;
            int windowStart = Math.Max(0, instructionIndex - 20);
            
            for (int i = instructionIndex - 1; i >= windowStart; i--)
            {
                var instr = instructions[i];
                
                // Stop if we hit a call that might consume our values
                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) && i != instructionIndex)
                    break;
                
                // Count consecutive ldc.i4 instructions
                if (IsLdcI4Instruction(instr))
                {
                    ldc4Count++;
                }
                else if (instr.OpCode != OpCodes.Nop && instr.OpCode != OpCodes.Dup && 
                         instr.OpCode != OpCodes.Pop && !IsLocalVariableLoad(instr))
                {
                    // Non-ldc, non-control-flow instruction breaks the sequence
                    // but allow some benign operations like nop, dup, pop, local loads
                }
            }

            // Pattern detected: 3+ sequential integer constants before dynamic invocation
            // This is characteristic of obfuscated loaders that encode method/field IDs as integers
            if (ldc4Count >= 3)
            {
                var snippetBuilder = new System.Text.StringBuilder();
                int contextLines = 3;
                for (int j = Math.Max(0, instructionIndex - contextLines); j < Math.Min(instructions.Count, instructionIndex + contextLines + 1); j++)
                {
                    snippetBuilder.Append(j == instructionIndex ? ">>> " : "    ");
                    snippetBuilder.AppendLine(instructions[j].ToString());
                }

                yield return new ScanFinding(
                    $"{method.DeclaringType.FullName}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Detected obfuscated reflection: {ldc4Count} sequential integer constants loaded before dynamic invocation (potential API resolution obfuscation)",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd());
            }
        }

        private static bool IsLdcI4Instruction(Instruction instruction)
        {
            return instruction.OpCode == OpCodes.Ldc_I4 ||
                   instruction.OpCode == OpCodes.Ldc_I4_0 ||
                   instruction.OpCode == OpCodes.Ldc_I4_1 ||
                   instruction.OpCode == OpCodes.Ldc_I4_2 ||
                   instruction.OpCode == OpCodes.Ldc_I4_3 ||
                   instruction.OpCode == OpCodes.Ldc_I4_4 ||
                   instruction.OpCode == OpCodes.Ldc_I4_5 ||
                   instruction.OpCode == OpCodes.Ldc_I4_6 ||
                   instruction.OpCode == OpCodes.Ldc_I4_7 ||
                   instruction.OpCode == OpCodes.Ldc_I4_8 ||
                   instruction.OpCode == OpCodes.Ldc_I4_M1 ||
                   instruction.OpCode == OpCodes.Ldc_I4_S;
        }

        private static bool IsLocalVariableLoad(Instruction instruction)
        {
            return instruction.OpCode == OpCodes.Ldloc ||
                   instruction.OpCode == OpCodes.Ldloc_0 ||
                   instruction.OpCode == OpCodes.Ldloc_1 ||
                   instruction.OpCode == OpCodes.Ldloc_2 ||
                   instruction.OpCode == OpCodes.Ldloc_3 ||
                   instruction.OpCode == OpCodes.Ldloc_S;
        }

        private static readonly HashSet<string> SystemAssemblies = new(StringComparer.OrdinalIgnoreCase)
        {
            "mscorlib",
            "System",
            "System.Core",
            "netstandard",
            "System.Runtime",
            "System.Reflection"
        };

        private static bool IsSystemAssembly(string assemblyName)
        {
            if (string.IsNullOrEmpty(assemblyName))
                return false;

            if (SystemAssemblies.Contains(assemblyName))
                return true;

            if (assemblyName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                assemblyName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase))
                return true;

            if (assemblyName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                var baseName = assemblyName.Substring(0, assemblyName.Length - 4);
                if (SystemAssemblies.Contains(baseName))
                    return true;
            }

            return false;
        }

        private static bool IsReflectionInvocationType(string typeName)
        {
            if (typeName == "System.Reflection.MethodInfo" ||
                typeName == "System.Reflection.MethodBase" ||
                typeName == "System.Reflection.ConstructorInfo")
            {
                return true;
            }

            return false;
        }
    }
}
