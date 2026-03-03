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
        public string Description =>
            "Detected reflection invocation without determinable target method (potential bypass).";

        public Severity Severity => Severity.High;
        public string RuleId => "ReflectionRule";
        public bool RequiresCompanionFinding => true;

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            // Reflection invocation - MethodInfo.Invoke and MethodBase.Invoke are high-confidence indicators
            // of dynamic method invocation which is commonly used for bypassing security controls
            if ((typeName == "System.Reflection.MethodInfo" && methodName == "Invoke") ||
                (typeName == "System.Reflection.MethodBase" && methodName == "Invoke"))
                return true;

            // Note: PropertyInfo.SetValue is intentionally NOT included here because it has many legitimate
            // uses in modding (UI manipulation, configuration setting). It is only flagged as suspicious
            // when part of a chain (Type.GetProperty + SetValue) in AnalyzeInstructions.

            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (!method.HasBody)
                return findings;

            // --- Pattern: Reflection variable types (requires companion finding) ---
            if (method.Body.HasVariables && methodSignals != null &&
                methodSignals.HasTriggeredRuleOtherThan(RuleId))
            {
                var reflectionTypes = new List<string>();

                foreach (var variable in method.Body.Variables)
                {
                    var variableType = variable.VariableType.FullName;

                    if (IsReflectionInvocationType(variableType))
                    {
                        reflectionTypes.Add($"{variableType} (var_{variable.Index})");
                    }
                }

                if (reflectionTypes.Count > 0)
                {
                    findings.Add(new ScanFinding(
                        $"{method.DeclaringType?.FullName}.{method.Name}",
                        Description +
                        $" - uses reflection types: {string.Join(", ", reflectionTypes.Take(3))}{(reflectionTypes.Count > 3 ? $" and {reflectionTypes.Count - 3} more" : "")}",
                        Severity,
                        $"Reflection variable types detected: {string.Join(", ", reflectionTypes)}"));
                }
            }

            // --- IL instruction pattern scanning ---
            bool hasTypeGetMethod = false;
            bool hasMethodBaseInvoke = false;
            bool hasAppDomainGetAssemblies = false;
            bool hasSelectManyGetTypes = false;
            bool hasFirstOrDefault = false;
            bool hasGetCustomAttribute = false;

            int getMethodIndex = -1;
            int invokeIndex = -1;
            int getAssembliesIndex = -1;
            int getCustomAttrIndex = -1;

            for (int i = 0; i < instructions.Count; i++)
            {
                var instr = instructions[i];

                if (instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt)
                    continue;

                if (instr.Operand is not MethodReference calledMethod || calledMethod.DeclaringType == null)
                    continue;

                string typeName = calledMethod.DeclaringType.FullName;
                string methodName = calledMethod.Name;

                // Type.GetMethod
                if (typeName == "System.Type" && methodName == "GetMethod")
                {
                    hasTypeGetMethod = true;
                    getMethodIndex = i;
                }

                // MethodBase.Invoke / MethodInfo.Invoke
                if ((typeName == "System.Reflection.MethodBase" || typeName == "System.Reflection.MethodInfo") &&
                    methodName == "Invoke")
                {
                    hasMethodBaseInvoke = true;
                    invokeIndex = i;
                }

                // AppDomain.get_CurrentDomain or AppDomain.GetAssemblies
                if (typeName == "System.AppDomain" &&
                    (methodName == "GetAssemblies" || methodName == "get_CurrentDomain"))
                {
                    hasAppDomainGetAssemblies = true;
                    getAssembliesIndex = i;
                }

                // SelectMany (used to flatten GetTypes across assemblies)
                if (typeName == "System.Linq.Enumerable" && methodName == "SelectMany")
                {
                    hasSelectManyGetTypes = true;
                }

                // FirstOrDefault (used to find a specific type by name)
                if (typeName == "System.Linq.Enumerable" && methodName == "FirstOrDefault")
                {
                    hasFirstOrDefault = true;
                }

                // GetCustomAttribute<T> or GetCustomAttributes
                if (methodName.StartsWith("GetCustomAttribute"))
                {
                    hasGetCustomAttribute = true;
                    getCustomAttrIndex = i;
                }
            }

            // Fix 5: Type.GetMethod + MethodBase.Invoke chain
            // This detects dynamic method invocation which is a high-confidence indicator of
            // potential security bypass (e.g., invoking private/internal methods)
            if (hasTypeGetMethod && hasMethodBaseInvoke && getMethodIndex < invokeIndex)
            {
                findings.Add(new ScanFinding(
                    $"{method.DeclaringType?.FullName}.{method.Name}",
                    "Detected reflection execution chain: Type.GetMethod → MethodBase.Invoke (dynamic method invocation)",
                    Severity.High,
                    BuildSnippet(instructions, getMethodIndex, invokeIndex)));
            }

            // Note: Type.GetProperty + PropertyInfo.SetValue chain detection is intentionally omitted.
            // While this pattern can be used maliciously (e.g., setting ProcessStartInfo properties),
            // it is also commonly used legitimately in modding for UI manipulation and configuration.
            // Malicious use of SetValue for process manipulation is better detected by ProcessStartRule
            // which has specific context about what properties are being set on what types.

            // Fix 6: AppDomain.GetAssemblies → SelectMany(GetTypes) → FirstOrDefault
            if (hasAppDomainGetAssemblies && hasSelectManyGetTypes && hasFirstOrDefault)
            {
                findings.Add(new ScanFinding(
                    $"{method.DeclaringType?.FullName}.{method.Name}",
                    "Detected runtime type scanning: AppDomain.GetAssemblies → SelectMany(GetTypes) → FirstOrDefault (type enumeration to resolve APIs dynamically)",
                    Severity.High,
                    "Method enumerates all loaded assemblies and types to find specific types at runtime, " +
                    "bypassing compile-time references."));
            }

            // Fix 7: GetCustomAttribute (especially near AppDomain or Assembly access)
            if (hasGetCustomAttribute && getCustomAttrIndex >= 0)
            {
                // Check if it's specifically accessing AssemblyMetadataAttribute
                var attrInstr = instructions[getCustomAttrIndex];
                bool isMetadataAttr = false;
                if (attrInstr.Operand is MethodReference attrMethod)
                {
                    // Check generic arguments for AssemblyMetadataAttribute
                    if (attrMethod is GenericInstanceMethod genericAttrMethod)
                    {
                        foreach (var genArg in genericAttrMethod.GenericArguments)
                        {
                            if (genArg.FullName.Contains("AssemblyMetadataAttribute"))
                            {
                                isMetadataAttr = true;
                                break;
                            }
                        }
                    }

                    // Also check non-generic overloads by parameter type
                    foreach (var param in attrMethod.Parameters)
                    {
                        if (param.ParameterType.FullName.Contains("AssemblyMetadataAttribute"))
                        {
                            isMetadataAttr = true;
                            break;
                        }
                    }
                }

                if (isMetadataAttr)
                {
                    findings.Add(new ScanFinding(
                        $"{method.DeclaringType?.FullName}.{method.Name}",
                        "Detected runtime access to AssemblyMetadataAttribute (potential hidden payload retrieval)",
                        Severity.High,
                        "Method reads AssemblyMetadataAttribute at runtime, which can be used to store " +
                        "and retrieve encoded payloads hidden in assembly metadata."));
                }
            }

            return findings;
        }

        private static string BuildSnippet(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int startIdx, int endIdx)
        {
            var sb = new System.Text.StringBuilder();
            int from = Math.Max(0, startIdx - 2);
            int to = Math.Min(instructions.Count, endIdx + 3);

            for (int j = from; j < to; j++)
            {
                sb.Append(j == startIdx || j == endIdx ? ">>> " : "    ");
                sb.AppendLine(instructions[j].ToString());
            }

            return sb.ToString().TrimEnd();
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals)
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

            // Note: PropertyInfo.SetValue is excluded from pattern detection here because it has
            // many legitimate uses in modding. It is only flagged when part of a suspicious chain.

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
                for (int j = Math.Max(0, instructionIndex - contextLines);
                     j < Math.Min(instructions.Count, instructionIndex + contextLines + 1);
                     j++)
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
            return typeName == "System.Reflection.MethodInfo" ||
                   typeName == "System.Reflection.MethodBase" ||
                   typeName == "System.Reflection.ConstructorInfo" ||
                   typeName == "System.Reflection.PropertyInfo";
        }
    }
}
