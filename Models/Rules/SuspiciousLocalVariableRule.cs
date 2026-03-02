using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects suspicious local variable types commonly used in malware.
    /// This rule requires companion findings and serves as a signal for multi-pattern detection.
    /// </summary>
    public class SuspiciousLocalVariableRule : IScanRule
    {
        public string Description => "Supporting signal: method uses variable types commonly seen in malicious code";
        public Severity Severity => Severity.Low;
        public string RuleId => "SuspiciousLocalVariableRule";
        public bool RequiresCompanionFinding => true;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes local variables, not method calls
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (!method.HasBody || !method.Body.HasVariables)
                return findings;

            var suspiciousTypes = new List<string>();
            bool suppressControlledProcessPattern = ShouldSuppressControlledProcessPattern(instructions, methodSignals);

            foreach (var variable in method.Body.Variables)
            {
                var variableType = variable.VariableType.FullName;

                // Check for suspicious types
                if (IsSuspiciousVariableType(variableType))
                {
                    if (suppressControlledProcessPattern && IsProcessVariableType(variableType))
                        continue;

                    suspiciousTypes.Add($"{variableType} (var_{variable.Index})");
                }
            }

            if (suspiciousTypes.Count > 0 && methodSignals != null)
            {
                // Supporting-signal only: contribute to method signals and companion checks,
                // but do not emit a standalone finding.
                methodSignals.HasSuspiciousLocalVariables = true;
                methodSignals.MarkRuleTriggered(RuleId);
            }

            return findings;
        }

        private static bool ShouldSuppressControlledProcessPattern(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals methodSignals)
        {
            if (methodSignals?.HasEnvironmentVariableModification == true)
                return false;

            bool hasProcessStart = false;
            bool hasUseShellExecuteFalse = false;
            bool hasOutputRedirection = false;
            bool hasWaitForExit = false;
            bool hasDangerousCommandLiteral = false;

            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];

                if (instruction.OpCode == OpCodes.Ldstr &&
                    instruction.Operand is string literal &&
                    IsDangerousProcessCommandLiteral(literal))
                {
                    hasDangerousCommandLiteral = true;
                }

                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt)
                    continue;

                if (instruction.Operand is not MethodReference methodRef)
                    continue;

                var declaringType = methodRef.DeclaringType?.FullName ?? string.Empty;
                var methodName = methodRef.Name ?? string.Empty;

                if (declaringType == "System.Diagnostics.Process")
                {
                    if (methodName == "Start")
                    {
                        hasProcessStart = true;
                    }
                    else if (methodName == "WaitForExit")
                    {
                        hasWaitForExit = true;
                    }

                    continue;
                }

                if (declaringType != "System.Diagnostics.ProcessStartInfo")
                    continue;

                if (methodName == "set_UseShellExecute")
                {
                    bool? value = TryGetBooleanArgument(instructions, i);
                    if (value == false)
                    {
                        hasUseShellExecuteFalse = true;
                    }
                }
                else if (methodName == "set_RedirectStandardOutput" || methodName == "set_RedirectStandardError")
                {
                    bool? value = TryGetBooleanArgument(instructions, i);
                    if (value == true)
                    {
                        hasOutputRedirection = true;
                    }
                }
            }

            return hasProcessStart &&
                   hasUseShellExecuteFalse &&
                   hasOutputRedirection &&
                   hasWaitForExit &&
                   !hasDangerousCommandLiteral;
        }

        private static bool? TryGetBooleanArgument(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callInstructionIndex)
        {
            if (callInstructionIndex <= 0)
                return null;

            var previous = instructions[callInstructionIndex - 1];

            if (previous.OpCode == OpCodes.Ldc_I4_0)
                return false;

            if (previous.OpCode == OpCodes.Ldc_I4_1)
                return true;

            if (previous.OpCode == OpCodes.Ldc_I4_S && previous.Operand is sbyte sbyteValue)
            {
                if (sbyteValue == 0)
                    return false;

                if (sbyteValue == 1)
                    return true;
            }

            if (previous.OpCode == OpCodes.Ldc_I4 && previous.Operand is int intValue)
            {
                if (intValue == 0)
                    return false;

                if (intValue == 1)
                    return true;
            }

            return null;
        }

        private static bool IsDangerousProcessCommandLiteral(string literal)
        {
            if (string.IsNullOrWhiteSpace(literal))
                return false;

            string normalized = literal.Trim().ToLowerInvariant();

            return normalized.Contains("cmd.exe") ||
                   normalized.Contains("powershell") ||
                   normalized.Contains("pwsh") ||
                   normalized.Contains("wscript") ||
                   normalized.Contains("cscript") ||
                   normalized.Contains("mshta") ||
                   normalized.Contains("rundll32") ||
                   normalized.Contains("regsvr32") ||
                   normalized.Contains("certutil") ||
                   normalized.Contains("bitsadmin");
        }

        private static bool IsProcessVariableType(string typeName)
        {
            return typeName.StartsWith("System.Diagnostics.Process", StringComparison.Ordinal);
        }

        private static bool IsSuspiciousVariableType(string typeName)
        {
            // NOTE: Reflection types (MethodInfo, MethodBase, ConstructorInfo, Assembly, etc.) are
            // handled by ReflectionRule.AnalyzeInstructions() to avoid duplicate detection
            // Assembly types are extremely common in legitimate mods for resource loading and should not be flagged here

            // Process types (used for executing external programs)
            if (typeName.StartsWith("System.Diagnostics.Process"))
            {
                return true;
            }

            // P/Invoke and unsafe types
            if (typeName.StartsWith("System.Runtime.InteropServices.") &&
                (typeName.Contains("Marshal") ||
                 typeName.Contains("DllImport")))
            {
                return true;
            }

            // WebClient and HTTP clients (for network communication)
            if (typeName.Contains("System.Net.WebClient") ||
                typeName.Contains("System.Net.Http.HttpClient"))
            {
                return true;
            }

            return false;
        }
    }
}
