using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects suspicious local variable types commonly used in malware.
    /// This rule requires companion findings and serves as a signal for multi-pattern detection.
    /// </summary>
    public class SuspiciousLocalVariableRule : IScanRule
    {
        public string Description => "Method uses variable types commonly seen in malicious code";
        public Severity Severity => Severity.Low;
        public string RuleId => "SuspiciousLocalVariableRule";
        public bool RequiresCompanionFinding => true;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes local variables, not method calls
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (!method.HasBody || !method.Body.HasVariables)
                return findings;

            var suspiciousTypes = new List<string>();

            foreach (var variable in method.Body.Variables)
            {
                var variableType = variable.VariableType.FullName;

                // Check for suspicious types
                if (IsSuspiciousVariableType(variableType))
                {
                    suspiciousTypes.Add($"{variableType} (var_{variable.Index})");
                }
            }

            if (suspiciousTypes.Count > 0)
            {
                var finding = new ScanFinding(
                    $"{method.DeclaringType?.FullName}.{method.Name}",
                    Description + $": {string.Join(", ", suspiciousTypes.Take(3))}{(suspiciousTypes.Count > 3 ? $" and {suspiciousTypes.Count - 3} more" : "")}",
                    Severity,
                    $"Suspicious local variable types detected: {string.Join(", ", suspiciousTypes)}");

                findings.Add(finding);
            }

            return findings;
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

