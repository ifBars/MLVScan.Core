using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
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

            // Detect reflection invoke methods
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

        private static bool IsReflectionInvocationType(string typeName)
        {
            // Only flag reflection types commonly used for dynamic invocation
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
