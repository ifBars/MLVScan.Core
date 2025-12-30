using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class LoadFromStreamRule : IScanRule
    {
        public string Description => "Detected dynamic assembly loading which could be used to execute hidden code.";
        public Severity Severity => Severity.Critical;
        public string RuleId => "LoadFromStreamRule";
        public bool RequiresCompanionFinding => false;
        
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            // Detect Assembly.Load and Assembly.LoadFrom calls
            if ((typeName.Contains("Assembly") || typeName.Contains("AssemblyLoadContext")) &&
                (methodName == "Load" || methodName.Contains("LoadFrom")))
            {
                return true;
            }

            // Detect GetManifestResourceStream - commonly used to load embedded resources as assemblies
            if (typeName.Contains("Assembly") && methodName == "GetManifestResourceStream")
            {
                return true;
            }

            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method, Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (method?.DeclaringType == null)
                return findings;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            // Check for GetManifestResourceStream pattern
            if (typeName.Contains("Assembly") && methodName == "GetManifestResourceStream")
            {
                // Look ahead to see if Assembly.Load is called with the stream result
                if (IsFollowedByAssemblyLoad(instructions, instructionIndex))
                {
                    var finding = new ScanFinding(
                        $"Instruction at index {instructionIndex}",
                        "Detected embedded resource being loaded as executable assembly (GetManifestResourceStream -> Assembly.Load pattern)",
                        Severity.Critical,
                        GetSnippetForPattern(instructions, instructionIndex));
                    
                    findings.Add(finding);
                }
            }

            return findings;
        }

        private static bool IsFollowedByAssemblyLoad(Mono.Collections.Generic.Collection<Instruction> instructions, int startIndex)
        {
            // Look ahead up to 20 instructions for Assembly.Load pattern
            int lookAheadLimit = Math.Min(startIndex + 20, instructions.Count);
            
            for (int i = startIndex + 1; i < lookAheadLimit; i++)
            {
                var instruction = instructions[i];
                
                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                    instruction.Operand is MethodReference calledMethod)
                {
                    var calledTypeName = calledMethod.DeclaringType?.FullName ?? "";
                    var calledMethodName = calledMethod.Name;

                    // Check for Assembly.Load
                    if (calledTypeName.Contains("Assembly") && 
                        (calledMethodName == "Load" || calledMethodName.Contains("LoadFrom")))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static string GetSnippetForPattern(Mono.Collections.Generic.Collection<Instruction> instructions, int startIndex)
        {
            var snippetLines = new List<string>();
            
            // Include a few instructions before and after
            int start = Math.Max(0, startIndex - 2);
            int end = Math.Min(instructions.Count - 1, startIndex + 10);

            for (int i = start; i <= end; i++)
            {
                var instruction = instructions[i];
                var prefix = i == startIndex ? ">>> " : "    ";
                var operand = instruction.Operand != null ? $" {instruction.Operand}" : "";
                snippetLines.Add($"{prefix}IL_{instruction.Offset:X4}: {instruction.OpCode}{operand}");
            }

            return string.Join("\n", snippetLines);
        }
    }
}