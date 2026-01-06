using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class COMReflectionAttackRule : IScanRule
    {
        public string Description => "Detected reflective shell execution via COM (GetTypeFromProgID + InvokeMember pattern).";
        public Severity Severity => Severity.Critical;
        public string RuleId => "COMReflectionAttackRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes instructions, not individual method references
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition methodDef, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            if (methodDef == null || instructions == null || instructions.Count == 0)
                yield break;
                
            bool hasTypeFromProgID = false;
            bool hasActivatorCreateInstance = false;
            bool hasInvokeMember = false;
            string? progIDValue = null;
            var allStrings = new List<string>();
            
            // First pass - collect all string literals and detect method calls
            foreach (var instruction in instructions)
            {
                // Collect all string literals in the method
                if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string str)
                {
                    allStrings.Add(str);
                }
                
                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt)
                    continue;
                    
                if (instruction.Operand is not MethodReference calledMethod)
                    continue;
                    
                if (calledMethod.DeclaringType == null)
                    continue;
                
                string typeName = calledMethod.DeclaringType.FullName;
                string methodName = calledMethod.Name;
                
                // Check for GetTypeFromProgID
                if (typeName == "System.Type" && methodName == "GetTypeFromProgID")
                {
                    hasTypeFromProgID = true;
                    
                    // Try to extract the progID value (usually a string literal before the call)
                    int index = instructions.IndexOf(instruction);
                    for (int i = Math.Max(0, index - 5); i < index; i++)
                    {
                        if (instructions[i].OpCode == OpCodes.Ldstr && instructions[i].Operand is string str2)
                        {
                            progIDValue = str2;
                            break;
                        }
                    }
                }
                
                // Check for Activator.CreateInstance
                if (typeName == "System.Activator" && methodName == "CreateInstance")
                {
                    hasActivatorCreateInstance = true;
                }
                
                // Check for InvokeMember
                if (typeName == "System.Type" && methodName == "InvokeMember")
                {
                    hasInvokeMember = true;
                }
            }
            
            // If we found the full pattern, add a finding
            if (hasTypeFromProgID && (hasActivatorCreateInstance || hasInvokeMember))
            {
                // Check if any strings indicate shell execution or COM abuse
                bool hasShellRelatedString = allStrings.Any(s => 
                    s.Contains("Shell.Application", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("WScript.Shell", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("ShellExecute", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("shell32", StringComparison.OrdinalIgnoreCase));
                
                bool hasCommandExecution = allStrings.Any(s =>
                    s.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("/c ", StringComparison.Ordinal) ||
                    s.Contains("/k ", StringComparison.Ordinal));
                
                // Trigger if:
                // 1. We have shell-related strings (Shell.Application, ShellExecute, etc.)
                // 2. We have both GetTypeFromProgID and InvokeMember (even without specific strings, this is suspicious)
                // 3. We have command execution strings combined with the pattern
                if (hasShellRelatedString || (hasTypeFromProgID && hasInvokeMember) || hasCommandExecution)
                {
                    var fullMethodSnippet = new System.Text.StringBuilder();
                    
                    // Include the full method for context
                    foreach (var instr in instructions)
                    {
                        fullMethodSnippet.AppendLine(instr.ToString());
                    }
                    
                    var description = "Detected reflective COM invocation pattern (GetTypeFromProgID + InvokeMember)";
                    if (hasShellRelatedString)
                        description += " with shell execution indicators";
                    if (hasCommandExecution)
                        description += " and command execution strings";
                    
                    yield return new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        description,
                        Severity.Critical,
                        fullMethodSnippet.ToString().TrimEnd());
                }
            }
        }
    }
}

