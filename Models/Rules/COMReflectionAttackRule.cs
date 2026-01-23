using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects COM-based reflection attacks like MLVBypass.
    /// Key distinction: Type.InvokeMember (late-bound COM) vs MethodInfo.Invoke (standard reflection).
    /// This rule specifically targets COM abuse patterns, not legitimate IL2Cpp interop.
    /// </summary>
    public class COMReflectionAttackRule : IScanRule
    {
        public string Description => "Detected reflective shell execution via COM (GetTypeFromProgID + InvokeMember pattern).";
        public Severity Severity => Severity.Critical;
        public string RuleId => "COMReflectionAttackRule";
        public bool RequiresCompanionFinding => false;

        // ProgIDs that are almost always malicious in game mod context
        private static readonly HashSet<string> CriticalProgIDs = new(StringComparer.OrdinalIgnoreCase)
        {
            "Shell.Application",
            "WScript.Shell",
            "Schedule.Service",      // Task scheduler (persistence)
            "MMC20.Application",     // UAC bypass vector
        };

        // ProgIDs that are risky but could have edge-case legitimate uses
        private static readonly HashSet<string> HighRiskProgIDs = new(StringComparer.OrdinalIgnoreCase)
        {
            "Scripting.FileSystemObject",
            "ADODB.Stream",
            "MSXML2.XMLHTTP",
            "WinHttp.WinHttpRequest.5.1",
            "Microsoft.XMLHTTP",
            "WScript.Network",
        };

        // Command execution indicators
        private static readonly string[] CommandStrings =
        {
            "cmd.exe", "powershell", "pwsh", "/c ", "/k ",
            "wscript", "cscript", "mshta", "regsvr32"
        };

        // Shell-related method/string indicators
        private static readonly string[] ShellIndicators =
        {
            "ShellExecute", "shell32", "Run", "Exec"
        };

        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes instructions, not individual method references
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(
            MethodDefinition methodDef,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals methodSignals)
        {
            if (methodDef == null || instructions == null || instructions.Count == 0)
                yield break;

            // === Pass 1: Collect all signals ===
            var signals = CollectSignals(instructions);

            // If no COM-related calls found, skip further analysis
            if (!signals.HasGetTypeFromProgID && !signals.HasGetTypeFromCLSID && !signals.HasMarshalGetActiveObject)
                yield break;

            // === Pass 2: Analyze string content ===
            var progIDRisk = ClassifyProgID(signals.ProgIDValue);
            bool hasCommandStrings = signals.AllStrings.Any(s =>
                CommandStrings.Any(cmd => s.Contains(cmd, StringComparison.OrdinalIgnoreCase)));
            bool hasShellIndicators = signals.AllStrings.Any(s =>
                ShellIndicators.Any(ind => s.Contains(ind, StringComparison.OrdinalIgnoreCase)));

            // === Pass 3: Determine severity and emit findings ===
            string location = $"{methodDef.DeclaringType?.FullName}.{methodDef.Name}";

            // Critical: GetTypeFromProgID/CLSID + Type.InvokeMember (full attack chain)
            if ((signals.HasGetTypeFromProgID || signals.HasGetTypeFromCLSID) && signals.HasTypeInvokeMember)
            {
                yield return CreateFinding(
                    location,
                    "COM reflection attack pattern: GetTypeFromProgID + Type.InvokeMember",
                    Severity.Critical,
                    signals,
                    instructions);
                yield break;
            }

            // Critical: Access to dangerous COM object (Shell.Application, WScript.Shell, etc.)
            if (signals.HasGetTypeFromProgID && progIDRisk == ProgIDRiskLevel.Critical)
            {
                yield return CreateFinding(
                    location,
                    $"Access to dangerous COM object: {signals.ProgIDValue}",
                    Severity.Critical,
                    signals,
                    instructions);
                yield break;
            }

            // Critical: COM access with command execution strings
            if (signals.HasGetTypeFromProgID && hasCommandStrings)
            {
                yield return CreateFinding(
                    location,
                    "COM access with command execution strings detected",
                    Severity.Critical,
                    signals,
                    instructions);
                yield break;
            }

            // High: Access to risky COM object (FileSystemObject, ADODB.Stream, etc.)
            if (signals.HasGetTypeFromProgID && progIDRisk == ProgIDRiskLevel.High)
            {
                yield return CreateFinding(
                    location,
                    $"Access to risky COM object: {signals.ProgIDValue}",
                    Severity.High,
                    signals,
                    instructions);
                yield break;
            }

            // High: Dynamic COM object instantiation (GetTypeFromProgID + CreateInstance)
            if ((signals.HasGetTypeFromProgID || signals.HasGetTypeFromCLSID) && signals.HasActivatorCreateInstance)
            {
                yield return CreateFinding(
                    location,
                    "Dynamic COM object instantiation detected",
                    Severity.High,
                    signals,
                    instructions);
                yield break;
            }

            // High: Marshal.GetActiveObject with shell indicators
            if (signals.HasMarshalGetActiveObject && hasShellIndicators)
            {
                yield return CreateFinding(
                    location,
                    "Accessing running COM instance with shell execution indicators",
                    Severity.High,
                    signals,
                    instructions);
                yield break;
            }
        }

        private static SignalCollection CollectSignals(Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            var signals = new SignalCollection();

            foreach (var instruction in instructions)
            {
                // Collect all string literals
                if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string str)
                {
                    signals.AllStrings.Add(str);
                }

                if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt)
                    continue;

                if (instruction.Operand is not MethodReference calledMethod)
                    continue;

                if (calledMethod.DeclaringType == null)
                    continue;

                string typeName = calledMethod.DeclaringType.FullName;
                string methodName = calledMethod.Name;

                // Type.GetTypeFromProgID
                if (typeName == "System.Type" && methodName == "GetTypeFromProgID")
                {
                    signals.HasGetTypeFromProgID = true;
                    signals.ProgIDValue = ExtractPrecedingString(instructions, instruction);
                }

                // Type.GetTypeFromCLSID
                if (typeName == "System.Type" && methodName == "GetTypeFromCLSID")
                {
                    signals.HasGetTypeFromCLSID = true;
                }

                // Activator.CreateInstance
                if (typeName == "System.Activator" && methodName == "CreateInstance")
                {
                    signals.HasActivatorCreateInstance = true;
                }

                // Type.InvokeMember (late-bound COM invocation - NOT MethodInfo.Invoke!)
                if (typeName == "System.Type" && methodName == "InvokeMember")
                {
                    signals.HasTypeInvokeMember = true;
                }

                // Marshal.GetActiveObject
                if (typeName == "System.Runtime.InteropServices.Marshal" && methodName == "GetActiveObject")
                {
                    signals.HasMarshalGetActiveObject = true;
                }
            }

            return signals;
        }

        private static string? ExtractPrecedingString(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            Instruction targetInstruction)
        {
            int index = instructions.IndexOf(targetInstruction);
            for (int i = Math.Max(0, index - 5); i < index; i++)
            {
                if (instructions[i].OpCode == OpCodes.Ldstr && instructions[i].Operand is string str)
                {
                    return str;
                }
            }
            return null;
        }

        private static ProgIDRiskLevel ClassifyProgID(string? progID)
        {
            if (string.IsNullOrEmpty(progID))
                return ProgIDRiskLevel.Unknown;

            if (CriticalProgIDs.Contains(progID))
                return ProgIDRiskLevel.Critical;

            if (HighRiskProgIDs.Contains(progID))
                return ProgIDRiskLevel.High;

            // Check for partial matches (e.g., "Shell" anywhere in the ProgID)
            if (progID.Contains("Shell", StringComparison.OrdinalIgnoreCase) ||
                progID.Contains("WScript", StringComparison.OrdinalIgnoreCase))
            {
                return ProgIDRiskLevel.Critical;
            }

            return ProgIDRiskLevel.Unknown;
        }

        private static ScanFinding CreateFinding(
            string location,
            string description,
            Severity severity,
            SignalCollection signals,
            Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            var snippet = new System.Text.StringBuilder();

            // Add context about what was detected
            if (signals.ProgIDValue != null)
                snippet.AppendLine($"ProgID: {signals.ProgIDValue}");

            if (signals.HasTypeInvokeMember)
                snippet.AppendLine("Uses: Type.InvokeMember (late-bound COM invocation)");

            if (signals.HasActivatorCreateInstance)
                snippet.AppendLine("Uses: Activator.CreateInstance");

            // Add suspicious strings found
            var suspiciousStrings = signals.AllStrings
                .Where(s => CommandStrings.Any(cmd => s.Contains(cmd, StringComparison.OrdinalIgnoreCase)) ||
                            ShellIndicators.Any(ind => s.Contains(ind, StringComparison.OrdinalIgnoreCase)))
                .Take(5)
                .ToList();

            if (suspiciousStrings.Count > 0)
            {
                snippet.AppendLine($"Suspicious strings: {string.Join(", ", suspiciousStrings.Select(s => $"\"{s}\""))}");
            }

            return new ScanFinding(location, description, severity, snippet.ToString().TrimEnd());
        }

        private enum ProgIDRiskLevel
        {
            Unknown,
            High,
            Critical
        }

        private class SignalCollection
        {
            public List<string> AllStrings { get; } = new();
            public bool HasGetTypeFromProgID { get; set; }
            public bool HasGetTypeFromCLSID { get; set; }
            public bool HasActivatorCreateInstance { get; set; }
            public bool HasTypeInvokeMember { get; set; }
            public bool HasMarshalGetActiveObject { get; set; }
            public string? ProgIDValue { get; set; }
        }
    }
}
