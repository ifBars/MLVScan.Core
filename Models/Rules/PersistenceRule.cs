using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Companion rule that detects file writes to the actual TEMP folder.
    /// Only triggers on Path.GetTempPath() + file write combinations.
    /// This is the primary location malware drops payloads.
    /// </summary>
    public class PersistenceRule : IScanRule
    {
        public string Description => "Detected file write to %TEMP% folder (companion finding).";
        public Severity Severity => Severity.Medium;
        public string RuleId => "PersistenceRule";
        public bool RequiresCompanionFinding => true;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "Use your mod framework's configuration system instead of direct file I/O. " +
            "For MelonLoader: use MelonPreferences. For BepInEx: use Config.Bind<T>(). " +
            "For save data, use the game's official persistence APIs if available. " +
            "Do not write executable files to TEMP or other system folders.",
            null,
            new[] {
                "MelonPreferences.CreateEntry<T> (MelonLoader)",
                "Config.Bind<T> (BepInEx)",
                "UnityEngine.PlayerPrefs (Unity)"
            },
            true
        );

        public static bool IsSensitiveFolder(int folderValue)
        {
            return false;
        }

        public static string GetFolderName(int folderValue)
        {
            return $"Folder({folderValue})";
        }

        private static bool IsModFrameworkType(string typeName)
        {
            if (string.IsNullOrEmpty(typeName))
                return false;

            // Check for known mod framework environment types
            return typeName.Contains("MelonEnvironment") ||
                   typeName.Contains("MelonLoader") ||
                   typeName.Contains("BepInEx") ||
                   typeName.Contains("BepInEx.Paths");
        }

        public bool IsSuspicious(MethodReference method)
        {
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(
            MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            string typeName = method.DeclaringType.FullName;
            string methodName = method.Name;

            bool isFileWrite =
                typeName.Equals("System.IO.File", StringComparison.OrdinalIgnoreCase) &&
                (methodName.Contains("Write", StringComparison.OrdinalIgnoreCase) ||
                 methodName.Contains("Create", StringComparison.OrdinalIgnoreCase));

            if (!isFileWrite)
                yield break;

            // Check if this method uses mod framework paths - if so, skip
            foreach (var instr in instructions)
            {
                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) &&
                    instr.Operand is MethodReference calledMethod)
                {
                    var declaringType = calledMethod.DeclaringType?.FullName ?? "";
                    // Skip known mod framework environment types
                    if (IsModFrameworkType(declaringType))
                    {
                        yield break;
                    }
                }
            }

            // Only flag if we find actual Path.GetTempPath() call
            bool foundTempPath = false;

            for (int i = 0; i < instructions.Count; i++)
            {
                var instr = instructions[i];

                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt) &&
                    instr.Operand is MethodReference pathMethod)
                {
                    var pathDeclaringType = pathMethod.DeclaringType?.FullName ?? "";

                    if (pathDeclaringType == "System.IO.Path" && pathMethod.Name == "GetTempPath")
                    {
                        foundTempPath = true;
                        break;
                    }
                }
            }

            // Only flag if we actually found Path.GetTempPath
            if (foundTempPath)
            {
                var snippetBuilder = new System.Text.StringBuilder();
                int contextLines = 2;
                for (int j = Math.Max(0, instructionIndex - contextLines); j < Math.Min(instructions.Count, instructionIndex + contextLines + 1); j++)
                {
                    snippetBuilder.Append(j == instructionIndex ? ">>> " : "    ");
                    snippetBuilder.AppendLine(instructions[j].ToString());
                }

                yield return new ScanFinding(
                    $"{method.DeclaringType.FullName}.{method.Name}:{instructions[instructionIndex].Offset}",
                    "Potential payload drop: Writing to TEMP folder (companion finding)",
                    Severity.Medium,
                    snippetBuilder.ToString().TrimEnd());
            }
        }
    }
}
