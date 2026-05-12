using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Companion rule that detects file writes to payload staging folders.
    /// Triggers on Path.GetTempPath() writes and executable/script writes to sensitive folders.
    /// </summary>
    public class PersistenceRule : IScanRule
    {
        private static readonly HashSet<string> SuspiciousPayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com"
        };

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
            new[]
            {
                "MelonPreferences.CreateEntry<T> (MelonLoader)", "Config.Bind<T> (BepInEx)",
                "UnityEngine.PlayerPrefs (Unity)"
            },
            true
        );

        public static bool IsSensitiveFolder(int folderValue)
        {
            return folderValue is
                7 or  // Startup
                24 or // CommonStartup
                36 or // Windows
                37 or // System
                38 or // ProgramFiles
                42;   // ProgramFilesX86
        }

        public static string GetFolderName(int folderValue)
        {
            return folderValue switch
            {
                7 => "Startup",
                24 => "CommonStartup",
                26 => "ApplicationData",
                28 => "LocalApplicationData",
                35 => "CommonApplicationData",
                36 => "Windows",
                37 => "System",
                38 => "ProgramFiles",
                42 => "ProgramFilesX86",
                _ => $"Folder({folderValue})"
            };
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

            bool isFileWrite = IsFileWriteOperation(typeName, methodName, instructions, instructionIndex);

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
            string? sensitiveFolderName = null;

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

                    if (pathDeclaringType == "System.Environment" && pathMethod.Name == "GetFolderPath")
                    {
                        var folderValue = Services.Helpers.InstructionHelper.ExtractFolderPathArgument(instructions, i);
                        if (folderValue.HasValue && IsPayloadStagingFolder(folderValue.Value))
                        {
                            sensitiveFolderName = GetFolderName(folderValue.Value);
                        }
                    }
                }
            }

            bool foundSensitivePayloadWrite = sensitiveFolderName != null &&
                                              HasSuspiciousPayloadPath(instructions, instructionIndex);

            if (foundTempPath || foundSensitivePayloadWrite)
            {
                var snippetBuilder = new System.Text.StringBuilder();
                int contextLines = 2;
                for (int j = Math.Max(0, instructionIndex - contextLines);
                     j < Math.Min(instructions.Count, instructionIndex + contextLines + 1);
                     j++)
                {
                    snippetBuilder.Append(j == instructionIndex ? ">>> " : "    ");
                    snippetBuilder.AppendLine(instructions[j].ToString());
                }

                string description = foundTempPath
                    ? "Potential payload drop: Writing to TEMP folder (companion finding)"
                    : $"Potential payload drop: Writing executable/script payload to sensitive folder {sensitiveFolderName} (companion finding)";

                yield return new ScanFinding(
                    $"{method.DeclaringType.FullName}.{method.Name}:{instructions[instructionIndex].Offset}",
                    description,
                    Severity.Medium,
                    snippetBuilder.ToString().TrimEnd());
            }
        }

        private static bool IsPayloadStagingFolder(int folderValue)
        {
            return IsSensitiveFolder(folderValue) ||
                   folderValue is
                       26 or // ApplicationData
                       28 or // LocalApplicationData
                       35;   // CommonApplicationData / ProgramData
        }

        private static bool HasSuspiciousPayloadPath(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex)
        {
            int start = Math.Max(0, instructionIndex - 12);
            int end = Math.Min(instructions.Count, instructionIndex + 3);

            for (int i = start; i < end; i++)
            {
                if (instructions[i].OpCode != OpCodes.Ldstr || instructions[i].Operand is not string literal)
                    continue;

                if (SuspiciousPayloadExtensions.Any(ext =>
                        literal.EndsWith(ext, StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains(ext + "\"", StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains(ext + "'", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsFileWriteOperation(
            string typeName,
            string methodName,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex)
        {
            if (typeName.Equals("System.IO.File", StringComparison.OrdinalIgnoreCase) &&
                (methodName.Contains("Write", StringComparison.OrdinalIgnoreCase) ||
                 methodName.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
                 methodName.Contains("Append", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (typeName.Equals("System.IO.FileStream", StringComparison.OrdinalIgnoreCase) &&
                methodName.Equals(".ctor", StringComparison.OrdinalIgnoreCase))
            {
                return HasWritableFileStreamArguments(instructions, instructionIndex);
            }

            if ((typeName.Equals("System.IO.StreamWriter", StringComparison.OrdinalIgnoreCase) ||
                 typeName.Equals("System.IO.BinaryWriter", StringComparison.OrdinalIgnoreCase)) &&
                methodName.StartsWith("Write", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        private static bool HasWritableFileStreamArguments(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex)
        {
            int start = Math.Max(0, instructionIndex - 8);
            var values = new List<int>();

            for (int i = start; i < instructionIndex; i++)
            {
                var instruction = instructions[i];
                if (!TryGetInt32(instruction, out int value))
                    continue;

                values.Add(value);
            }

            if (values.Count == 0)
                return false;

            // Constructor overloads that include FileAccess load it after FileMode.
            if (values.Count >= 2)
            {
                int access = values[^1];
                if (access == 2 || access == 3) // Write or ReadWrite.
                    return true;

                if (access == 1) // Read.
                    return false;
            }

            int mode = values[^1];
            return mode == 1 || mode == 2 || mode == 4 || mode == 5 || mode == 6;
        }

        private static bool TryGetInt32(Instruction instruction, out int value)
        {
            switch (instruction.OpCode.Code)
            {
                case Code.Ldc_I4_M1:
                    value = -1;
                    return true;
                case Code.Ldc_I4_0:
                    value = 0;
                    return true;
                case Code.Ldc_I4_1:
                    value = 1;
                    return true;
                case Code.Ldc_I4_2:
                    value = 2;
                    return true;
                case Code.Ldc_I4_3:
                    value = 3;
                    return true;
                case Code.Ldc_I4_4:
                    value = 4;
                    return true;
                case Code.Ldc_I4_5:
                    value = 5;
                    return true;
                case Code.Ldc_I4_6:
                    value = 6;
                    return true;
                case Code.Ldc_I4_7:
                    value = 7;
                    return true;
                case Code.Ldc_I4_8:
                    value = 8;
                    return true;
                case Code.Ldc_I4_S:
                    value = (sbyte)instruction.Operand;
                    return true;
                case Code.Ldc_I4:
                    value = (int)instruction.Operand;
                    return true;
                default:
                    value = 0;
                    return false;
            }
        }
    }
}
