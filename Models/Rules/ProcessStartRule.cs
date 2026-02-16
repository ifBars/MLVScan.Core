using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects Process.Start calls that could execute arbitrary programs.
    /// Includes contextual analysis to suppress safe patterns like:
    /// - Bare "explorer.exe" calls (Windows Explorer file/folder operations)
    /// - Current process restart patterns
    /// </summary>
    public class ProcessStartRule : IScanRule
    {
        public string Description => "Detected Process.Start call which could execute arbitrary programs.";
        public Severity Severity => Severity.Critical;
        public string RuleId => "ProcessStartRule";
        public bool RequiresCompanionFinding => false;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "MelonLoader mods should not start external processes. " +
            "For legitimate use cases like opening folders, use Process.Start(\"explorer.exe\", path). " +
            "For restart functionality, use Process.GetCurrentProcess().MainModule.FileName.",
            null,
            new[]
            {
                "Process.Start(\"explorer.exe\", folderPath) - opens folder in Explorer",
                "Process.GetCurrentProcess().MainModule.FileName - gets current executable for restart"
            },
            isRemediable: true
        );

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return (typeName.Contains("System.Diagnostics.Process") && methodName == "Start") ||
                   (typeName.Contains("Process") && methodName == "Start");
        }

        /// <summary>
        /// Determines if a Process.Start finding should be suppressed based on contextual analysis.
        /// Suppresses safe patterns like bare "explorer.exe" and current process restart.
        /// SECURITY: Never suppress if:
        /// - Environment variables were modified (prevents PATH manipulation attacks)
        /// - File writes were performed in method or type (prevents embedded resource extraction attacks)
        /// </summary>
        public bool ShouldSuppressFinding(
            MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals,
            MethodSignals? typeSignals = null)
        {
            // SECURITY CHECK 1: Never suppress if environment variables were modified
            // This prevents PATH manipulation attacks where attacker modifies PATH to point
            // to a malicious explorer.exe before calling Process.Start("explorer.exe")
            if (methodSignals?.HasEnvironmentVariableModification == true ||
                typeSignals?.HasEnvironmentVariableModification == true)
            {
                return false;
            }

            // SECURITY CHECK 2: Never suppress if files were written (method or type level)
            // This prevents embedded resource attacks where attacker:
            // 1. Embeds malicious explorer.exe as resource
            // 2. Writes it to disk in ANY method in the type (File.WriteAllBytes, File.Move, etc.)
            // 3. Calls Process.Start("explorer.exe") from a different method
            // Also catches cross-method attacks where Drop() writes and Execute() runs
            if (methodSignals?.HasFileWrite == true ||
                typeSignals?.HasFileWrite == true)
            {
                return false;
            }

            // Check if this is a safe explorer.exe call (bare filename, no path manipulation)
            if (IsSafeBareExplorerLaunch(instructions, instructionIndex))
            {
                return true;
            }

            // Check if this is a current process restart pattern
            if (IsCurrentProcessRestart(instructions, instructionIndex))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if the Process.Start call is using bare "explorer.exe" with no path manipulation.
        /// This is safe because Windows PATH prioritizes system directories.
        /// </summary>
        private static bool IsSafeBareExplorerLaunch(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            // Look back up to 10 instructions for string loading
            for (int i = Math.Max(0, processStartIndex - 10); i < processStartIndex; i++)
            {
                var instruction = instructions[i];
                if (instruction.OpCode == Mono.Cecil.Cil.OpCodes.Ldstr &&
                    instruction.Operand is string str)
                {
                    // Must be EXACTLY "explorer.exe" (case-insensitive for Windows)
                    if (!str.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Reject if this is a path (contains path separators or full path indicator)
                    // Examples that are REJECTED:
                    // - "C:\Windows\explorer.exe" (contains backslash)
                    // - "C:/Windows/explorer.exe" (contains forward slash)
                    // - "MyFolder/explorer.exe" (contains path separator)
                    // - "..\explorer.exe" (contains parent directory)
                    if (str.Contains("\\") || str.Contains("/") || str.Contains(":"))
                    {
                        return false;
                    }

                    // Check for path manipulation between ldstr and Process.Start
                    if (HasPathManipulation(instructions, i, processStartIndex))
                    {
                        return false;
                    }

                    // Safe pattern detected: bare "explorer.exe" literal with no manipulation
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks for path manipulation operations between the string literal and the Process.Start call.
        /// </summary>
        private static bool HasPathManipulation(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int strIndex,
            int callIndex)
        {
            // Check instructions between ldstr "explorer.exe" and Process.Start call
            for (int i = strIndex + 1; i < callIndex; i++)
            {
                var inst = instructions[i];

                // Check for string/concatenation operations that could manipulate the path
                if (inst.OpCode == Mono.Cecil.Cil.OpCodes.Call || inst.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt)
                {
                    if (inst.Operand is MethodReference methodRef)
                    {
                        var typeName = methodRef.DeclaringType?.FullName ?? "";
                        var methodName = methodRef.Name ?? "";

                        // Dangerous string operations that could manipulate the path
                        if ((typeName == "System.String" &&
                             (methodName == "Concat" || methodName == "Format" || methodName == "Replace")) ||
                            (typeName == "System.IO.Path" &&
                             (methodName == "Combine" || methodName == "Join" || methodName == "GetFullPath")))
                        {
                            return true; // Path manipulation detected
                        }
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if this is a current process restart pattern.
        /// Pattern: Process.GetCurrentProcess() -> get_MainModule() -> get_FileName() -> Process.Start()
        /// This is safe because it restarts the same executable already running.
        /// </summary>
        private static bool IsCurrentProcessRestart(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            // Look back up to 40 instructions for the restart pattern
            // The pattern requires all three calls in order:
            // 1. Process.GetCurrentProcess()
            // 2. Process.get_MainModule()
            // 3. ProcessModule.get_FileName()
            bool foundGetCurrentProcess = false;
            bool foundGetMainModule = false;
            bool foundGetFileName = false;

            // Track the order and proximity of the calls
            int getCurrentProcessIndex = -1;
            int getMainModuleIndex = -1;
            int getFileNameIndex = -1;

            int searchStart = Math.Max(0, processStartIndex - 40);

            for (int i = searchStart; i < processStartIndex; i++)
            {
                var instruction = instructions[i];

                if (instruction.OpCode != Mono.Cecil.Cil.OpCodes.Call &&
                    instruction.OpCode != Mono.Cecil.Cil.OpCodes.Callvirt)
                    continue;

                if (instruction.Operand is not MethodReference methodRef)
                    continue;

                var typeName = methodRef.DeclaringType?.FullName ?? "";
                var methodName = methodRef.Name ?? "";

                // Check for Process.GetCurrentProcess()
                if (typeName == "System.Diagnostics.Process" && methodName == "GetCurrentProcess")
                {
                    foundGetCurrentProcess = true;
                    getCurrentProcessIndex = i;
                }
                // Check for Process.get_MainModule()
                else if (typeName == "System.Diagnostics.Process" && methodName == "get_MainModule")
                {
                    // Must come after GetCurrentProcess
                    if (foundGetCurrentProcess && i > getCurrentProcessIndex)
                    {
                        foundGetMainModule = true;
                        getMainModuleIndex = i;
                    }
                }
                // Check for ProcessModule.get_FileName()
                else if (typeName == "System.Diagnostics.ProcessModule" && methodName == "get_FileName")
                {
                    // Must come after get_MainModule
                    if (foundGetMainModule && i > getMainModuleIndex)
                    {
                        foundGetFileName = true;
                        getFileNameIndex = i;
                    }
                }
            }

            // All three calls must be present and in the correct order
            if (foundGetCurrentProcess && foundGetMainModule && foundGetFileName)
            {
                // Additional safety check: ensure there are no string manipulation operations
                // on the FileName result before Process.Start
                if (getFileNameIndex > 0)
                {
                    for (int i = getFileNameIndex + 1; i < processStartIndex; i++)
                    {
                        var inst = instructions[i];
                        if (inst.OpCode != Mono.Cecil.Cil.OpCodes.Call && inst.OpCode != Mono.Cecil.Cil.OpCodes.Callvirt)
                            continue;

                        if (inst.Operand is MethodReference methodRef)
                        {
                            var typeName = methodRef.DeclaringType?.FullName ?? "";
                            var methodName = methodRef.Name ?? "";

                            // Reject if string manipulation occurs
                            if ((typeName == "System.String" &&
                                 (methodName == "Concat" || methodName == "Format" || methodName == "Replace")) ||
                                (typeName == "System.IO.Path" &&
                                 (methodName == "Combine" || methodName == "Join")))
                            {
                                return false;
                            }
                        }
                    }
                }

                return true;
            }

            return false;
        }
    }
}
