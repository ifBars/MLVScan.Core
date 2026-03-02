using System.Text.RegularExpressions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects Process.Start calls with severity scaling based on target and arguments.
    ///
    /// Severity levels:
    /// - Critical: LOLBin execution (powershell, cmd, mshta, wscript) with suspicious arguments
    /// - High: LOLBin execution without suspicious arguments, or suspicious arguments with unknown target
    /// - Medium: Unknown external process with arguments
    /// - Low: Known safe external tool (yt-dlp, ffmpeg, etc.)
    ///
    /// Suppresses safe patterns like:
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
            "Game mods should not start external processes as this can be used to execute malware. " +
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

        private static readonly HashSet<string> LolBinExecutables = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "regsvr32.exe",
            "rundll32.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "msiexec.exe",
            "svchost.exe",
            "sc.exe",
            "schtasks.exe",
            "wmic.exe"
        };

        private static readonly HashSet<string> KnownSafeTools = new(StringComparer.OrdinalIgnoreCase)
        {
            "yt-dlp.exe",
            "yt-dlp",
            "ffmpeg.exe",
            "ffmpeg",
            "ffprobe.exe",
            "ffprobe",
            "git.exe",
            "git",
            "node.exe",
            "node",
            "npm.exe",
            "npm",
            "python.exe",
            "python",
            "dotnet.exe",
            "dotnet"
        };

        private static readonly Regex SuspiciousArgumentPattern = new Regex(
            @"(?i)(-ep\s+bypass|-enc\s+[A-Za-z0-9+/=]|iex|invoke-(expression|webrequest)|iwr\s+|downloadstring|downloadfile|start-bitstransfer|hidden|windowstyle\s+hidden|createnowindow|net\.webclient|system\.net\.webclient|curl|wget|\bwget\b|\bcurl\b|out-file|set-content|add-content|>\s*[\w\\]|out-string|base64|frombase64string|http://|https://)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex TempPathPattern = new Regex(
            @"(?i)(%temp%|%tmp%|\\temp\\|\\tmp\\|gettemppath|gettempfile)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex DownloadPattern = new Regex(
            @"https?://[^\s""'<>]+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly HashSet<string> SystemAssemblies = new(StringComparer.OrdinalIgnoreCase)
        {
            "mscorlib",
            "System",
            "System.Core",
            "netstandard",
            "System.Runtime",
            "System.Diagnostics.Process"
        };

        private static bool IsSystemAssembly(string assemblyName)
        {
            if (string.IsNullOrEmpty(assemblyName))
                return false;

            // Exact match for common system assemblies
            if (SystemAssemblies.Contains(assemblyName))
                return true;

            // Check for common system assembly prefixes
            if (assemblyName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                assemblyName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase))
                return true;

            // Check for version-qualified assemblies (e.g., System.Diagnostics.Process.dll)
            if (assemblyName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                var baseName = assemblyName.Substring(0, assemblyName.Length - 4);
                if (SystemAssemblies.Contains(baseName))
                    return true;
            }

            return false;
        }

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return (typeName.Contains("System.Diagnostics.Process") && methodName == "Start") ||
                   (typeName.Contains("Process") && methodName == "Start");
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(
            MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            if (!IsSuspicious(method))
                yield break;

            // Skip findings at the framework/BCL method level - we only want findings at the caller level
            // This prevents duplicate findings like:
            // - System.Diagnostics.Process.Start:285 (less useful - framework method)
            // - MoreTrees.Mod/<AsyncSwitch>d__1.MoveNext:285 (useful - actual malicious code)
            //
            // IMPORTANT: Check by assembly name, not namespace, to prevent bypass attacks
            // where attacker creates their own "System.Diagnostics" namespace
            var declaringType = method.DeclaringType;
            if (declaringType?.Scope != null)
            {
                var assemblyName = declaringType.Scope.Name;
                // Only skip if it's from a real BCL/system assembly
                if (IsSystemAssembly(assemblyName))
                {
                    yield break;
                }
            }

            var target = ExtractProcessTarget(null, method, instructions, instructionIndex);
            var arguments = ExtractProcessArguments(null, instructions, instructionIndex);

            // Detect ProcessStartInfo evasion indicators
            var hasUseShell =
                InstructionValueResolver.TryResolveUseShellExecute(null, instructions, instructionIndex,
                    out var useShell);
            var hasCreateNoWin =
                InstructionValueResolver.TryResolveCreateNoWindow(null, instructions, instructionIndex,
                    out var createNoWin);
            var hasWindowStyle =
                InstructionValueResolver.TryResolveWindowStyle(null, instructions, instructionIndex,
                    out var windowStyle);
            var hasWorkingDir =
                InstructionValueResolver.TryResolveWorkingDirectory(null, instructions, instructionIndex,
                    out var workingDir);

            var useShellExecute = hasUseShell && useShell == true;
            var createNoWindow = hasCreateNoWin && createNoWin == true;
            var windowStyleHidden = hasWindowStyle && windowStyle == 1; // 1 = Hidden
            var workingDirectoryIsTemp = hasWorkingDir && workingDir != null && TempPathPattern.IsMatch(workingDir);

            var targetLower = target.ToLowerInvariant().Trim('"');
            var argumentsLower = arguments.ToLowerInvariant();

            var (severity, riskReason) = DetermineSeverity(targetLower, argumentsLower, target, arguments,
                useShellExecute, createNoWindow, windowStyleHidden, workingDirectoryIsTemp);

            if (severity == null)
                yield break;

            var description =
                $"Detected Process.Start call which could execute arbitrary programs. Target: {target}. Arguments: {arguments}";

            // Add evasion indicators to description
            var evasionIndicators = new List<string>();
            if (useShellExecute)
                evasionIndicators.Add("UseShellExecute=true");
            if (createNoWindow)
                evasionIndicators.Add("CreateNoWindow=true");
            if (windowStyleHidden)
                evasionIndicators.Add("WindowStyle=Hidden");
            if (workingDirectoryIsTemp)
                evasionIndicators.Add("WorkingDirectory=Temp");

            if (evasionIndicators.Count > 0)
            {
                description += " [Evasion: " + string.Join(", ", evasionIndicators) + "]";
            }

            if (!string.IsNullOrEmpty(riskReason))
                description += $" [{riskReason}]";

            var snippetBuilder = new System.Text.StringBuilder();
            int contextLines = 2;
            for (int j = Math.Max(0, instructionIndex - contextLines);
                 j < Math.Min(instructions.Count, instructionIndex + contextLines + 1);
                 j++)
            {
                snippetBuilder.Append(j == instructionIndex ? ">>> " : "    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            yield return new ScanFinding(
                $"{method.DeclaringType.FullName}.{method.Name}:{instructions[instructionIndex].Offset}",
                description,
                severity.Value,
                snippetBuilder.ToString().TrimEnd());
        }

        private (Severity? severity, string? reason) DetermineSeverity(
            string targetLower,
            string argumentsLower,
            string targetDisplay,
            string argumentsDisplay,
            bool useShellExecute = false,
            bool createNoWindow = false,
            bool windowStyleHidden = false,
            bool workingDirectoryIsTemp = false)
        {
            bool isLolBin = LolBinExecutables.Contains(targetLower) ||
                            LolBinExecutables.Any(lol =>
                                targetLower.EndsWith("\\" + lol) || targetLower.EndsWith("/" + lol));

            bool isKnownSafe = KnownSafeTools.Contains(targetLower) ||
                               KnownSafeTools.Any(safe =>
                                   targetLower.EndsWith("\\" + safe) || targetLower.EndsWith("/" + safe));

            bool hasSuspiciousArgs = !string.IsNullOrEmpty(argumentsLower) &&
                                     argumentsLower != "<unknown/no-arguments>" &&
                                     SuspiciousArgumentPattern.IsMatch(argumentsLower);

            bool hasDownloadUrl = !string.IsNullOrEmpty(argumentsLower) &&
                                  DownloadPattern.IsMatch(argumentsLower);

            bool hasTempPath = !string.IsNullOrEmpty(argumentsLower) &&
                               argumentsLower != "<unknown/no-arguments>" &&
                               TempPathPattern.IsMatch(argumentsLower);

            bool isUnknownTarget = targetLower.Contains("<unknown") || targetLower.Contains("<dynamic");

            // Check for evasion indicators first - these escalate severity
            bool hasEvasionIndicators =
                useShellExecute || createNoWindow || windowStyleHidden || workingDirectoryIsTemp;

            if (hasEvasionIndicators && isLolBin)
            {
                var reasons = new List<string>();
                if (useShellExecute)
                    reasons.Add("UseShellExecute");
                if (createNoWindow)
                    reasons.Add("CreateNoWindow");
                if (windowStyleHidden)
                    reasons.Add("WindowStyle.Hidden");
                if (workingDirectoryIsTemp)
                    reasons.Add("WorkingDirectory=Temp");
                return (Severity.Critical, $"LOLBin with hidden execution ({string.Join(", ", reasons)})");
            }

            if (hasEvasionIndicators && hasSuspiciousArgs)
            {
                return (Severity.Critical, "Process with evasion and suspicious arguments");
            }

            if (hasEvasionIndicators && hasDownloadUrl)
            {
                return (Severity.Critical, "Process with evasion and download URL");
            }

            if (hasEvasionIndicators && hasTempPath)
            {
                return (Severity.Critical, "Process with evasion and temp path execution");
            }

            if (hasEvasionIndicators)
            {
                var reasons = new List<string>();
                if (useShellExecute)
                    reasons.Add("UseShellExecute");
                if (createNoWindow)
                    reasons.Add("CreateNoWindow");
                if (windowStyleHidden)
                    reasons.Add("WindowStyle.Hidden");
                if (workingDirectoryIsTemp)
                    reasons.Add("WorkingDirectory=Temp");
                return (Severity.High, $"Hidden process execution ({string.Join(", ", reasons)})");
            }

            if (isLolBin && hasSuspiciousArgs)
            {
                return (Severity.Critical, "LOLBin with suspicious arguments");
            }

            if (isLolBin && hasDownloadUrl)
            {
                return (Severity.Critical, "LOLBin with URL in arguments");
            }

            if (isLolBin)
            {
                return (Severity.High, "LOLBin execution");
            }

            if (hasSuspiciousArgs && hasDownloadUrl)
            {
                return (Severity.Critical, "Process with suspicious download arguments");
            }

            if (hasSuspiciousArgs)
            {
                return (Severity.High, "Process with suspicious arguments");
            }

            if (isUnknownTarget && !string.IsNullOrEmpty(argumentsLower) && argumentsLower != "<unknown/no-arguments>")
            {
                return (Severity.Medium, "Unknown target with arguments");
            }

            if (isKnownSafe)
            {
                return (Severity.Low, "Known external tool");
            }

            if (isUnknownTarget)
            {
                return (Severity.Medium, "Unknown process target");
            }

            return (Severity.Medium, "External process execution");
        }

        public string GetFindingDescription(
            MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int instructionIndex)
        {
            return BuildFindingDescription(null, method, instructions, instructionIndex);
        }

        public string GetFindingDescription(
            MethodDefinition containingMethod,
            MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int instructionIndex)
        {
            return BuildFindingDescription(containingMethod, method, instructions, instructionIndex);
        }

        private string BuildFindingDescription(
            MethodDefinition? containingMethod,
            MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int instructionIndex)
        {
            string target = ExtractProcessTarget(containingMethod, method, instructions, instructionIndex);
            string arguments = ExtractProcessArguments(containingMethod, instructions, instructionIndex);

            // Detect ProcessStartInfo evasion indicators
            var hasUseShell = InstructionValueResolver.TryResolveUseShellExecute(containingMethod, instructions,
                instructionIndex, out var useShell);
            var hasCreateNoWin = InstructionValueResolver.TryResolveCreateNoWindow(containingMethod, instructions,
                instructionIndex, out var createNoWin);
            var hasWindowStyle = InstructionValueResolver.TryResolveWindowStyle(containingMethod, instructions,
                instructionIndex, out var windowStyle);
            var hasWorkingDir = InstructionValueResolver.TryResolveWorkingDirectory(containingMethod, instructions,
                instructionIndex, out var workingDir);

            var useShellExecute = hasUseShell && useShell == true;
            var createNoWindow = hasCreateNoWin && createNoWin == true;
            var windowStyleHidden = hasWindowStyle && windowStyle == 1; // 1 = Hidden
            var workingDirectoryIsTemp = hasWorkingDir && workingDir != null && TempPathPattern.IsMatch(workingDir);

            var description = $"{Description} Target: {target}. Arguments: {arguments}";

            // Add evasion indicators to description
            var evasionIndicators = new List<string>();
            if (useShellExecute)
                evasionIndicators.Add("UseShellExecute=true");
            if (createNoWindow)
                evasionIndicators.Add("CreateNoWindow=true");
            if (windowStyleHidden)
                evasionIndicators.Add("WindowStyle=Hidden");
            if (workingDirectoryIsTemp)
                evasionIndicators.Add("WorkingDirectory=Temp");

            if (evasionIndicators.Count > 0)
            {
                description += " [Evasion: " + string.Join(", ", evasionIndicators) + "]";
            }

            return description;
        }

        public bool ShouldSuppressFinding(
            MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals,
            MethodSignals? typeSignals = null)
        {
            if (methodSignals?.HasEnvironmentVariableModification == true ||
                typeSignals?.HasEnvironmentVariableModification == true)
            {
                return false;
            }

            if (methodSignals?.HasFileWrite == true ||
                typeSignals?.HasFileWrite == true)
            {
                return false;
            }

            if (IsSafeBareExplorerLaunch(instructions, instructionIndex))
            {
                return true;
            }

            if (IsCurrentProcessRestart(instructions, instructionIndex))
            {
                return true;
            }

            return false;
        }

        private static bool IsSafeBareExplorerLaunch(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            for (int i = Math.Max(0, processStartIndex - 10); i < processStartIndex; i++)
            {
                var instruction = instructions[i];
                if (instruction.OpCode == Mono.Cecil.Cil.OpCodes.Ldstr &&
                    instruction.Operand is string str)
                {
                    if (!str.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (str.Contains("\\") || str.Contains("/") || str.Contains(":"))
                    {
                        return false;
                    }

                    if (HasPathManipulation(instructions, i, processStartIndex))
                    {
                        return false;
                    }

                    return true;
                }
            }

            return false;
        }

        private static bool HasPathManipulation(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int strIndex,
            int callIndex)
        {
            for (int i = strIndex + 1; i < callIndex; i++)
            {
                var inst = instructions[i];

                if (inst.OpCode == Mono.Cecil.Cil.OpCodes.Call || inst.OpCode == Mono.Cecil.Cil.OpCodes.Callvirt)
                {
                    if (inst.Operand is MethodReference methodRef)
                    {
                        var typeName = methodRef.DeclaringType?.FullName ?? "";
                        var methodName = methodRef.Name ?? "";

                        if ((typeName == "System.String" &&
                             (methodName == "Concat" || methodName == "Format" || methodName == "Replace")) ||
                            (typeName == "System.IO.Path" &&
                             (methodName == "Combine" || methodName == "Join" || methodName == "GetFullPath")))
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static bool IsCurrentProcessRestart(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            bool foundGetCurrentProcess = false;
            bool foundGetMainModule = false;
            bool foundGetFileName = false;

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

                if (typeName == "System.Diagnostics.Process" && methodName == "GetCurrentProcess")
                {
                    foundGetCurrentProcess = true;
                    getCurrentProcessIndex = i;
                }
                else if (typeName == "System.Diagnostics.Process" && methodName == "get_MainModule")
                {
                    if (foundGetCurrentProcess && i > getCurrentProcessIndex)
                    {
                        foundGetMainModule = true;
                        getMainModuleIndex = i;
                    }
                }
                else if (typeName == "System.Diagnostics.ProcessModule" && methodName == "get_FileName")
                {
                    if (foundGetMainModule && i > getMainModuleIndex)
                    {
                        foundGetFileName = true;
                        getFileNameIndex = i;
                    }
                }
            }

            if (foundGetCurrentProcess && foundGetMainModule && foundGetFileName)
            {
                if (getFileNameIndex > 0)
                {
                    for (int i = getFileNameIndex + 1; i < processStartIndex; i++)
                    {
                        var inst = instructions[i];
                        if (inst.OpCode != Mono.Cecil.Cil.OpCodes.Call &&
                            inst.OpCode != Mono.Cecil.Cil.OpCodes.Callvirt)
                            continue;

                        if (inst.Operand is MethodReference methodRef)
                        {
                            var typeName = methodRef.DeclaringType?.FullName ?? "";
                            var methodName = methodRef.Name ?? "";

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

        private static string ExtractProcessTarget(
            MethodDefinition? containingMethod,
            MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            if (InstructionValueResolver.TryResolveProcessTarget(containingMethod, method, instructions,
                    processStartIndex, out string target))
            {
                return target;
            }

            return "<unknown/non-literal>";
        }

        private static string ExtractProcessArguments(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            if (InstructionValueResolver.TryResolveProcessArguments(containingMethod, instructions, processStartIndex,
                    out string arguments))
            {
                return arguments;
            }

            return "<unknown/no-arguments>";
        }
    }
}
