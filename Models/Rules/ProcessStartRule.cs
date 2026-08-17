using System.Text.RegularExpressions;
using MLVScan.Abstractions;
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
    /// - Critical: Staged loader execution chain (download -> temp drop -> execute), or LOLBin with suspicious/evasive args
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
        private Severity _severity = Severity.Critical;

        public string Description => "Detected Process.Start call which could execute arbitrary programs.";
        public Severity Severity => _severity;
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
            "powershell",
            "pwsh.exe",
            "pwsh",
            "cmd.exe",
            "cmd",
            "mshta.exe",
            "mshta",
            "wscript.exe",
            "wscript",
            "cscript.exe",
            "cscript",
            "regsvr32.exe",
            "regsvr32",
            "rundll32.exe",
            "rundll32",
            "certutil.exe",
            "certutil",
            "bitsadmin.exe",
            "bitsadmin",
            "msiexec.exe",
            "msiexec",
            "svchost.exe",
            "svchost",
            "sc.exe",
            "sc",
            "schtasks.exe",
            "schtasks",
            "wmic.exe",
            "wmic"
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
            @"(?i)((-|/)ep\s+bypass|(-|/)executionpolicy\s+bypass|(-|/)enc(odedcommand)?\s+[A-Za-z0-9+/=]|(-|/)nop(rofile)?\b|iex|invoke-(expression|webrequest|restmethod)|iwr\s+|irm\s+|\biwx\b|\biwe\b|downloadstring|downloadfile|start-bitstransfer|hidden|windowstyle\s+hidden|(-|/)w\s+hidden|createnowindow|net\.webclient|system\.net\.webclient|curl|wget|\bwget\b|\bcurl\b|out-file|set-content|add-content|>\s*[\w\\]|out-string|base64|frombase64string)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex TempPathPattern = new Regex(
            @"(?i)(%temp%|%tmp%|\\temp\\|\\tmp\\|gettemppath|gettempfile)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex DownloadPattern = new Regex(
            @"https?://[^\s""'<>]+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex ScriptDropExtensionPattern = new Regex(
            @"(?i)\.(bat|cmd|ps1|vbs|js|hta)(\b|\s|\""|'|$)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex StagedLoaderPivotPattern = new Regex(
            @"(?i)(\s/c\s|\s/k\s|start-process|\bstart\b|\bcall\b|&&|\|)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex StagedLoaderDownloadCommandPattern = new Regex(
            @"(?i)(\biwr\b|invoke-webrequest|\birm\b|invoke-restmethod|\biex\b|invoke-expression|\biwx\b|\biwe\b|downloadstring|downloadfile|start-bitstransfer|new-object\s+net\.webclient|\bcurl\b|\bwget\b)",
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
            var hasUseShellExecuteIndicator = hasUseShell || HasProcessStartInfoSetter(instructions, instructionIndex, "set_UseShellExecute");
            var hasCreateNoWindowIndicator = hasCreateNoWin || HasProcessStartInfoSetter(instructions, instructionIndex, "set_CreateNoWindow");
            var hasWindowStyleIndicator = hasWindowStyle || HasProcessStartInfoSetter(instructions, instructionIndex, "set_WindowStyle");
            var hasWorkingDirectoryIndicator = hasWorkingDir || HasProcessStartInfoSetter(instructions, instructionIndex, "set_WorkingDirectory");
            var hasRedirectStandardInputIndicator =
                HasProcessStartInfoSetter(instructions, instructionIndex, "set_RedirectStandardInput");
            var hasRedirectStandardOutputIndicator =
                HasProcessStartInfoSetter(instructions, instructionIndex, "set_RedirectStandardOutput");
            var hasRedirectStandardErrorIndicator =
                HasProcessStartInfoSetter(instructions, instructionIndex, "set_RedirectStandardError");

            var targetLower = target.ToLowerInvariant().Trim('"');
            var argumentsLower = arguments.ToLowerInvariant();

            var (severity, riskReason) = DetermineSeverity(targetLower, argumentsLower, target, arguments,
                useShellExecute, createNoWindow, windowStyleHidden, workingDirectoryIsTemp,
                hasUseShellExecuteIndicator, hasCreateNoWindowIndicator, hasWindowStyleIndicator,
                hasWorkingDirectoryIndicator, hasRedirectStandardInputIndicator,
                hasRedirectStandardOutputIndicator, hasRedirectStandardErrorIndicator,
                methodSignals?.HasNetworkCall == true,
                methodSignals?.HasFileWrite == true);

            if (severity == null)
                yield break;

            var description =
                $"Detected Process.Start call which could execute arbitrary programs. Target: {target}. Arguments: {arguments}";

            // Add evasion indicators to description
            var evasionIndicators = new List<string>();
            AddProcessStartInfoIndicators(evasionIndicators, useShellExecute, createNoWindow, windowStyleHidden,
                workingDirectoryIsTemp, hasUseShellExecuteIndicator, hasCreateNoWindowIndicator,
                hasWindowStyleIndicator, hasWorkingDirectoryIndicator);

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
            bool workingDirectoryIsTemp = false,
            bool hasUseShellExecuteIndicator = false,
            bool hasCreateNoWindowIndicator = false,
            bool hasWindowStyleIndicator = false,
            bool hasWorkingDirectoryIndicator = false,
            bool hasRedirectStandardInputIndicator = false,
            bool hasRedirectStandardOutputIndicator = false,
            bool hasRedirectStandardErrorIndicator = false,
            bool hasNetworkCallSignal = false,
            bool hasFileWriteSignal = false)
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

            bool hasResolverPlaceholderArgs = argumentsLower.Contains("<arg ") ||
                                              argumentsLower.Contains("<dynamic") ||
                                              argumentsLower.Contains("<unknown");

            if (hasResolverPlaceholderArgs)
            {
                hasSuspiciousArgs = false;
            }

            bool hasDownloadUrl = !string.IsNullOrEmpty(argumentsLower) &&
                                  DownloadPattern.IsMatch(argumentsLower);

            bool hasTempPath = !string.IsNullOrEmpty(argumentsLower) &&
                               argumentsLower != "<unknown/no-arguments>" &&
                               TempPathPattern.IsMatch(argumentsLower);

            bool hasScriptDropExtension = !string.IsNullOrEmpty(argumentsLower) &&
                                          argumentsLower != "<unknown/no-arguments>" &&
                                          ScriptDropExtensionPattern.IsMatch(argumentsLower);

            bool hasStagedLoaderPivot = !string.IsNullOrEmpty(argumentsLower) &&
                                        argumentsLower != "<unknown/no-arguments>" &&
                                        StagedLoaderPivotPattern.IsMatch(argumentsLower);

            bool hasStagedDownloadCommand = !string.IsNullOrEmpty(argumentsLower) &&
                                            argumentsLower != "<unknown/no-arguments>" &&
                                            StagedLoaderDownloadCommandPattern.IsMatch(argumentsLower);

            bool isUnknownTarget = targetLower.Contains("<unknown") || targetLower.Contains("<dynamic");

            // Check for evasion indicators first - these escalate severity
            bool hasStrongEvasionIndicators =
                useShellExecute || createNoWindow || windowStyleHidden || workingDirectoryIsTemp;

            bool hasProcessStartInfoIndicators =
                hasUseShellExecuteIndicator || hasCreateNoWindowIndicator || hasWindowStyleIndicator ||
                hasWorkingDirectoryIndicator;

            bool hasEvasionIndicators = hasStrongEvasionIndicators || hasProcessStartInfoIndicators;
            bool hasRedirectedStandardIo =
                hasRedirectStandardInputIndicator || hasRedirectStandardOutputIndicator ||
                hasRedirectStandardErrorIndicator;
            bool isControlledChildProcess =
                !isLolBin &&
                !hasSuspiciousArgs &&
                !hasDownloadUrl &&
                !hasTempPath &&
                !hasScriptDropExtension &&
                !hasStagedDownloadCommand &&
                !hasStagedLoaderPivot &&
                !hasNetworkCallSignal &&
                !hasFileWriteSignal &&
                !useShellExecute &&
                createNoWindow &&
                hasRedirectedStandardIo;

            bool hasStagedLoaderChain =
                hasDownloadUrl &&
                (hasTempPath || hasScriptDropExtension || workingDirectoryIsTemp) &&
                (hasStagedDownloadCommand || hasStagedLoaderPivot || hasSuspiciousArgs || hasFileWriteSignal ||
                 hasNetworkCallSignal);

            if (hasStagedLoaderChain)
            {
                if (isLolBin || hasStrongEvasionIndicators || hasFileWriteSignal || hasNetworkCallSignal)
                {
                    return (Severity.Critical, "Staged loader chain (download -> temp drop -> execute)");
                }

                if (hasProcessStartInfoIndicators)
                {
                    return (Severity.Critical,
                        "Staged loader chain with ProcessStartInfo execution indicators");
                }

                return (Severity.High, "Potential staged loader chain (download -> temp drop -> execute)");
            }

            if (isKnownSafe)
            {
                if ((hasDownloadUrl && hasTempPath && hasEvasionIndicators) ||
                    (hasEvasionIndicators && hasFileWriteSignal && hasNetworkCallSignal))
                {
                    return (Severity.High, "Known tool with suspicious download-and-execute chain");
                }

                if (hasSuspiciousArgs && hasEvasionIndicators)
                {
                    return (Severity.High, "Known tool with suspicious hidden execution arguments");
                }

                if (hasEvasionIndicators || hasSuspiciousArgs || hasDownloadUrl || hasTempPath)
                {
                    return (Severity.Medium, "Known external tool with elevated execution context");
                }

                return (Severity.Low, "Known external tool");
            }

            if (isControlledChildProcess)
            {
                return (Severity.Medium, "Controlled child process with redirected I/O");
            }

            if (hasStrongEvasionIndicators && isLolBin)
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

            if (hasProcessStartInfoIndicators && isLolBin)
            {
                return (Severity.Critical, "LOLBin with ProcessStartInfo execution indicators");
            }

            if (hasStrongEvasionIndicators && hasSuspiciousArgs)
            {
                return (Severity.Critical, "Process with evasion and suspicious arguments");
            }

            if (hasProcessStartInfoIndicators && hasSuspiciousArgs)
            {
                return (Severity.Critical, "ProcessStartInfo execution with suspicious arguments");
            }

            if (hasStrongEvasionIndicators && hasDownloadUrl)
            {
                return (Severity.Critical, "Process with evasion and download URL");
            }

            if (hasProcessStartInfoIndicators && hasDownloadUrl)
            {
                return (Severity.Critical, "ProcessStartInfo execution with download URL");
            }

            if (hasStrongEvasionIndicators && hasTempPath)
            {
                return (Severity.Critical, "Process with evasion and temp path execution");
            }

            if (hasProcessStartInfoIndicators && hasTempPath)
            {
                return (Severity.Critical, "ProcessStartInfo execution with temp path indicator");
            }

            if (hasStrongEvasionIndicators)
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

            if (hasProcessStartInfoIndicators)
            {
                var reasons = new List<string>();
                if (hasUseShellExecuteIndicator)
                    reasons.Add("UseShellExecute");
                if (hasCreateNoWindowIndicator)
                    reasons.Add("CreateNoWindow");
                if (hasWindowStyleIndicator)
                    reasons.Add("WindowStyle");
                if (hasWorkingDirectoryIndicator)
                    reasons.Add("WorkingDirectory");
                return (Severity.High,
                    $"ProcessStartInfo execution indicators ({string.Join(", ", reasons)})");
            }

            if (isLolBin && hasSuspiciousArgs)
            {
                return (Severity.Critical, "LOLBin with suspicious arguments");
            }

            if (isLolBin && hasDownloadUrl)
            {
                return (Severity.Critical, "LOLBin with URL in arguments");
            }

            if (isLolBin && hasTempPath)
            {
                return (Severity.Critical, "LOLBin with temp path execution");
            }

            if (isLolBin)
            {
                return (Severity.High, "LOLBin execution");
            }

            if (hasSuspiciousArgs && hasDownloadUrl)
            {
                if (hasEvasionIndicators && hasTempPath)
                {
                    return (Severity.Critical, "Process with hidden suspicious download-to-temp execution");
                }

                return (Severity.High, "Process with suspicious download arguments");
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
            var hasUseShellExecuteIndicator = hasUseShell || HasProcessStartInfoSetter(instructions, instructionIndex, "set_UseShellExecute");
            var hasCreateNoWindowIndicator = hasCreateNoWin || HasProcessStartInfoSetter(instructions, instructionIndex, "set_CreateNoWindow");
            var hasWindowStyleIndicator = hasWindowStyle || HasProcessStartInfoSetter(instructions, instructionIndex, "set_WindowStyle");
            var hasWorkingDirectoryIndicator = hasWorkingDir || HasProcessStartInfoSetter(instructions, instructionIndex, "set_WorkingDirectory");
            var hasRedirectStandardInputIndicator =
                HasProcessStartInfoSetter(instructions, instructionIndex, "set_RedirectStandardInput");
            var hasRedirectStandardOutputIndicator =
                HasProcessStartInfoSetter(instructions, instructionIndex, "set_RedirectStandardOutput");
            var hasRedirectStandardErrorIndicator =
                HasProcessStartInfoSetter(instructions, instructionIndex, "set_RedirectStandardError");

            var description = $"{Description} Target: {target}. Arguments: {arguments}";

            var targetLower = target.ToLowerInvariant().Trim('"');
            var argumentsLower = arguments.ToLowerInvariant();

            var (severity, riskReason) = DetermineSeverity(targetLower, argumentsLower, target, arguments,
                useShellExecute, createNoWindow, windowStyleHidden, workingDirectoryIsTemp,
                hasUseShellExecuteIndicator, hasCreateNoWindowIndicator, hasWindowStyleIndicator,
                hasWorkingDirectoryIndicator, hasRedirectStandardInputIndicator,
                hasRedirectStandardOutputIndicator, hasRedirectStandardErrorIndicator);

            _severity = severity ?? Severity.Medium;

            // Add evasion indicators to description
            var evasionIndicators = new List<string>();
            AddProcessStartInfoIndicators(evasionIndicators, useShellExecute, createNoWindow, windowStyleHidden,
                workingDirectoryIsTemp, hasUseShellExecuteIndicator, hasCreateNoWindowIndicator,
                hasWindowStyleIndicator, hasWorkingDirectoryIndicator);

            if (evasionIndicators.Count > 0)
            {
                description += " [Evasion: " + string.Join(", ", evasionIndicators) + "]";
            }

            if (!string.IsNullOrEmpty(riskReason))
            {
                description += $" [{riskReason}]";
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

            if (IsSafeBareExplorerLaunch(method, instructions, instructionIndex))
            {
                return true;
            }

            if (IsSafeShellFolderLaunch(method, instructions, instructionIndex))
            {
                return true;
            }

            if (IsCurrentProcessRestart(method, instructions, instructionIndex))
            {
                return true;
            }

            return false;
        }

        private static bool IsSafeBareExplorerLaunch(
            MethodReference processStartMethod,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            if (processStartMethod == null ||
                processStartMethod.Parameters.Count == 0 ||
                !InstructionValueResolver.TryResolveCallArgumentDisplay(null, processStartMethod, instructions,
                    processStartIndex, 0, out var target) ||
                !target.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return !HasPathManipulation(instructions, Math.Max(0, processStartIndex - 10), processStartIndex);
        }

        private static bool IsSafeShellFolderLaunch(
            MethodReference processStartMethod,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            if (processStartMethod == null ||
                processStartMethod.Parameters.Count != 1 ||
                processStartMethod.Parameters[0].ParameterType.FullName != "System.Diagnostics.ProcessStartInfo" ||
                !InstructionValueResolver.TryResolveCallArgumentIdentity(processStartMethod, instructions,
                    processStartIndex, 0, out var launchedStartInfoIdentity))
            {
                return false;
            }

            var checkedDirectoryTargets = new Dictionary<string, int>(StringComparer.Ordinal);
            string? fileNameTarget = null;
            bool useShell = false;
            bool setsArguments = false;
            int searchStart = Math.Max(0, processStartIndex - 40);
            for (int i = searchStart; i < processStartIndex; i++)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName == "System.IO.Directory" &&
                    (methodRef.Name == "Exists" || methodRef.Name == "CreateDirectory"))
                {
                    if (InstructionValueResolver.TryResolveCallArgumentDisplay(null, methodRef, instructions, i, 0,
                            out var directoryTarget))
                    {
                        bool validatesDirectory = methodRef.Name == "CreateDirectory"
                            ? HasStraightLineDominance(instructions, i, processStartIndex)
                            : IsTrueDirectoryExistsGuard(instructions, i, processStartIndex) ||
                              IsEnsureDirectoryGuard(instructions, i, processStartIndex, directoryTarget);
                        if (validatesDirectory)
                        {
                            checkedDirectoryTargets[directoryTarget] = i;
                        }
                    }

                    continue;
                }

                if (methodRef.DeclaringType?.FullName == "System.Diagnostics.ProcessStartInfo" &&
                    methodRef.Name == "set_FileName")
                {
                    if (HasMatchingReceiverIdentity(instructions, i, launchedStartInfoIdentity) &&
                        HasStraightLineDominance(instructions, i, processStartIndex) &&
                        InstructionValueResolver.TryResolveStackValueDisplay(null, instructions, i - 1,
                            out var resolvedFileName))
                    {
                        fileNameTarget = resolvedFileName;
                    }

                    continue;
                }

                if (methodRef.DeclaringType?.FullName == "System.Diagnostics.ProcessStartInfo" &&
                    methodRef.Name == "set_UseShellExecute")
                {
                    if (HasMatchingReceiverIdentity(instructions, i, launchedStartInfoIdentity) &&
                        HasStraightLineDominance(instructions, i, processStartIndex) &&
                        InstructionValueResolver.TryResolveStackValueDisplay(null, instructions, i - 1,
                            out var resolvedUseShell))
                    {
                        useShell = resolvedUseShell is "True" or "true" or "1";
                    }

                    continue;
                }

                if (methodRef.DeclaringType?.FullName == "System.Diagnostics.ProcessStartInfo" &&
                    methodRef.Name == "set_Arguments")
                {
                    if (HasMatchingReceiverIdentity(instructions, i, launchedStartInfoIdentity))
                    {
                        setsArguments = true;
                    }
                }
            }

            return useShell &&
                   !setsArguments &&
                   fileNameTarget != null &&
                   !IsUnsafeShellTarget(fileNameTarget) &&
                   checkedDirectoryTargets.TryGetValue(fileNameTarget, out int validationIndex) &&
                   !HasStoredArgumentBetween(fileNameTarget, instructions, validationIndex, processStartIndex);
        }

        private static bool HasMatchingReceiverIdentity(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int callIndex,
            string expectedIdentity)
        {
            return InstructionValueResolver.TryResolveCallReceiverIdentity(instructions, callIndex,
                       out var receiverIdentity) &&
                   receiverIdentity == expectedIdentity;
        }

        private static bool IsTrueDirectoryExistsGuard(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int existsCallIndex,
            int processStartIndex)
        {
            int branchIndex = existsCallIndex + 1;
            if (branchIndex >= instructions.Count ||
                instructions[branchIndex].Operand is not Instruction branchTarget)
            {
                return false;
            }

            int targetIndex = instructions.IndexOf(branchTarget);
            var branchOp = instructions[branchIndex].OpCode;
            if (branchOp == OpCodes.Brfalse || branchOp == OpCodes.Brfalse_S)
            {
                return targetIndex > processStartIndex &&
                       HasStraightLineDominance(instructions, branchIndex, processStartIndex);
            }

            if (instructions[branchIndex].OpCode != OpCodes.Brtrue &&
                instructions[branchIndex].OpCode != OpCodes.Brtrue_S)
            {
                return false;
            }

            if (targetIndex <= branchIndex || targetIndex > processStartIndex ||
                !HasTerminatingFallthrough(instructions, branchIndex + 1, targetIndex) ||
                !HasStraightLineDominance(instructions, targetIndex, processStartIndex))
            {
                return false;
            }

            return true;
        }

        private static bool HasTerminatingFallthrough(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int startIndex,
            int endIndex)
        {
            for (int i = startIndex; i < endIndex; i++)
            {
                var flowControl = instructions[i].OpCode.FlowControl;
                if (flowControl is FlowControl.Return or FlowControl.Throw)
                    return true;

                if (flowControl is FlowControl.Branch or FlowControl.Cond_Branch)
                    return false;
            }

            return false;
        }

        private static bool HasStoredArgumentBetween(
            string target,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int startIndex,
            int endIndex)
        {
            const string prefix = "<arg ";
            int markerEnd = target.IndexOf('>', prefix.Length);
            if (!target.StartsWith(prefix, StringComparison.Ordinal) ||
                markerEnd < 0 ||
                !int.TryParse(target.Substring(prefix.Length, markerEnd - prefix.Length), out int argumentIndex))
            {
                return false;
            }

            for (int i = startIndex + 1; i < endIndex; i++)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Starg && instruction.OpCode != OpCodes.Starg_S) ||
                    instruction.Operand is not ParameterDefinition parameter)
                {
                    continue;
                }

                int storedArgumentIndex = parameter.Index + (parameter.Method?.HasThis == true ? 1 : 0);
                if (storedArgumentIndex == argumentIndex)
                    return true;
            }

            return false;
        }

        private static bool HasStraightLineDominance(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int validationIndex,
            int processStartIndex)
        {
            for (int i = validationIndex + 1; i < processStartIndex; i++)
            {
                var flowControl = instructions[i].OpCode.FlowControl;
                if (flowControl is FlowControl.Branch or FlowControl.Cond_Branch or
                    FlowControl.Return or FlowControl.Throw)
                {
                    return false;
                }
            }

            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].Operand is Instruction target)
                {
                    int targetIndex = instructions.IndexOf(target);
                    if (targetIndex > validationIndex && targetIndex <= processStartIndex)
                        return false;
                }
                else if (instructions[i].Operand is Instruction[] targets)
                {
                    foreach (var switchTarget in targets)
                    {
                        int targetIndex = instructions.IndexOf(switchTarget);
                        if (targetIndex > validationIndex && targetIndex <= processStartIndex)
                            return false;
                    }
                }
            }

            return true;
        }

        private static bool IsEnsureDirectoryGuard(
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int existsCallIndex,
            int processStartIndex,
            string existsTarget)
        {
            int branchIndex = existsCallIndex + 1;
            if (branchIndex >= instructions.Count ||
                (instructions[branchIndex].OpCode != OpCodes.Brtrue &&
                 instructions[branchIndex].OpCode != OpCodes.Brtrue_S) ||
                instructions[branchIndex].Operand is not Instruction joinTarget)
            {
                return false;
            }

            int joinIndex = instructions.IndexOf(joinTarget);
            if (joinIndex <= branchIndex || joinIndex >= processStartIndex ||
                !HasStraightLineDominance(instructions, joinIndex, processStartIndex))
            {
                return false;
            }

            bool createsMatchingDirectory = false;
            for (int i = branchIndex + 1; i < joinIndex; i++)
            {
                var flowControl = instructions[i].OpCode.FlowControl;
                if (flowControl is FlowControl.Branch or FlowControl.Cond_Branch or
                    FlowControl.Return or FlowControl.Throw)
                {
                    return false;
                }

                if ((instructions[i].OpCode == OpCodes.Call || instructions[i].OpCode == OpCodes.Callvirt) &&
                    instructions[i].Operand is MethodReference methodRef &&
                    methodRef.DeclaringType?.FullName == "System.IO.Directory" &&
                    methodRef.Name == "CreateDirectory" &&
                    InstructionValueResolver.TryResolveCallArgumentDisplay(null, methodRef, instructions, i, 0,
                        out var createTarget) &&
                    createTarget == existsTarget &&
                    HasStraightLineDominance(instructions, branchIndex, i))
                {
                    createsMatchingDirectory = true;
                }
            }

            return createsMatchingDirectory;
        }

        private static bool IsUnsafeShellTarget(string target)
        {
            var normalized = target.Trim().Trim('"');
            if (normalized.Length == 0 ||
                normalized.IndexOf("<unknown", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("<dynamic", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("<field ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("<static-field ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("<local ", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.StartsWith(@"\\", StringComparison.Ordinal) ||
                normalized.Contains("://"))
            {
                return true;
            }

            int colonIndex = normalized.IndexOf(':');
            if (colonIndex >= 0 && !(colonIndex == 1 && char.IsLetter(normalized[0])))
            {
                return true;
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
            MethodReference processStartMethod,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex)
        {
            if (processStartMethod == null ||
                !TryResolveLaunchedTargetIdentity(processStartMethod, instructions, processStartIndex,
                    out var launchedTargetIdentity))
            {
                return false;
            }

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

                return launchedTargetIdentity.Equals($"call:{getFileNameIndex}", StringComparison.Ordinal);
            }

            return false;
        }

        private static bool TryResolveLaunchedTargetIdentity(
            MethodReference processStartMethod,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions,
            int processStartIndex,
            out string targetIdentity)
        {
            targetIdentity = string.Empty;

            if (processStartMethod.Parameters.Count > 0 &&
                processStartMethod.Parameters[0].ParameterType.FullName != "System.Diagnostics.ProcessStartInfo")
            {
                return InstructionValueResolver.TryResolveCallArgumentIdentity(processStartMethod, instructions,
                    processStartIndex, 0, out targetIdentity);
            }

            string startInfoIdentity;
            if (processStartMethod.Parameters.Count > 0)
            {
                if (!InstructionValueResolver.TryResolveCallArgumentIdentity(processStartMethod, instructions,
                        processStartIndex, 0, out startInfoIdentity))
                {
                    return false;
                }
            }
            else
            {
                if (!processStartMethod.HasThis ||
                    !InstructionValueResolver.TryResolveCallReceiverIdentity(instructions, processStartIndex,
                        out var launchedProcessIdentity))
                {
                    return false;
                }

                startInfoIdentity = string.Empty;
                for (int i = processStartIndex - 1; i >= Math.Max(0, processStartIndex - 80); i--)
                {
                    if (instructions[i].Operand is not MethodReference setter ||
                        setter.DeclaringType?.FullName != "System.Diagnostics.Process" ||
                        setter.Name != "set_StartInfo" ||
                        !InstructionValueResolver.TryResolveCallReceiverIdentity(instructions, i,
                            out var receiverIdentity) ||
                        !receiverIdentity.Equals(launchedProcessIdentity, StringComparison.Ordinal) ||
                        !InstructionValueResolver.TryResolveCallArgumentIdentity(setter, instructions, i, 0,
                            out startInfoIdentity))
                    {
                        continue;
                    }

                    break;
                }

                if (startInfoIdentity.Length == 0)
                    return false;
            }

            for (int i = processStartIndex - 1; i >= Math.Max(0, processStartIndex - 80); i--)
            {
                if (instructions[i].Operand is not MethodReference setter ||
                    setter.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    setter.Name != "set_FileName" ||
                    !InstructionValueResolver.TryResolveCallReceiverIdentity(instructions, i,
                        out var receiverIdentity) ||
                    !receiverIdentity.Equals(startInfoIdentity, StringComparison.Ordinal))
                {
                    continue;
                }

                return InstructionValueResolver.TryResolveCallArgumentIdentity(setter, instructions, i, 0,
                    out targetIdentity);
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

        private static bool HasProcessStartInfoSetter(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            string setterName)
        {
            int searchStart = Math.Max(0, processStartIndex - 400);

            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName == "System.Diagnostics.ProcessStartInfo" &&
                    methodRef.Name == setterName)
                {
                    return true;
                }
            }

            return false;
        }

        private static void AddProcessStartInfoIndicators(
            List<string> indicators,
            bool useShellExecute,
            bool createNoWindow,
            bool windowStyleHidden,
            bool workingDirectoryIsTemp,
            bool hasUseShellExecuteIndicator,
            bool hasCreateNoWindowIndicator,
            bool hasWindowStyleIndicator,
            bool hasWorkingDirectoryIndicator)
        {
            if (useShellExecute)
                indicators.Add("UseShellExecute=true");
            else if (hasUseShellExecuteIndicator)
                indicators.Add("UseShellExecute set");

            if (createNoWindow)
                indicators.Add("CreateNoWindow=true");
            else if (hasCreateNoWindowIndicator)
                indicators.Add("CreateNoWindow set");

            if (windowStyleHidden)
                indicators.Add("WindowStyle=Hidden");
            else if (hasWindowStyleIndicator)
                indicators.Add("WindowStyle set");

            if (workingDirectoryIsTemp)
                indicators.Add("WorkingDirectory=Temp");
            else if (hasWorkingDirectoryIndicator)
                indicators.Add("WorkingDirectory set");
        }
    }
}
