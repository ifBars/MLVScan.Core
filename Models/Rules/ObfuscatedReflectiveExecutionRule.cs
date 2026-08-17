using System.Globalization;
using System.Text;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects correlated obfuscation, decode, and staging behavior that culminates in reflective,
    /// assembly-loading, process-launch, or native execution sinks.
    /// </summary>
    public class ObfuscatedReflectiveExecutionRule : IScanRule
    {
        private const int MinimumDecodeScore = 25;
        private const int MinimumSinkScore = 35;
        private const int MinimumTotalScore = 70;
        private const int ReflectionOnlyDangerFloor = 10;
        private const int ReflectionOnlyDecodeFloor = 45;
        private const int MaximumDecodedStaticArrayStrings = 256;
        private const int MaximumDecodedStaticArrayBytes = 256 * 1024;
        private const int MaximumDecodedStaticArrayFieldBytes = 4096;

        /// <summary>
        /// Gets the description emitted when the rule identifies an obfuscated execution chain.
        /// </summary>
        public string Description =>
            "Detected correlated obfuscation/decode behavior reaching reflective or staged execution sinks.";

        /// <summary>
        /// Gets the severity assigned to obfuscated reflective execution chains.
        /// </summary>
        public Severity Severity => Severity.High;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "ObfuscatedReflectiveExecutionRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Returns false because this rule evaluates instruction-level evidence rather than method signatures.
        /// </summary>
        public bool IsSuspicious(MethodReference method)
        {
            return false;
        }

        /// <summary>
        /// Collects obfuscation evidence from the method body and emits a finding when the score is high enough.
        /// </summary>
        /// <param name="methodDef">The method being analyzed.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="methodSignals">Current method signal state.</param>
        /// <returns>A single high-confidence finding when the evidence passes the reporting threshold.</returns>
        public IEnumerable<ScanFinding> AnalyzeInstructions(
            MethodDefinition methodDef,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals methodSignals)
        {
            if (methodDef == null || instructions == null || instructions.Count == 0)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            ObfuscatedExecutionEvidence evidence = ObfuscatedExecutionHeuristics.CollectEvidence(instructions);
            if (!ShouldReport(evidence))
            {
                return Enumerable.Empty<ScanFinding>();
            }

            Severity severity = DetermineSeverity(evidence);
            if (severity < Severity.High)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            int anchorIndex = evidence.AnchorInstructionIndex;
            if (anchorIndex < 0 || anchorIndex >= instructions.Count)
            {
                anchorIndex = 0;
            }

            int offset = instructions[anchorIndex].Offset;
            string snippet = BuildSnippet(instructions, anchorIndex, 2);

            var finding = new ScanFinding(
                $"{methodDef.DeclaringType?.FullName}.{methodDef.Name}:{offset}",
                BuildDescription(evidence),
                severity,
                snippet) { RiskScore = evidence.TotalScore, BypassCompanionCheck = evidence.TotalScore >= 85 };

            return new[] { finding };
        }

        /// <summary>
        /// Correlates loader patterns that deliberately split decode, type resolution, object staging,
        /// and reflective invocation across helper types to avoid single-method detection.
        /// </summary>
        /// <param name="module">The module being scanned.</param>
        /// <param name="existingFindings">Findings emitted by earlier rule passes.</param>
        /// <returns>Additional findings for namespace-level obfuscated reflection staging clusters.</returns>
        public IEnumerable<ScanFinding> PostAnalysisRefine(
            ModuleDefinition module,
            IEnumerable<ScanFinding> existingFindings)
        {
            if (module == null)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            List<ScanFinding> priorFindings = existingFindings?.ToList() ?? new List<ScanFinding>();
            var findings = new List<ScanFinding>();
            (IReadOnlyList<string> moduleDecodedStrings, bool staticArrayCollectionTruncated) =
                CollectDecodedStaticArrayStringsWithStatus(module);
            var moduleDecodedMarkerCache = new Dictionary<string, bool>(StringComparer.Ordinal);

            if (staticArrayCollectionTruncated)
            {
                findings.Add(new ScanFinding(
                    module.Name,
                    "Static RVA string analysis reached its bounded work budget before every eligible field " +
                    "could be inspected. Full IL analysis was skipped for the remaining static data and manual " +
                    "review is required.",
                    Severity.Low)
                {
                    RuleId = "StaticRvaScanWarning",
                    RiskScore = 20,
                    BypassCompanionCheck = true
                });
            }

            foreach (var namespaceGroup in EnumerateTypes(module)
                         .Where(static type => !string.IsNullOrWhiteSpace(type.Namespace))
                         .GroupBy(static type => type.Namespace, StringComparer.Ordinal))
            {
                RemoteConfigTempCmdStagerEvidence remoteConfigEvidence =
                    CollectRemoteConfigTempCmdStagerEvidence(
                        namespaceGroup, moduleDecodedStrings, moduleDecodedMarkerCache);
                if (remoteConfigEvidence.ShouldReport)
                {
                    findings.Add(new ScanFinding(
                        namespaceGroup.Key,
                        "Detected cross-method hex remote config reflective temp command stager: " +
                        "hex-encoded remote command config URLs, reflected WebClient.DownloadString, " +
                        "temporary .cmd script staging, File.WriteAllText, reflected ProcessStartInfo cmd.exe launch, " +
                        "hidden window settings, and MethodInfo.Invoke are split across helper methods.",
                        Severity.Critical,
                        BuildRemoteConfigTempCmdSnippet(remoteConfigEvidence))
                    {
                        RuleId = RuleId,
                        RiskScore = 96,
                        BypassCompanionCheck = true
                    });
                }

                if (!HasDecodedExecutionFinding(namespaceGroup.Key, priorFindings))
                {
                    continue;
                }

                CrossMethodReflectionClusterEvidence evidence = CollectCrossMethodEvidence(namespaceGroup);
                if (!evidence.ShouldReport)
                {
                    continue;
                }

                findings.Add(new ScanFinding(
                    namespaceGroup.Key,
                    "Detected cross-method obfuscated reflection staging cluster: numeric string reconstruction, " +
                    "runtime assembly/type enumeration, Activator.CreateInstance object staging, reflected property " +
                    "assignment, and MethodInfo.Invoke are split across helper methods around a decoded execution payload.",
                    Severity.Critical,
                    BuildCrossMethodSnippet(evidence))
                {
                    RuleId = RuleId,
                    RiskScore = 92,
                    BypassCompanionCheck = true
                });
            }

            return findings;
        }

        private static bool ShouldReport(ObfuscatedExecutionEvidence evidence)
        {
            if (evidence.SinkScore < MinimumSinkScore || evidence.DecodeScore < MinimumDecodeScore)
            {
                return false;
            }

            if (!evidence.HasStrongDecodePrimitive)
            {
                return false;
            }

            if (evidence.TotalScore < MinimumTotalScore)
            {
                return false;
            }

            bool reflectionOnly = evidence.HasReflectionInvokeSink &&
                                  !evidence.HasProcessLikeSink &&
                                  !evidence.HasAssemblyLoadSink &&
                                  !evidence.HasNativeSink;

            if (reflectionOnly && evidence.DangerScore < ReflectionOnlyDangerFloor &&
                evidence.DecodeScore < ReflectionOnlyDecodeFloor)
            {
                return false;
            }

            if (reflectionOnly &&
                !evidence.HasEncodedLiteral &&
                !evidence.HasDangerousLiteral &&
                !evidence.HasNetworkCall &&
                !evidence.HasFileWriteCall &&
                !evidence.HasSensitivePathAccess)
            {
                return false;
            }

            return true;
        }

        private static CrossMethodReflectionClusterEvidence CollectCrossMethodEvidence(
            IEnumerable<TypeDefinition> namespaceTypes)
        {
            var evidence = new CrossMethodReflectionClusterEvidence();

            foreach (TypeDefinition type in namespaceTypes)
            {
                foreach (MethodDefinition method in EnumerateMethods(type))
                {
                    if (!method.HasBody || method.Body.Instructions.Count == 0)
                    {
                        continue;
                    }

                    ObfuscatedExecutionEvidence methodEvidence =
                        ObfuscatedExecutionHeuristics.CollectEvidence(method.Body.Instructions);
                    if (methodEvidence.HasStrongDecodePrimitive && methodEvidence.DecodeScore >= 18)
                    {
                        evidence.HasNumericStringReconstruction = true;
                        evidence.NumericDecodeLocation ??= $"{type.FullName}.{method.Name}";
                    }

                    bool hasAppDomainAssemblyEnumeration = false;
                    bool hasAssemblyGetTypes = false;
                    bool hasEnumerableTypeSearch = false;
                    bool hasTypeGetProperty = false;
                    bool hasPropertySetValue = false;
                    bool hasTypeGetMethod = false;
                    bool hasMethodInfoInvoke = false;

                    foreach (Instruction instruction in method.Body.Instructions)
                    {
                        if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                            instruction.Operand is not MethodReference calledMethod)
                        {
                            continue;
                        }

                        string typeName = calledMethod.DeclaringType?.FullName ?? string.Empty;
                        string methodName = calledMethod.Name ?? string.Empty;

                        if (typeName == "System.AppDomain" &&
                            (methodName == "get_CurrentDomain" || methodName == "GetAssemblies"))
                        {
                            hasAppDomainAssemblyEnumeration = true;
                        }

                        if (typeName == "System.Reflection.Assembly" && methodName == "GetTypes")
                        {
                            hasAssemblyGetTypes = true;
                        }

                        if (typeName == "System.Linq.Enumerable" &&
                            (methodName == "SelectMany" || methodName == "FirstOrDefault"))
                        {
                            hasEnumerableTypeSearch = true;
                        }

                        if (typeName == "System.Activator" && methodName == "CreateInstance")
                        {
                            evidence.HasActivatorStaging = true;
                            evidence.ActivatorLocation ??= $"{type.FullName}.{method.Name}";
                        }

                        if (typeName == "System.Type" && methodName == "GetProperty")
                        {
                            hasTypeGetProperty = true;
                        }

                        if (typeName == "System.Reflection.PropertyInfo" && methodName == "SetValue")
                        {
                            hasPropertySetValue = true;
                        }

                        if (typeName == "System.Type" && methodName == "GetMethod")
                        {
                            hasTypeGetMethod = true;
                        }

                        if (ObfuscatedSinkMatcher.IsReflectionInvokeSink(typeName, methodName))
                        {
                            hasMethodInfoInvoke = true;
                        }
                    }

                    if (hasAppDomainAssemblyEnumeration && (hasAssemblyGetTypes || hasEnumerableTypeSearch))
                    {
                        evidence.HasRuntimeTypeEnumeration = true;
                        evidence.TypeEnumerationLocation ??= $"{type.FullName}.{method.Name}";
                    }

                    if (hasTypeGetProperty && hasPropertySetValue)
                    {
                        evidence.HasReflectedPropertyAssignment = true;
                        evidence.PropertyAssignmentLocation ??= $"{type.FullName}.{method.Name}";
                    }

                    if (hasTypeGetMethod && hasMethodInfoInvoke)
                    {
                        evidence.HasReflectionInvoke = true;
                        evidence.ReflectionInvokeLocation ??= $"{type.FullName}.{method.Name}";
                    }
                }
            }

            return evidence;
        }

        private static RemoteConfigTempCmdStagerEvidence CollectRemoteConfigTempCmdStagerEvidence(
            IEnumerable<TypeDefinition> namespaceTypes,
            IReadOnlyList<string> moduleDecodedStrings,
            IDictionary<string, bool> moduleDecodedMarkerCache)
        {
            var evidence = new RemoteConfigTempCmdStagerEvidence();
            // Module-wide decoded strings are read-only evidence. Keep namespace-local strings separate so
            // every namespace does not copy and rehash the same attacker-controlled module collection.
            var recoveredStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (TypeDefinition type in namespaceTypes)
            {
                foreach (MethodDefinition method in EnumerateMethods(type))
                {
                    if (!method.HasBody || method.Body.Instructions.Count == 0)
                    {
                        continue;
                    }

                    string methodLocation = $"{type.FullName}.{method.Name}";
                    var methodStrings = new List<string>();
                    bool methodHasEncodingGetString = false;
                    bool methodHasConvertToByteBase16 = false;
                    bool methodHasTypeGetType = false;
                    bool methodHasTypeGetMethod = false;
                    bool methodHasTypeGetProperty = false;
                    bool methodHasPropertySetValue = false;
                    bool methodHasMethodInfoInvoke = false;
                    bool methodHasActivatorCreateInstance = false;

                    var instructions = method.Body.Instructions;
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        Instruction instruction = instructions[i];

                        if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string literal)
                        {
                            methodStrings.Add(literal);
                            recoveredStrings.Add(literal);

                            if (TryDecodeHexString(literal, out string decodedHex))
                            {
                                methodStrings.Add(decodedHex);
                                recoveredStrings.Add(decodedHex);
                            }
                        }

                        if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                            instruction.Operand is not MethodReference calledMethod)
                        {
                            continue;
                        }

                        string typeName = calledMethod.DeclaringType?.FullName ?? string.Empty;
                        string methodName = calledMethod.Name ?? string.Empty;

                        if (typeName == "System.Text.Encoding" && methodName == "GetString")
                        {
                            methodHasEncodingGetString = true;
                            evidence.ByteStringDecodeLocation ??= methodLocation;
                        }

                        if (typeName == "System.Convert" && methodName == "ToByte" &&
                            HasBase16Argument(instructions, i))
                        {
                            methodHasConvertToByteBase16 = true;
                            evidence.HexDecodeLocation ??= methodLocation;
                        }

                        if (typeName == "System.Type" && methodName == "GetType")
                        {
                            methodHasTypeGetType = true;
                        }

                        if (typeName == "System.Type" && methodName == "GetMethod")
                        {
                            methodHasTypeGetMethod = true;
                        }

                        if (typeName == "System.Type" && methodName == "GetProperty")
                        {
                            methodHasTypeGetProperty = true;
                        }

                        if (typeName == "System.Reflection.PropertyInfo" && methodName == "SetValue")
                        {
                            methodHasPropertySetValue = true;
                        }

                        if (ObfuscatedSinkMatcher.IsReflectionInvokeSink(typeName, methodName))
                        {
                            methodHasMethodInfoInvoke = true;
                        }

                        if (typeName == "System.Activator" && methodName == "CreateInstance")
                        {
                            methodHasActivatorCreateInstance = true;
                        }
                    }

                    if (methodStrings.Any(IsRemoteConfigUrl))
                    {
                        evidence.HasRemoteConfigUrl = true;
                        evidence.RemoteConfigLocation ??= methodLocation;
                    }

                    if (methodHasEncodingGetString || methodHasConvertToByteBase16)
                    {
                        evidence.HasStringReconstruction = true;
                    }

                    if (methodHasConvertToByteBase16)
                    {
                        evidence.HasHexDecode = true;
                    }

                    if (methodHasTypeGetType)
                    {
                        evidence.HasReflectedTypeResolution = true;
                    }

                    if (methodHasTypeGetMethod)
                    {
                        evidence.HasReflectedMethodLookup = true;
                    }

                    if (methodHasTypeGetProperty && methodHasPropertySetValue)
                    {
                        evidence.HasReflectedPropertyAssignment = true;
                        evidence.PropertyAssignmentLocation ??= methodLocation;
                    }

                    if (methodHasMethodInfoInvoke)
                    {
                        evidence.HasReflectionInvoke = true;
                        evidence.ReflectionInvokeLocation ??= methodLocation;
                    }

                    if (methodHasActivatorCreateInstance)
                    {
                        evidence.HasActivatorStaging = true;
                    }
                }
            }

            if (ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "System.Net.WebClient", "WebClient") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "DownloadString", "DownloadFile"))
            {
                evidence.HasReflectedNetworkDownload = true;
            }

            if (ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "System.IO.Path", "Path") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "GetTempFileName") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, ".cmd", ".bat") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "System.IO.File", "File") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "WriteAllText", "WriteAllBytes"))
            {
                evidence.HasTempScriptStaging = true;
            }

            if (ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "System.Diagnostics.ProcessStartInfo", "ProcessStartInfo") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "System.Diagnostics.Process", "Process") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "cmd.exe") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "/c") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "WindowStyle") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "Hidden") &&
                ContainsRecoveredMarker(recoveredStrings, moduleDecodedStrings, moduleDecodedMarkerCache, "UseShellExecute", "CreateNoWindow"))
            {
                evidence.HasHiddenCmdProcessLaunch = true;
            }

            return evidence;
        }

        private static bool ContainsRecoveredMarker(
            IEnumerable<string> namespaceStrings,
            IReadOnlyList<string> moduleDecodedStrings,
            IDictionary<string, bool> moduleDecodedMarkerCache,
            params string[] markers)
        {
            if (namespaceStrings.Any(value => ContainsMarker(value, markers)))
                return true;

            string cacheKey = string.Join('\0', markers);
            if (!moduleDecodedMarkerCache.TryGetValue(cacheKey, out bool moduleContainsMarker))
            {
                moduleContainsMarker = moduleDecodedStrings.Any(value => ContainsMarker(value, markers));
                moduleDecodedMarkerCache[cacheKey] = moduleContainsMarker;
            }

            return moduleContainsMarker;
        }

        private static IReadOnlyList<string> CollectDecodedStaticArrayStrings(ModuleDefinition module)
        {
            return CollectDecodedStaticArrayStringsWithStatus(module).Strings;
        }

        private static (IReadOnlyList<string> Strings, bool WasTruncated)
            CollectDecodedStaticArrayStringsWithStatus(ModuleDefinition module)
        {
            var strings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int inspectedBytes = 0;

            foreach (TypeDefinition type in EnumerateTypes(module))
            {
                foreach (FieldDefinition field in type.Fields)
                {
                    if (!field.HasFieldRVA || field.InitialValue == null || field.InitialValue.Length < 3)
                    {
                        continue;
                    }

                    // Oversized initializers cannot be decoded by this heuristic. Ignore them without
                    // allowing attacker-controlled padding to terminate collection before later markers.
                    if (field.InitialValue.Length > MaximumDecodedStaticArrayFieldBytes)
                    {
                        continue;
                    }

                    if (strings.Count >= MaximumDecodedStaticArrayStrings ||
                        field.InitialValue.Length > MaximumDecodedStaticArrayBytes - inspectedBytes)
                    {
                        return (strings.ToList(), true);
                    }

                    inspectedBytes += field.InitialValue.Length;
                    if (TryDecodePrintableBytes(field.InitialValue, out string decoded))
                    {
                        strings.Add(decoded);
                    }
                }
            }

            return (strings.ToList(), false);
        }

        private static bool TryDecodePrintableBytes(byte[] bytes, out string decoded)
        {
            decoded = string.Empty;
            if (bytes.Length < 3 || bytes.Length > MaximumDecodedStaticArrayFieldBytes)
            {
                return false;
            }

            string candidate = Encoding.ASCII.GetString(bytes).TrimEnd('\0');
            if (candidate.Length < 3)
            {
                return false;
            }

            int printable = candidate.Count(static c => c is >= ' ' and <= '~' || c == '\t' || c == '\r' || c == '\n');
            if ((double)printable / candidate.Length < 0.85)
            {
                return false;
            }

            decoded = candidate;
            return true;
        }

        private static bool TryDecodeHexString(string literal, out string decoded)
        {
            decoded = string.Empty;
            if (!ObfuscatedDecodeMatcher.IsHexLikeLiteral(literal))
            {
                return false;
            }

            string normalized = literal
                .Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace(":", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal);

            try
            {
                var bytes = new byte[normalized.Length / 2];
                for (int i = 0; i < normalized.Length; i += 2)
                {
                    bytes[i / 2] = byte.Parse(normalized.Substring(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                }

                return TryDecodePrintableBytes(bytes, out decoded);
            }
            catch
            {
                return false;
            }
        }

        private static bool HasBase16Argument(Mono.Collections.Generic.Collection<Instruction> instructions, int callIndex)
        {
            int start = Math.Max(0, callIndex - 6);
            for (int i = callIndex - 1; i >= start; i--)
            {
                if (instructions[i].TryResolveInt32Literal(out int value) && value == 16)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsRemoteConfigUrl(string value)
        {
            return (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) &&
                   (value.Contains("paste", StringComparison.OrdinalIgnoreCase) ||
                    value.Contains("gist", StringComparison.OrdinalIgnoreCase) ||
                    value.Contains("raw", StringComparison.OrdinalIgnoreCase) ||
                    value.Contains("file.io", StringComparison.OrdinalIgnoreCase) ||
                    value.Contains("transfer", StringComparison.OrdinalIgnoreCase) ||
                    value.Contains("config", StringComparison.OrdinalIgnoreCase));
        }

        private static bool ContainsMarker(string value, params string[] markers)
        {
            return markers.Any(marker => value.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static bool HasDecodedExecutionFinding(string namespaceName, IReadOnlyCollection<ScanFinding> findings)
        {
            return findings.Any(finding =>
                finding.Severity >= Severity.High &&
                string.Equals(finding.RuleId, "EncodedStringLiteralRule", StringComparison.Ordinal) &&
                finding.Location.StartsWith(namespaceName + ".", StringComparison.Ordinal) &&
                ContainsExecutionMarker(finding.Description + " " + finding.CodeSnippet));
        }

        private static bool ContainsExecutionMarker(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            string[] markers =
            {
                "ProcessStartInfo",
                "Process.Start",
                "powershell",
                "cmd.exe",
                "MethodInfo.Invoke",
                "CreateNoWindow",
                "WindowStyle"
            };

            return markers.Any(marker => text.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static IEnumerable<TypeDefinition> EnumerateTypes(ModuleDefinition module)
        {
            foreach (TypeDefinition type in module.Types)
            {
                foreach (TypeDefinition nested in EnumerateTypes(type))
                {
                    yield return nested;
                }
            }
        }

        private static IEnumerable<TypeDefinition> EnumerateTypes(TypeDefinition type)
        {
            yield return type;

            foreach (TypeDefinition nestedType in type.NestedTypes)
            {
                foreach (TypeDefinition nested in EnumerateTypes(nestedType))
                {
                    yield return nested;
                }
            }
        }

        private static IEnumerable<MethodDefinition> EnumerateMethods(TypeDefinition type)
        {
            foreach (MethodDefinition method in type.Methods)
            {
                yield return method;
            }
        }

        private static string BuildCrossMethodSnippet(CrossMethodReflectionClusterEvidence evidence)
        {
            return string.Join(
                Environment.NewLine,
                new[]
                {
                    $"numeric decode: {evidence.NumericDecodeLocation}",
                    $"type enumeration: {evidence.TypeEnumerationLocation}",
                    $"activator staging: {evidence.ActivatorLocation}",
                    $"property assignment: {evidence.PropertyAssignmentLocation}",
                    $"reflection invoke: {evidence.ReflectionInvokeLocation}"
                });
        }

        private static string BuildRemoteConfigTempCmdSnippet(RemoteConfigTempCmdStagerEvidence evidence)
        {
            return string.Join(
                Environment.NewLine,
                new[]
                {
                    $"remote config: {evidence.RemoteConfigLocation}",
                    $"hex decode: {evidence.HexDecodeLocation}",
                    $"byte string decode: {evidence.ByteStringDecodeLocation}",
                    $"property assignment: {evidence.PropertyAssignmentLocation}",
                    $"reflection invoke: {evidence.ReflectionInvokeLocation}",
                    "staging: WebClient.DownloadString -> GetTempFileName + .cmd -> File.WriteAllText",
                    "execution: ProcessStartInfo FileName=cmd.exe Arguments=/c WindowStyle=Hidden UseShellExecute=True"
                });
        }

        private static Severity DetermineSeverity(ObfuscatedExecutionEvidence evidence)
        {
            bool strongExecutionSink =
                evidence.HasProcessLikeSink || evidence.HasAssemblyLoadSink || evidence.HasNativeSink;
            bool hasDangerPivot = evidence.HasDangerousLiteral ||
                                  evidence.DangerScore >= 15 ||
                                  (evidence.HasNetworkCall && evidence.HasFileWriteCall);

            if (evidence.TotalScore >= 90 && strongExecutionSink && hasDangerPivot)
            {
                return Severity.Critical;
            }

            return Severity.High;
        }

        private static string BuildDescription(ObfuscatedExecutionEvidence evidence)
        {
            string decode = BuildReasonSegment(evidence.DecodeReasons, "decode evidence");
            string sink = BuildReasonSegment(evidence.SinkReasons, "sink evidence");
            string danger = BuildReasonSegment(evidence.DangerReasons, "context evidence");

            return
                $"Detected correlated obfuscation/decode behavior that reaches reflective or staged execution (score {evidence.TotalScore}): {decode}; {sink}; {danger}.";
        }

        private static string BuildReasonSegment(IReadOnlyList<string> reasons, string fallback)
        {
            if (reasons.Count == 0)
            {
                return fallback;
            }

            return string.Join(", ", reasons.Take(3));
        }

        private static string BuildSnippet(Mono.Collections.Generic.Collection<Instruction> instructions,
            int centerIndex, int context)
        {
            var snippetBuilder = new StringBuilder();
            int start = Math.Max(0, centerIndex - context);
            int end = Math.Min(instructions.Count - 1, centerIndex + context);

            for (int i = start; i <= end; i++)
            {
                snippetBuilder.Append(i == centerIndex ? ">>> " : "    ");
                snippetBuilder.AppendLine(instructions[i].ToString());
            }

            return snippetBuilder.ToString().TrimEnd();
        }

        private sealed class CrossMethodReflectionClusterEvidence
        {
            public bool HasNumericStringReconstruction { get; set; }
            public bool HasRuntimeTypeEnumeration { get; set; }
            public bool HasActivatorStaging { get; set; }
            public bool HasReflectedPropertyAssignment { get; set; }
            public bool HasReflectionInvoke { get; set; }

            public string? NumericDecodeLocation { get; set; }
            public string? TypeEnumerationLocation { get; set; }
            public string? ActivatorLocation { get; set; }
            public string? PropertyAssignmentLocation { get; set; }
            public string? ReflectionInvokeLocation { get; set; }

            public bool ShouldReport =>
                HasNumericStringReconstruction &&
                HasRuntimeTypeEnumeration &&
                HasActivatorStaging &&
                HasReflectedPropertyAssignment &&
                HasReflectionInvoke;
        }

        private sealed class RemoteConfigTempCmdStagerEvidence
        {
            public bool HasRemoteConfigUrl { get; set; }
            public bool HasHexDecode { get; set; }
            public bool HasStringReconstruction { get; set; }
            public bool HasReflectedTypeResolution { get; set; }
            public bool HasReflectedMethodLookup { get; set; }
            public bool HasReflectedPropertyAssignment { get; set; }
            public bool HasReflectionInvoke { get; set; }
            public bool HasActivatorStaging { get; set; }
            public bool HasReflectedNetworkDownload { get; set; }
            public bool HasTempScriptStaging { get; set; }
            public bool HasHiddenCmdProcessLaunch { get; set; }

            public string? RemoteConfigLocation { get; set; }
            public string? HexDecodeLocation { get; set; }
            public string? ByteStringDecodeLocation { get; set; }
            public string? PropertyAssignmentLocation { get; set; }
            public string? ReflectionInvokeLocation { get; set; }

            public bool ShouldReport =>
                HasRemoteConfigUrl &&
                HasHexDecode &&
                HasStringReconstruction &&
                HasReflectedTypeResolution &&
                HasReflectedMethodLookup &&
                HasReflectedPropertyAssignment &&
                HasReflectionInvoke &&
                HasActivatorStaging &&
                HasReflectedNetworkDownload &&
                HasTempScriptStaging &&
                HasHiddenCmdProcessLaunch;
        }
    }
}
