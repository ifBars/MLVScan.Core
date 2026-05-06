using System.Text;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
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

            foreach (var namespaceGroup in EnumerateTypes(module)
                         .Where(static type => !string.IsNullOrWhiteSpace(type.Namespace))
                         .GroupBy(static type => type.Namespace, StringComparer.Ordinal))
            {
                if (!HasCriticalDecodedExecutionFinding(namespaceGroup.Key, priorFindings))
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

        private static bool HasCriticalDecodedExecutionFinding(string namespaceName, IReadOnlyCollection<ScanFinding> findings)
        {
            return findings.Any(finding =>
                finding.Severity >= Severity.Critical &&
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
    }
}
