using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Diagnostics;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.ComponentModel;
using System.Reflection;

namespace MLVScan.Services
{
    /// <summary>
    /// Analyzes method bodies for suspicious instruction-level patterns and contextual rule matches.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class InstructionAnalyzer
    {
        private static readonly HashSet<string> ReflectionCompanionRuleIds = new(StringComparer.Ordinal)
        {
            "ProcessStartRule",
            "Shell32Rule",
            "COMReflectionAttackRule",
            "AssemblyDynamicLoadRule",
            "PersistenceRule",
            "RegistryRule",
            "DataExfiltrationRule",
            "DataInfiltrationRule",
            "Base64Rule",
            "HexStringRule",
            "EncodedStringLiteralRule",
            "EncodedStringPipelineRule",
            "EncodedBlobSplittingRule",
            "ByteArrayManipulationRule"
        };

        private readonly IReadOnlyList<IScanRule> _rules;
        private readonly IReadOnlyList<IScanRule> _contextualPatternRules;
        private readonly SignalTracker _signalTracker;
        private readonly ReflectionDetector _reflectionDetector;
        private readonly StringPatternDetector _stringPatternDetector;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly ScanConfig _config;
        private readonly CallGraphBuilder? _callGraphBuilder;
        private readonly IScanRule? _reflectionRule;
        private readonly ScanTelemetryHub _telemetry;

        /// <summary>
        /// Initializes a new instance of the <see cref="InstructionAnalyzer"/> class.
        /// </summary>
        /// <param name="rules">The rules that participate in instruction analysis.</param>
        /// <param name="signalTracker">Tracks method and type-level signals across analysis passes.</param>
        /// <param name="reflectionDetector">Evaluates reflection-based bypass patterns.</param>
        /// <param name="stringPatternDetector">Detects suspicious string-based context around calls.</param>
        /// <param name="snippetBuilder">Builds snippets for emitted findings.</param>
        /// <param name="config">Controls instruction-analysis behavior.</param>
        /// <param name="callGraphBuilder">Optional call-graph collector used for consolidated findings.</param>
        public InstructionAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker,
            ReflectionDetector reflectionDetector,
            StringPatternDetector stringPatternDetector, CodeSnippetBuilder snippetBuilder, ScanConfig config,
            CallGraphBuilder? callGraphBuilder = null)
            : this(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, config,
                new ScanTelemetryHub(), callGraphBuilder)
        {
        }

        internal InstructionAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker,
            ReflectionDetector reflectionDetector,
            StringPatternDetector stringPatternDetector, CodeSnippetBuilder snippetBuilder, ScanConfig config,
            ScanTelemetryHub telemetry, CallGraphBuilder? callGraphBuilder = null)
        {
            if (rules == null)
                throw new ArgumentNullException(nameof(rules));

            _rules = rules.ToArray();
            _contextualPatternRules = _rules
                .Where(static rule => OverridesRuleMethod(rule, nameof(IScanRule.AnalyzeContextualPattern),
                    typeof(MethodReference),
                    typeof(Mono.Collections.Generic.Collection<Instruction>),
                    typeof(int),
                    typeof(MethodSignals)))
                .ToArray();
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _reflectionDetector = reflectionDetector ?? throw new ArgumentNullException(nameof(reflectionDetector));
            _stringPatternDetector =
                stringPatternDetector ?? throw new ArgumentNullException(nameof(stringPatternDetector));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _config = config ?? new ScanConfig();
            _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
            _callGraphBuilder = callGraphBuilder;
            _reflectionRule = _rules.FirstOrDefault(static rule => rule is ReflectionRule);
        }

        /// <summary>
        /// Represents the findings gathered from a single instruction-analysis pass.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public class InstructionAnalysisResult
        {
            /// <summary>
            /// Gets or sets the findings emitted during instruction analysis.
            /// </summary>
            public List<ScanFinding> Findings { get; set; } = new List<ScanFinding>();

            /// <summary>
            /// Gets or sets reflection findings that must be revisited after type-level signals are collected.
            /// </summary>
            public List<(MethodDefinition method, Instruction instruction, int index,
                    Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals? methodSignals)>
                PendingReflectionFindings { get; set; } =
                new List<(MethodDefinition, Instruction, int, Mono.Collections.Generic.Collection<Instruction>,
                    MethodSignals?)>();
        }

        /// <summary>
        /// Analyzes a method body for contextual rule matches, direct suspicious calls, and reflection bypasses.
        /// </summary>
        /// <param name="method">The method being analyzed.</param>
        /// <param name="instructions">The method instructions.</param>
        /// <param name="methodSignals">Optional signal state collected for the current method.</param>
        /// <param name="typeFullName">The declaring type's full name for type-level signal correlation.</param>
        /// <returns>The findings and deferred reflection work collected for the method.</returns>
        public InstructionAnalysisResult AnalyzeInstructions(MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals? methodSignals, string typeFullName)
        {
            var result = new InstructionAnalysisResult();
            var effectiveMethodSignals = methodSignals ?? _signalTracker.CreateMethodSignals() ?? new MethodSignals();
            var analysisStart = _telemetry.StartTimestamp();
            _telemetry.IncrementCounter("InstructionAnalyzer.MethodsAnalyzed");
            _telemetry.IncrementCounter("InstructionAnalyzer.InstructionsVisited", instructions.Count);

            // Build set of instruction offsets inside exception handlers
            // These are analyzed by ExceptionHandlerAnalyzer with proper context, skip here to prevent duplicates
            var exceptionOffsetStart = _telemetry.StartTimestamp();
            var exceptionHandlerOffsets = BuildExceptionHandlerOffsets(method, instructions);
            _telemetry.AddPhaseElapsed("InstructionAnalyzer.BuildExceptionHandlerOffsets", exceptionOffsetStart);

            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                try
                {
                    // Check for direct method calls
                    if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                        instruction.Operand is MethodReference calledMethod)
                    {
                        _telemetry.IncrementCounter("InstructionAnalyzer.CallInstructions");

                        // Track signals for multi-pattern detection
                        if (methodSignals != null)
                        {
                            var signalUpdateStart = _telemetry.StartTimestamp();
                            _signalTracker.UpdateMethodSignals(methodSignals, calledMethod, method.DeclaringType);
                            _telemetry.AddPhaseElapsed("InstructionAnalyzer.UpdateMethodSignals",
                                signalUpdateStart);

                            // Check for Environment.GetFolderPath with sensitive folder values (for signal tracking)
                            if (calledMethod.DeclaringType?.FullName == "System.Environment" &&
                                calledMethod.Name == "GetFolderPath")
                            {
                                var folderValue = InstructionHelper.ExtractFolderPathArgument(instructions, i);
                                if (folderValue.HasValue && PersistenceRule.IsSensitiveFolder(folderValue.Value))
                                {
                                    _signalTracker.MarkSensitiveFolder(methodSignals, method.DeclaringType);
                                }
                            }
                        }

                        // Check if this call is to a suspicious method that's tracked by CallGraphBuilder
                        bool isCallToTrackedSuspiciousMethod = _callGraphBuilder != null &&
                                                               _callGraphBuilder.IsSuspiciousMethod(calledMethod);

                        if (isCallToTrackedSuspiciousMethod)
                        {
                            _telemetry.IncrementCounter("InstructionAnalyzer.CallGraphTrackedCalls");
                            // Register this call site with the call graph builder instead of creating a finding
                            var snippet = _snippetBuilder.BuildSnippet(instructions, i, 8);
                            var invocationContext =
                                DllImportInvocationContextExtractor.TryBuildContext(method, calledMethod, instructions,
                                    i);
                            _callGraphBuilder!.RegisterCallSite(method, calledMethod, instruction.Offset, snippet,
                                invocationContext);

                            // Mark rule as triggered for signal tracking
                            if (methodSignals != null)
                            {
                                var rule = FindFirstSuspiciousRule(calledMethod);
                                if (rule != null)
                                {
                                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                                }
                            }

                            // Skip normal finding creation for this call - it will be consolidated later
                            continue;
                        }

                        // Skip AnalyzeContextualPattern for instructions inside exception handlers
                        // Those are already analyzed by ExceptionHandlerAnalyzer with proper context
                        if (!exceptionHandlerOffsets.Contains(instruction.Offset))
                        {
                            foreach (var rule in _contextualPatternRules)
                            {
                                _telemetry.IncrementCounter("InstructionAnalyzer.ContextualRuleInvocations");
                                var contextualRuleStart = _telemetry.StartTimestamp();
                                var ruleFindings =
                                    rule.AnalyzeContextualPattern(calledMethod, instructions, i,
                                        effectiveMethodSignals);
                                _telemetry.AddPhaseElapsed("InstructionAnalyzer.ContextualRuleDispatch",
                                    contextualRuleStart);
                                foreach (var finding in ruleFindings)
                                {
                                    // If rule requires companion finding, check if other rules have been triggered
                                    // Exception: Low severity findings are always allowed (e.g., legitimate update checkers)
                                    // Exception: Findings with BypassCompanionCheck are always allowed (high-confidence scored findings)
                                    if (rule.RequiresCompanionFinding && finding.Severity != Severity.Low &&
                                        !finding.BypassCompanionCheck)
                                    {
                                        bool hasOtherTriggeredRules = methodSignals != null &&
                                                                      methodSignals.HasTriggeredRuleOtherThan(
                                                                          rule.RuleId);

                                        // Also check type-level triggered rules
                                        bool hasTypeLevelTriggeredRules = false;
                                        if (!string.IsNullOrEmpty(typeFullName))
                                        {
                                            var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
                                            if (typeSignal != null)
                                            {
                                                hasTypeLevelTriggeredRules =
                                                    typeSignal.HasTriggeredRuleOtherThan(rule.RuleId);
                                            }
                                        }

                                        // Only add finding if other rules have been triggered
                                        if (!hasOtherTriggeredRules && !hasTypeLevelTriggeredRules)
                                            continue;
                                    }

                                    // Enrich finding with rule metadata
                                    finding.WithRuleMetadata(rule);
                                    result.Findings.Add(finding);
                                    _telemetry.IncrementCounter("InstructionAnalyzer.ContextualFindings");
                                    if (methodSignals != null &&
                                        !(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                                    {
                                        _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType,
                                            rule.RuleId);
                                    }
                                }
                            }
                        } // end exception handler skip
                        else
                        {
                            _telemetry.IncrementCounter("InstructionAnalyzer.ExceptionHandlerSkippedCalls");
                        }

                        // For reflection invocations, only flag if combined with other malicious patterns
                        var reflectionHandlingStart = _telemetry.StartTimestamp();
                        bool isReflectionInvoke = _reflectionDetector.IsReflectionInvokeMethod(calledMethod);
                        _telemetry.AddPhaseElapsed("InstructionAnalyzer.ReflectionInvokeCheck",
                            reflectionHandlingStart);
                        if (isReflectionInvoke)
                        {
                            _telemetry.IncrementCounter("InstructionAnalyzer.ReflectionInvokes");
                            var reflectionRule = _reflectionRule;
                            if (reflectionRule != null)
                            {
                                // Check if strong companion rules have been triggered (not just any rule).
                                bool hasOtherTriggeredRules =
                                    HasStrongReflectionCompanion(methodSignals, reflectionRule.RuleId);

                                // Also check type-level triggered rules
                                bool hasTypeLevelTriggeredRules = false;
                                if (!string.IsNullOrEmpty(typeFullName))
                                {
                                    var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
                                    if (typeSignal != null)
                                    {
                                        hasTypeLevelTriggeredRules =
                                            HasStrongReflectionCompanion(typeSignal, reflectionRule.RuleId);
                                    }
                                }

                                // If no other rules have been triggered, queue for later processing
                                if (!hasOtherTriggeredRules && !hasTypeLevelTriggeredRules)
                                {
                                    // Queue for later processing after all methods in type are scanned
                                    if (_config.EnableMultiSignalDetection && method.DeclaringType != null)
                                    {
                                        result.PendingReflectionFindings.Add((method, instruction, i, instructions,
                                            methodSignals));
                                        _telemetry.IncrementCounter("InstructionAnalyzer.PendingReflectionQueued");
                                    }
                                }
                                else
                                {
                                    // Reflection combined with other triggered rules is suspicious
                                    var snippet = _snippetBuilder.BuildSnippet(instructions, i, 2);

                                    var finding = new ScanFinding(
                                        $"{method.DeclaringType?.FullName}.{method.Name}:{instruction.Offset}",
                                        reflectionRule.Description + " (combined with other suspicious patterns)",
                                        reflectionRule.Severity,
                                        snippet).WithRuleMetadata(reflectionRule);
                                    result.Findings.Add(finding);
                                    _telemetry.IncrementCounter("InstructionAnalyzer.ReflectionFindings");
                                    if (methodSignals != null && !(reflectionRule.RequiresCompanionFinding &&
                                                                   finding.Severity == Severity.Low))
                                    {
                                        _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType,
                                            reflectionRule.RuleId);
                                    }
                                }
                            }
                        }

                        // Check for suspicious patterns using IsSuspicious (skip for exception handlers)
                        // Also skip if CallGraphBuilder is tracking this method (will be consolidated)
                        // Note: isCallToTrackedSuspiciousMethod is checked at the top and continues early,
                        // but we also need to skip if the method is tracked (for methods matched by rules)
                        if (!exceptionHandlerOffsets.Contains(instruction.Offset) &&
                            !isCallToTrackedSuspiciousMethod &&
                            !isReflectionInvoke)
                        {
                            var suspiciousRuleStart = _telemetry.StartTimestamp();
                            var rule = FindFirstSuspiciousRule(calledMethod);
                            _telemetry.AddPhaseElapsed("InstructionAnalyzer.FindFirstSuspiciousRule",
                                suspiciousRuleStart);
                            if (rule != null)
                            {
                                _telemetry.IncrementCounter("InstructionAnalyzer.DirectSuspiciousMatches");
                                // Get type-level signals for cross-method detection (e.g., file writes in other methods)
                                MethodSignals? typeSignals = null;
                                if (!string.IsNullOrEmpty(typeFullName))
                                {
                                    typeSignals = _signalTracker.GetTypeSignals(typeFullName);
                                }

                                // Check if rule wants to suppress this finding based on contextual analysis
                                var suppressFindingStart = _telemetry.StartTimestamp();
                                if (rule.ShouldSuppressFinding(calledMethod, instructions, i, effectiveMethodSignals,
                                        typeSignals))
                                {
                                    _telemetry.AddPhaseElapsed("InstructionAnalyzer.ShouldSuppressFinding",
                                        suppressFindingStart);
                                    _telemetry.IncrementCounter("InstructionAnalyzer.SuppressedFindings");
                                    continue;
                                }
                                _telemetry.AddPhaseElapsed("InstructionAnalyzer.ShouldSuppressFinding",
                                    suppressFindingStart);

                                var snippet = _snippetBuilder.BuildSnippet(instructions, i, 2);

                                var description = rule.GetFindingDescription(method, calledMethod, instructions, i);

                                var finding = new ScanFinding(
                                    $"{method.DeclaringType?.FullName}.{method.Name}:{instruction.Offset}",
                                    description,
                                    rule.Severity,
                                    snippet).WithRuleMetadata(rule);
                                if (HasEquivalentFinding(result.Findings, finding))
                                {
                                    continue;
                                }

                                result.Findings.Add(finding);
                                _telemetry.IncrementCounter("InstructionAnalyzer.DirectFindings");
                                if (methodSignals != null &&
                                    !(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                                {
                                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType,
                                        rule.RuleId);
                                }
                            }
                        }

                        // Check for reflection-based calls that might bypass detection
                        var reflectionDetectorStart = _telemetry.StartTimestamp();
                        var reflectionFindings = _reflectionDetector.ScanForReflectionInvocation(method, instruction,
                            calledMethod, i, instructions, methodSignals);
                        _telemetry.AddPhaseElapsed("InstructionAnalyzer.ReflectionDetector",
                            reflectionDetectorStart);
                        foreach (var finding in reflectionFindings)
                        {
                            result.Findings.Add(finding);
                            _telemetry.IncrementCounter("InstructionAnalyzer.ReflectionBypassFindings");
                            var reflectionRuleForFinding = _rules.FirstOrDefault(r => r is ReflectionRule);
                            if (methodSignals != null && reflectionRuleForFinding != null &&
                                !(reflectionRuleForFinding.RequiresCompanionFinding &&
                                  finding.Severity == Severity.Low))
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType,
                                    reflectionRuleForFinding.RuleId);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // Skip instruction if it can't be properly analyzed
                }
            }

            _telemetry.AddPhaseElapsed("InstructionAnalyzer.AnalyzeInstructions", analysisStart);
            return result;
        }

        private IScanRule? FindFirstSuspiciousRule(MethodReference calledMethod)
        {
            foreach (var rule in _rules)
            {
                if (rule.IsSuspicious(calledMethod))
                {
                    return rule;
                }
            }

            return null;
        }

        private static bool HasEquivalentFinding(IEnumerable<ScanFinding> findings, ScanFinding candidate)
        {
            return findings.Any(existing =>
                string.Equals(existing.RuleId, candidate.RuleId, StringComparison.Ordinal) &&
                string.Equals(existing.Location, candidate.Location, StringComparison.Ordinal) &&
                string.Equals(existing.Description, candidate.Description, StringComparison.Ordinal) &&
                existing.Severity == candidate.Severity);
        }

        /// <summary>
        /// Builds a set of instruction offsets that are inside exception handler blocks.
        /// These are already analyzed by ExceptionHandlerAnalyzer with proper context.
        /// </summary>
        private HashSet<int> BuildExceptionHandlerOffsets(MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            var offsets = new HashSet<int>();

            if (!_config.AnalyzeExceptionHandlers || !method.Body.HasExceptionHandlers)
                return offsets;

            foreach (var handler in method.Body.ExceptionHandlers)
            {
                if (handler.HandlerStart == null)
                    continue;

                var startOffset = handler.HandlerStart.Offset;
                var endOffset = handler.HandlerEnd?.Offset ?? int.MaxValue;

                foreach (var instr in instructions)
                {
                    if (instr.Offset >= startOffset && instr.Offset < endOffset)
                    {
                        offsets.Add(instr.Offset);
                    }
                }
            }

            return offsets;
        }

        private static bool HasStrongReflectionCompanion(MethodSignals? signals, string reflectionRuleId)
        {
            if (signals == null)
                return false;

            foreach (var triggeredRuleId in signals.GetTriggeredRuleIds())
            {
                if (triggeredRuleId.Equals(reflectionRuleId, StringComparison.Ordinal))
                    continue;

                if (ReflectionCompanionRuleIds.Contains(triggeredRuleId))
                    return true;
            }

            return false;
        }

        private static bool OverridesRuleMethod(IScanRule rule, string methodName, params Type[] parameterTypes)
        {
            var method = rule.GetType().GetMethod(
                methodName,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                types: parameterTypes,
                modifiers: null);

            return method != null && method.DeclaringType != typeof(IScanRule);
        }
    }
}
