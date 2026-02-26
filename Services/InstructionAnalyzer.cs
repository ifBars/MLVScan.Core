using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
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

        private readonly IEnumerable<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly ReflectionDetector _reflectionDetector;
        private readonly StringPatternDetector _stringPatternDetector;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly ScanConfig _config;
        private readonly CallGraphBuilder? _callGraphBuilder;

        public InstructionAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker, ReflectionDetector reflectionDetector,
                                   StringPatternDetector stringPatternDetector, CodeSnippetBuilder snippetBuilder, ScanConfig config,
                                   CallGraphBuilder? callGraphBuilder = null)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _reflectionDetector = reflectionDetector ?? throw new ArgumentNullException(nameof(reflectionDetector));
            _stringPatternDetector = stringPatternDetector ?? throw new ArgumentNullException(nameof(stringPatternDetector));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _config = config ?? new ScanConfig();
            _callGraphBuilder = callGraphBuilder;
        }

        public class InstructionAnalysisResult
        {
            public List<ScanFinding> Findings { get; set; } = new List<ScanFinding>();
            public List<(MethodDefinition method, Instruction instruction, int index, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals? methodSignals)> PendingReflectionFindings { get; set; } = new List<(MethodDefinition, Instruction, int, Mono.Collections.Generic.Collection<Instruction>, MethodSignals?)>();
        }

        public InstructionAnalysisResult AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions,
                                                          MethodSignals? methodSignals, string typeFullName)
        {
            var result = new InstructionAnalysisResult();

            // Build set of instruction offsets inside exception handlers
            // These are analyzed by ExceptionHandlerAnalyzer with proper context, skip here to prevent duplicates
            var exceptionHandlerOffsets = BuildExceptionHandlerOffsets(method, instructions);

            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                try
                {
                    // Check for direct method calls
                    if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                        instruction.Operand is MethodReference calledMethod)
                    {
                        // Track signals for multi-pattern detection
                        if (methodSignals != null)
                        {
                            _signalTracker.UpdateMethodSignals(methodSignals, calledMethod, method.DeclaringType);

                            // Check for Environment.GetFolderPath with sensitive folder values (for signal tracking)
                            if (calledMethod.DeclaringType?.FullName == "System.Environment" &&
                                calledMethod.Name == "GetFolderPath")
                            {
                                var folderValue = InstructionHelper.ExtractFolderPathArgument(instructions, i);
                                if (folderValue.HasValue && EnvironmentPathRule.IsSensitiveFolder(folderValue.Value))
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
                            // Register this call site with the call graph builder instead of creating a finding
                            var snippet = _snippetBuilder.BuildSnippet(instructions, i, 8);
                            var invocationContext = DllImportInvocationContextExtractor.TryBuildContext(method, calledMethod, instructions, i);
                            _callGraphBuilder!.RegisterCallSite(method, calledMethod, instruction.Offset, snippet, invocationContext);

                            // Mark rule as triggered for signal tracking
                            if (methodSignals != null)
                            {
                                var rule = _rules.FirstOrDefault(r => r.IsSuspicious(calledMethod));
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
                            // Call AnalyzeContextualPattern for all rules
                            foreach (var rule in _rules)
                            {
                                var ruleFindings = rule.AnalyzeContextualPattern(calledMethod, instructions, i, methodSignals);
                                foreach (var finding in ruleFindings)
                                {
                                    // If rule requires companion finding, check if other rules have been triggered
                                    // Exception: Low severity findings are always allowed (e.g., legitimate update checkers)
                                    // Exception: Findings with BypassCompanionCheck are always allowed (high-confidence scored findings)
                                    if (rule.RequiresCompanionFinding && finding.Severity != Severity.Low && !finding.BypassCompanionCheck)
                                    {
                                        bool hasOtherTriggeredRules = methodSignals != null &&
                                            methodSignals.HasTriggeredRuleOtherThan(rule.RuleId);

                                        // Also check type-level triggered rules
                                        bool hasTypeLevelTriggeredRules = false;
                                        if (!string.IsNullOrEmpty(typeFullName))
                                        {
                                            var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
                                            if (typeSignal != null)
                                            {
                                                hasTypeLevelTriggeredRules = typeSignal.HasTriggeredRuleOtherThan(rule.RuleId);
                                            }
                                        }

                                        // Only add finding if other rules have been triggered
                                        if (!hasOtherTriggeredRules && !hasTypeLevelTriggeredRules)
                                            continue;
                                    }

                                    // Enrich finding with rule metadata
                                    finding.WithRuleMetadata(rule);
                                    result.Findings.Add(finding);
                                    if (methodSignals != null && !(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                                    {
                                        _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                                    }
                                }
                            }
                        } // end exception handler skip

                        // For reflection invocations, only flag if combined with other malicious patterns
                        bool isReflectionInvoke = _reflectionDetector.IsReflectionInvokeMethod(calledMethod);
                        if (isReflectionInvoke)
                        {
                            var reflectionRule = _rules.FirstOrDefault(r => r is ReflectionRule);
                            if (reflectionRule == null)
                                continue;

                            // Check if strong companion rules have been triggered (not just any rule).
                            bool hasOtherTriggeredRules = HasStrongReflectionCompanion(methodSignals, reflectionRule.RuleId);

                            // Also check type-level triggered rules
                            bool hasTypeLevelTriggeredRules = false;
                            if (!string.IsNullOrEmpty(typeFullName))
                            {
                                var typeSignal = _signalTracker.GetTypeSignals(typeFullName);
                                if (typeSignal != null)
                                {
                                    hasTypeLevelTriggeredRules = HasStrongReflectionCompanion(typeSignal, reflectionRule.RuleId);
                                }
                            }

                            // If no other rules have been triggered, queue for later processing
                            if (!hasOtherTriggeredRules && !hasTypeLevelTriggeredRules)
                            {
                                // Queue for later processing after all methods in type are scanned
                                if (_config.EnableMultiSignalDetection && method.DeclaringType != null)
                                {
                                    result.PendingReflectionFindings.Add((method, instruction, i, instructions, methodSignals));
                                }
                                continue;
                            }

                            // Reflection combined with other triggered rules is suspicious
                            var snippet = _snippetBuilder.BuildSnippet(instructions, i, 2);

                            var finding = new ScanFinding(
                                $"{method.DeclaringType?.FullName}.{method.Name}:{instruction.Offset}",
                                reflectionRule.Description + " (combined with other suspicious patterns)",
                                reflectionRule.Severity,
                                snippet).WithRuleMetadata(reflectionRule);
                            result.Findings.Add(finding);
                            if (methodSignals != null && !(reflectionRule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, reflectionRule.RuleId);
                            }
                        }
                        // Check for suspicious patterns using IsSuspicious (skip for exception handlers)
                        // Also skip if CallGraphBuilder is tracking this method (will be consolidated)
                        // Note: isCallToTrackedSuspiciousMethod is checked at the top and continues early,
                        // but we also need to skip if the method is tracked (for methods matched by rules)
                        if (!exceptionHandlerOffsets.Contains(instruction.Offset) &&
                            !isCallToTrackedSuspiciousMethod &&
                            !isReflectionInvoke &&
                            _rules.Any(r => r.IsSuspicious(calledMethod)))
                        {
                            var rule = _rules.First(r => r.IsSuspicious(calledMethod));

                            // Get type-level signals for cross-method detection (e.g., file writes in other methods)
                            MethodSignals? typeSignals = null;
                            if (!string.IsNullOrEmpty(typeFullName))
                            {
                                typeSignals = _signalTracker.GetTypeSignals(typeFullName);
                            }

                            // Check if rule wants to suppress this finding based on contextual analysis
                            if (rule.ShouldSuppressFinding(calledMethod, instructions, i, methodSignals, typeSignals))
                            {
                                continue;
                            }

                            var snippet = _snippetBuilder.BuildSnippet(instructions, i, 2);

                            var description = rule.GetFindingDescription(method, calledMethod, instructions, i);

                            var finding = new ScanFinding(
                                $"{method.DeclaringType?.FullName}.{method.Name}:{instruction.Offset}",
                                description,
                                rule.Severity,
                                snippet).WithRuleMetadata(rule);
                            result.Findings.Add(finding);
                            if (methodSignals != null && !(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                            }
                        }

                        // Check for reflection-based calls that might bypass detection
                        var reflectionFindings = _reflectionDetector.ScanForReflectionInvocation(method, instruction, calledMethod, i, instructions, methodSignals);
                        foreach (var finding in reflectionFindings)
                        {
                            result.Findings.Add(finding);
                            var reflectionRuleForFinding = _rules.FirstOrDefault(r => r is ReflectionRule);
                            if (methodSignals != null && reflectionRuleForFinding != null &&
                                !(reflectionRuleForFinding.RequiresCompanionFinding && finding.Severity == Severity.Low))
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, reflectionRuleForFinding.RuleId);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // Skip instruction if it can't be properly analyzed
                }
            }

            return result;
        }

        /// <summary>
        /// Builds a set of instruction offsets that are inside exception handler blocks.
        /// These are already analyzed by ExceptionHandlerAnalyzer with proper context.
        /// </summary>
        private HashSet<int> BuildExceptionHandlerOffsets(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions)
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
    }
}
