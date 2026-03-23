using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Diagnostics;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.ComponentModel;
using MLVScan.Abstractions;

namespace MLVScan.Services
{
    /// <summary>
    /// Coordinates per-method rule execution across local-variable, exception-handler, string, and instruction passes.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class MethodScanner
    {
        private readonly IReadOnlyList<IScanRule> _rules;
        private readonly IReadOnlyList<IScanRule> _stringLiteralRules;
        private readonly SignalTracker _signalTracker;
        private readonly InstructionAnalyzer _instructionAnalyzer;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly LocalVariableAnalyzer _localVariableAnalyzer;
        private readonly ExceptionHandlerAnalyzer _exceptionHandlerAnalyzer;
        private readonly ScanConfig _config;
        private readonly ScanTelemetryHub _telemetry;

        /// <summary>
        /// Initializes a new instance of the <see cref="MethodScanner"/> class.
        /// </summary>
        /// <param name="rules">The rules that participate in method scanning.</param>
        /// <param name="signalTracker">Tracks method and type-level signals.</param>
        /// <param name="instructionAnalyzer">Performs instruction-level contextual analysis.</param>
        /// <param name="snippetBuilder">Builds snippets for emitted findings.</param>
        /// <param name="localVariableAnalyzer">Performs the early local-variable signal pass.</param>
        /// <param name="exceptionHandlerAnalyzer">Analyzes exception handlers separately from the main pass.</param>
        /// <param name="config">Controls method-scanner behavior.</param>
        public MethodScanner(IEnumerable<IScanRule> rules, SignalTracker signalTracker,
            InstructionAnalyzer instructionAnalyzer,
            CodeSnippetBuilder snippetBuilder, LocalVariableAnalyzer localVariableAnalyzer,
            ExceptionHandlerAnalyzer exceptionHandlerAnalyzer, ScanConfig config)
            : this(rules, signalTracker, instructionAnalyzer, snippetBuilder, localVariableAnalyzer,
                exceptionHandlerAnalyzer, config, new ScanTelemetryHub())
        {
        }

        internal MethodScanner(IEnumerable<IScanRule> rules, SignalTracker signalTracker,
            InstructionAnalyzer instructionAnalyzer,
            CodeSnippetBuilder snippetBuilder, LocalVariableAnalyzer localVariableAnalyzer,
            ExceptionHandlerAnalyzer exceptionHandlerAnalyzer, ScanConfig config, ScanTelemetryHub telemetry)
        {
            if (rules == null)
                throw new ArgumentNullException(nameof(rules));

            _rules = rules.ToArray();
            _stringLiteralRules = _rules
                .Where(static rule => RuleOverrideChecker.OverridesRuleMethod(rule, nameof(IScanRule.AnalyzeStringLiteral),
                    typeof(string), typeof(MethodDefinition), typeof(int)))
                .ToArray();
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _instructionAnalyzer = instructionAnalyzer ?? throw new ArgumentNullException(nameof(instructionAnalyzer));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _localVariableAnalyzer =
                localVariableAnalyzer ?? throw new ArgumentNullException(nameof(localVariableAnalyzer));
            _exceptionHandlerAnalyzer = exceptionHandlerAnalyzer ??
                                        throw new ArgumentNullException(nameof(exceptionHandlerAnalyzer));
            _config = config ?? new ScanConfig();
            _telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
        }

        /// <summary>
        /// Represents the aggregate result of scanning a single method.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public class MethodScanResult
        {
            /// <summary>
            /// Gets or sets the findings produced while scanning the method.
            /// </summary>
            public List<ScanFinding> Findings { get; set; } = new List<ScanFinding>();

            /// <summary>
            /// Gets or sets reflection findings that must be revisited once type-level signals are known.
            /// </summary>
            public List<(MethodDefinition method, Instruction instruction, int index,
                    Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals? methodSignals)>
                PendingReflectionFindings { get; set; } =
                new List<(MethodDefinition, Instruction, int, Mono.Collections.Generic.Collection<Instruction>,
                    MethodSignals?)>();
        }

        /// <summary>
        /// Scans a single method across all method-level analysis passes.
        /// </summary>
        /// <param name="method">The method to scan.</param>
        /// <param name="typeFullName">The declaring type's full name for cross-method signal correlation.</param>
        /// <returns>The findings and deferred reflection work collected for the method.</returns>
        public MethodScanResult ScanMethod(MethodDefinition method, string typeFullName)
        {
            var result = new MethodScanResult();
            var methodName = $"{method.DeclaringType?.FullName}.{method.Name}";
            var methodStart = _telemetry.StartTimestamp();
            var instructionCount = method.HasBody ? method.Body.Instructions.Count : 0;
            var localVariableCount = method.HasBody && method.Body.HasVariables ? method.Body.Variables.Count : 0;
            var exceptionHandlerCount = method.HasBody && method.Body.HasExceptionHandlers
                ? method.Body.ExceptionHandlers.Count
                : 0;

            try
            {
                // Skip methods without a body (e.g., abstract or interface methods)
                if (!method.HasBody)
                {
                    _telemetry.IncrementCounter("MethodScanner.MethodsWithoutBodySkipped");
                    return result;
                }

                _telemetry.IncrementCounter("MethodScanner.MethodsScanned");
                _telemetry.IncrementCounter("MethodScanner.InstructionsVisited", instructionCount);
                _telemetry.IncrementCounter("MethodScanner.LocalVariablesVisited", localVariableCount);
                _telemetry.IncrementCounter("MethodScanner.ExceptionHandlersVisited", exceptionHandlerCount);

                var instructions = method.Body.Instructions;
                var processedLocalRuleIds = new HashSet<string>(StringComparer.Ordinal);

                // Initialize signal tracking for this method
                var methodSignals = _signalTracker.CreateMethodSignals();
                var effectiveMethodSignals = methodSignals ?? new MethodSignals();

                // Analyze local variables if present
                if (method.Body.HasVariables)
                {
                    var localVariableStart = _telemetry.StartTimestamp();
                    var variableFindings =
                        _localVariableAnalyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals);
                    _telemetry.AddPhaseElapsed("MethodScanner.AnalyzeLocalVariables", localVariableStart);
                    result.Findings.AddRange(variableFindings);
                    if (_config.AnalyzeLocalVariables)
                    {
                        processedLocalRuleIds = new HashSet<string>(_localVariableAnalyzer.GetProcessedRuleIds(),
                            StringComparer.Ordinal);
                    }
                }

                // Analyze exception handlers if present
                if (method.Body.HasExceptionHandlers)
                {
                    var exceptionHandlerStart = _telemetry.StartTimestamp();
                    var handlerFindings = _exceptionHandlerAnalyzer.AnalyzeExceptionHandlers(
                        method, method.Body.ExceptionHandlers, methodSignals, typeFullName);
                    _telemetry.AddPhaseElapsed("MethodScanner.AnalyzeExceptionHandlers", exceptionHandlerStart);
                    result.Findings.AddRange(handlerFindings);
                }

                // Call AnalyzeInstructions for all rules
                var ruleInstructionPassStart = _telemetry.StartTimestamp();
                foreach (var rule in _rules)
                {
                    if (processedLocalRuleIds.Contains(rule.RuleId))
                    {
                        continue;
                    }

                    _telemetry.IncrementCounter("MethodScanner.RuleInstructionPasses");
                    var ruleFindings = rule.AnalyzeInstructions(method, instructions, effectiveMethodSignals);
                    foreach (var finding in ruleFindings)
                    {
                        // If rule requires companion finding, check if other rules have been triggered
                        // Exception: Low severity findings are always allowed (e.g., legitimate update checkers)
                        // Exception: Findings with BypassCompanionCheck are always allowed (high-confidence scored findings)
                        if (rule.RequiresCompanionFinding && finding.Severity != Severity.Low &&
                            !finding.BypassCompanionCheck)
                        {
                            bool hasOtherTriggeredRules = methodSignals != null &&
                                                          methodSignals.HasTriggeredRuleOtherThan(rule.RuleId);

                            // Only add finding if other rules have been triggered
                            if (!hasOtherTriggeredRules)
                                continue;
                        }

                        // Enrich finding with rule metadata
                        finding.WithRuleMetadata(rule);
                        result.Findings.Add(finding);
                        // Companion-requiring rules that only emitted a Low finding (audit annotation) must
                        // not mark themselves as triggered — that would let them bootstrap their own companion.
                        // Non-companion rules may always mark triggered regardless of severity.
                        if (methodSignals != null &&
                            !(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                        {
                            _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                        }

                        // Update signals if encoded strings were detected
                        if (methodSignals != null &&
                            (rule is EncodedStringLiteralRule ||
                             rule is EncodedStringPipelineRule ||
                             rule is EncodedBlobSplittingRule))
                        {
                            _signalTracker.MarkEncodedStrings(methodSignals, method.DeclaringType);
                        }
                    }
                }
                _telemetry.AddPhaseElapsed("MethodScanner.RuleInstructionPasses", ruleInstructionPassStart);

                // Scan for encoded strings in all ldstr instructions
                var stringLiteralStart = _telemetry.StartTimestamp();
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];

                    // Check for encoded strings using rule analysis
                    if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string strLiteral)
                    {
                        _telemetry.IncrementCounter("MethodScanner.StringLiteralInstructions");
                        foreach (var rule in _stringLiteralRules)
                        {
                            _telemetry.IncrementCounter("MethodScanner.StringLiteralRulePasses");
                            var ruleFindings = rule.AnalyzeStringLiteral(strLiteral, method, i);
                            foreach (var finding in ruleFindings)
                            {
                                // If rule requires companion finding, check if other rules have been triggered
                                // Exception: Low severity findings are always allowed (e.g., legitimate update checkers)
                                // Exception: Findings with BypassCompanionCheck are always allowed (high-confidence scored findings)
                                if (rule.RequiresCompanionFinding && finding.Severity != Severity.Low &&
                                    !finding.BypassCompanionCheck)
                                {
                                    bool hasOtherTriggeredRules = methodSignals != null &&
                                                                  methodSignals.HasTriggeredRuleOtherThan(rule.RuleId);

                                    // Only add finding if other rules have been triggered
                                    if (!hasOtherTriggeredRules)
                                        continue;
                                }

                                // Enrich finding with rule metadata
                                finding.WithRuleMetadata(rule);
                                result.Findings.Add(finding);
                                if (methodSignals != null &&
                                    !(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                                {
                                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                                }

                                // Update signals if encoded strings were detected
                                if (methodSignals != null)
                                {
                                    _signalTracker.MarkEncodedStrings(methodSignals, method.DeclaringType);
                                }
                            }
                        }
                    }
                }
                _telemetry.AddPhaseElapsed("MethodScanner.StringLiteralPasses", stringLiteralStart);

                // Analyze instructions for method calls and suspicious patterns
                var instructionAnalyzerStart = _telemetry.StartTimestamp();
                var instructionResult =
                    _instructionAnalyzer.AnalyzeInstructions(method, instructions, methodSignals, typeFullName);
                _telemetry.AddPhaseElapsed("MethodScanner.InstructionAnalyzer", instructionAnalyzerStart);
                result.Findings.AddRange(instructionResult.Findings);
                result.PendingReflectionFindings.AddRange(instructionResult.PendingReflectionFindings);

                // After scanning all instructions, check for multi-signal combinations
                if (methodSignals != null && _config.EnableMultiSignalDetection)
                {
                    if (methodSignals.IsCriticalCombination())
                    {
                        result.Findings.Add(new ScanFinding(
                            $"{method.DeclaringType?.FullName}.{method.Name}",
                            $"Critical: Multiple suspicious patterns detected ({methodSignals.GetCombinationDescription()})",
                            Severity.Critical,
                            $"This method contains {methodSignals.SignalCount} suspicious signals that form a likely malicious pattern.")
                        {
                            RuleId = "MultiSignalDetection"
                        });
                    }
                    else if (methodSignals.IsHighRiskCombination())
                    {
                        result.Findings.Add(new ScanFinding(
                            $"{method.DeclaringType?.FullName}.{method.Name}",
                            $"High risk: Multiple suspicious patterns detected ({methodSignals.GetCombinationDescription()})",
                            Severity.High,
                            $"This method contains {methodSignals.SignalCount} suspicious signals.")
                        {
                            RuleId = "MultiSignalDetection"
                        });
                    }
                }
            }
            catch (Exception)
            {
                // Skip method if it can't be properly analyzed
            }
            finally
            {
                _telemetry.AddPhaseElapsed("MethodScanner.ScanMethod", methodStart);
                _telemetry.RecordMethodSample(
                    methodName,
                    methodStart,
                    instructionCount,
                    result.Findings.Count,
                    localVariableCount,
                    exceptionHandlerCount,
                    result.PendingReflectionFindings.Count);
            }

            return result;
        }
    }
}
