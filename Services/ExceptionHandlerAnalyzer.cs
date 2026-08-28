using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    /// <summary>
    /// Analyzes code within exception handlers (try/catch/finally/filter blocks).
    /// Malware often hides malicious code in exception handlers to evade detection.
    /// </summary>
    public class ExceptionHandlerAnalyzer
    {
        private readonly IReadOnlyList<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly ScanConfig _config;

        public ExceptionHandlerAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker,
            CodeSnippetBuilder snippetBuilder, ScanConfig config)
        {
            _rules = rules?.ToArray() ?? throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _config = config ?? new ScanConfig();
        }

        public IEnumerable<ScanFinding> AnalyzeExceptionHandlers(MethodDefinition method,
            Mono.Collections.Generic.Collection<ExceptionHandler> exceptionHandlers,
            MethodSignals? methodSignals, string typeFullName)
        {
            var findings = new List<ScanFinding>();
            if (!_config.AnalyzeExceptionHandlers)
                return findings;

            bool incomplete = false;
            try
            {
                var instructions = method.Body.Instructions;
                var instructionIndexes = instructions
                    .Select((instruction, index) => (instruction, index))
                    .ToDictionary(item => item.instruction, item => item.index);
                int instructionBudget = Math.Max(1, _config.MaxExceptionHandlerInstructionsPerMethod);
                int findingBudget = Math.Max(1, _config.MaxExceptionHandlerFindingsPerMethod);
                int handlerBudget = Math.Max(1, _config.MaxExceptionHandlersPerMethod);

                for (int handlerIndex = 0; handlerIndex < exceptionHandlers.Count; handlerIndex++)
                {
                    if (handlerIndex >= handlerBudget)
                    {
                        incomplete = true;
                        break;
                    }

                    var handler = exceptionHandlers[handlerIndex];
                    if (handler.HandlerStart == null)
                        continue;

                    AnalyzeHandlerBlock(method, handler, instructions, instructionIndexes, methodSignals,
                        typeFullName, findings, ref instructionBudget, ref findingBudget, ref incomplete);

                    if (incomplete)
                        break;
                }
            }
            catch (Exception)
            {
                incomplete = true;
            }

            if (incomplete)
            {
                findings.Add(new ScanFinding(
                    $"{method.DeclaringType?.FullName}.{method.Name}",
                    "Exception-handler analysis reached a safety limit and could not complete; manual review is required.",
                    Severity.Medium,
                    string.Empty)
                {
                    RuleId = "ExceptionHandlerScanWarning"
                });
            }

            return findings;
        }

        private void AnalyzeHandlerBlock(MethodDefinition method,
            ExceptionHandler handler,
            Mono.Collections.Generic.Collection<Instruction> allInstructions,
            IReadOnlyDictionary<Instruction, int> instructionIndexes,
            MethodSignals? methodSignals,
            string typeFullName,
            ICollection<ScanFinding> findings,
            ref int instructionBudget,
            ref int findingBudget,
            ref bool incomplete)
        {
            if (!instructionIndexes.TryGetValue(handler.HandlerStart, out int startIndex))
            {
                incomplete = true;
                return;
            }

            int endExclusive = allInstructions.Count;
            if (handler.HandlerEnd != null &&
                !instructionIndexes.TryGetValue(handler.HandlerEnd, out endExclusive))
            {
                incomplete = true;
                return;
            }

            if (endExclusive < startIndex)
            {
                incomplete = true;
                return;
            }

            int instructionCount = endExclusive - startIndex;
            int instructionsToAnalyze = Math.Min(instructionCount, instructionBudget);
            if (instructionsToAnalyze < instructionCount)
                incomplete = true;

            for (int instructionIndex = startIndex;
                 instructionIndex < startIndex + instructionsToAnalyze;
                 instructionIndex++)
            {
                instructionBudget--;
                var instruction = allInstructions[instructionIndex];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference calledMethod)
                {
                    continue;
                }

                foreach (var rule in _rules)
                {
                    try
                    {
                        TrackSuspiciousDownloadSignal(method, calledMethod, allInstructions,
                            instructionIndex, methodSignals, rule);

                        if (!rule.IsSuspicious(calledMethod))
                            continue;

                        var effectiveSignals = methodSignals ?? new MethodSignals();
                        var handlerTypeDesc = GetHandlerTypeDescription(handler);
                        bool addedContextualFinding = false;

                        foreach (var contextualFinding in rule.AnalyzeContextualPattern(
                                     calledMethod, allInstructions, instructionIndex, effectiveSignals))
                        {
                            if (rule.RequiresCompanionFinding &&
                                contextualFinding.Severity != Severity.Low &&
                                !contextualFinding.BypassCompanionCheck)
                            {
                                bool hasOtherMethodRule = methodSignals != null &&
                                                          methodSignals.HasTriggeredRuleOtherThan(rule.RuleId);
                                var typeSignals = string.IsNullOrEmpty(typeFullName)
                                    ? null
                                    : _signalTracker.GetTypeSignals(typeFullName);
                                bool hasOtherTypeRule = typeSignals != null &&
                                                        typeSignals.HasTriggeredRuleOtherThan(rule.RuleId);
                                if (!hasOtherMethodRule && !hasOtherTypeRule)
                                    continue;
                            }

                            if (findingBudget == 0)
                            {
                                incomplete = true;
                                return;
                            }

                            contextualFinding.Description += $" (found in exception {handlerTypeDesc})";
                            contextualFinding.RuleId = rule.RuleId;
                            contextualFinding.DeveloperGuidance = rule.DeveloperGuidance;
                            findings.Add(contextualFinding);
                            findingBudget--;
                            addedContextualFinding = true;
                            MarkFindingSignals(method, methodSignals, rule, contextualFinding);
                        }

                        if (addedContextualFinding)
                            continue;

                        if (methodSignals != null &&
                            rule.ShouldSuppressFinding(calledMethod, allInstructions, instructionIndex, methodSignals))
                        {
                            continue;
                        }

                        if (findingBudget == 0)
                        {
                            incomplete = true;
                            return;
                        }

                        var snippet = _snippetBuilder.BuildSnippet(allInstructions, instructionIndex, 2);
                        var finding = new ScanFinding(
                            $"{method.DeclaringType?.FullName}.{method.Name}:{instruction.Offset}",
                            rule.Description + $" (found in exception {handlerTypeDesc})",
                            rule.Severity,
                            snippet)
                        {
                            RuleId = rule.RuleId,
                            DeveloperGuidance = rule.DeveloperGuidance
                        };

                        findings.Add(finding);
                        findingBudget--;
                        MarkFindingSignals(method, methodSignals, rule, finding);
                    }
                    catch (Exception)
                    {
                        // Individual rules may require optional dependency resolution. Other rules still run.
                    }
                }
            }
        }

        private void MarkFindingSignals(MethodDefinition method, MethodSignals? methodSignals,
            IScanRule rule, ScanFinding finding)
        {
            if (methodSignals == null)
                return;

            if (!(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);

            _signalTracker.MarkSuspiciousExceptionHandling(methodSignals, method.DeclaringType);
        }

        private void TrackSuspiciousDownloadSignal(
            MethodDefinition method,
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> allInstructions,
            int instructionIndex,
            MethodSignals? methodSignals,
            IScanRule rule)
        {
            if (instructionIndex < 0 || methodSignals == null ||
                !rule.RuleId.Equals("DataInfiltrationRule", StringComparison.Ordinal))
            {
                return;
            }

            foreach (var finding in rule.AnalyzeContextualPattern(
                         calledMethod, allInstructions, instructionIndex, methodSignals))
            {
                if (finding.Severity is Severity.High or Severity.Critical)
                    _signalTracker.MarkSuspiciousNetworkDownload(methodSignals, method.DeclaringType);
            }
        }

        private static string GetHandlerTypeDescription(ExceptionHandler handler)
        {
            return handler.HandlerType switch
            {
                ExceptionHandlerType.Catch => "catch block",
                ExceptionHandlerType.Finally => "finally block",
                ExceptionHandlerType.Filter => "filter block",
                ExceptionHandlerType.Fault => "fault block",
                _ => "handler"
            };
        }
    }
}
