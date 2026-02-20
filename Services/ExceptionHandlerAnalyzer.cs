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
        private readonly IEnumerable<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly ScanConfig _config;

        public ExceptionHandlerAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker,
                                        CodeSnippetBuilder snippetBuilder, ScanConfig config)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
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

            try
            {
                foreach (var handler in exceptionHandlers)
                {
                    // Analyze handler block (catch/finally/filter)
                    if (handler.HandlerStart != null && handler.HandlerEnd != null)
                    {
                        var handlerFindings = AnalyzeHandlerBlock(
                            method,
                            handler,
                            method.Body.Instructions,
                            methodSignals,
                            typeFullName);
                        findings.AddRange(handlerFindings);
                    }
                }
            }
            catch (Exception)
            {
                // Skip if exception handler analysis fails
            }

            return findings;
        }

        private IEnumerable<ScanFinding> AnalyzeHandlerBlock(MethodDefinition method,
            ExceptionHandler handler,
            Mono.Collections.Generic.Collection<Instruction> allInstructions,
            MethodSignals? methodSignals,
            string typeFullName)
        {
            var findings = new List<ScanFinding>();

            try
            {
                var handlerInstructions = GetInstructionsInRange(
                    allInstructions,
                    handler.HandlerStart,
                    handler.HandlerEnd);

                if (handlerInstructions.Count == 0)
                    return findings;

                // Analyze instructions in the handler block
                foreach (var instruction in handlerInstructions)
                {
                    // Check for method calls in exception handlers
                    if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                        instruction.Operand is MethodReference calledMethod)
                    {
                        // Check if any rule considers this method suspicious
                        foreach (var rule in _rules)
                        {
                            if (rule.IsSuspicious(calledMethod))
                            {
                                var instructionIndex = allInstructions.IndexOf(instruction);
                                var snippet = _snippetBuilder.BuildSnippet(allInstructions, instructionIndex, 2);

                                var handlerTypeDesc = GetHandlerTypeDescription(handler);
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

                                // Mark signals
                                if (methodSignals != null)
                                {
                                    _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                                    _signalTracker.MarkSuspiciousExceptionHandling(methodSignals, method.DeclaringType);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Skip if handler block analysis fails
            }

            return findings;
        }

        private static List<Instruction> GetInstructionsInRange(
            Mono.Collections.Generic.Collection<Instruction> allInstructions,
            Instruction start,
            Instruction? end)
        {
            var result = new List<Instruction>();

            if (start == null)
                return result;

            bool inRange = false;
            foreach (var instruction in allInstructions)
            {
                if (instruction == start)
                {
                    inRange = true;
                }

                if (inRange)
                {
                    result.Add(instruction);
                }

                if (instruction == end)
                {
                    break;
                }
            }

            return result;
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

