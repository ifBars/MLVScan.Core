using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    /// <summary>
    /// Analyzes local variables in method bodies for suspicious types.
    /// This provides context for multi-signal detection.
    /// </summary>
    public class LocalVariableAnalyzer
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly SignalTracker _signalTracker;
        private readonly ScanConfig _config;

        public LocalVariableAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker, ScanConfig config)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _config = config ?? new ScanConfig();
        }

        public IEnumerable<ScanFinding> AnalyzeLocalVariables(MethodDefinition method,
            Mono.Collections.Generic.Collection<VariableDefinition> variables, MethodSignals? methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (!_config.AnalyzeLocalVariables)
                return findings;

            try
            {
                // Run AnalyzeInstructions on all rules (not just SuspiciousLocalVariableRule)
                // This allows any rule to analyze local variables based on their own logic
                foreach (var rule in _rules)
                {
                    var ruleFindings = rule.AnalyzeInstructions(method, method.Body.Instructions, methodSignals);

                    foreach (var finding in ruleFindings)
                    {
                        // Only add if companion finding requirement is met
                        if (rule.RequiresCompanionFinding)
                        {
                            bool hasOtherTriggeredRules = methodSignals != null &&
                                                          methodSignals.HasTriggeredRuleOtherThan(rule.RuleId);

                            if (!hasOtherTriggeredRules)
                                continue;
                        }

                        // Enrich finding with rule metadata
                        finding.WithRuleMetadata(rule);
                        findings.Add(finding);

                        if (methodSignals != null)
                        {
                            // Companion-requiring rules must not self-bootstrap via their own Low findings
                            if (!(rule.RequiresCompanionFinding && finding.Severity == Severity.Low))
                            {
                                _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, rule.RuleId);
                            }

                            _signalTracker.MarkSuspiciousLocalVariables(methodSignals, method.DeclaringType);
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Skip if analysis fails
            }

            return findings;
        }
    }
}
