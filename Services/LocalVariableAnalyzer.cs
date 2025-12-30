using MLVScan.Models;
using MLVScan.Models.Rules;
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

        public IEnumerable<ScanFinding> AnalyzeLocalVariables(MethodDefinition method, Mono.Collections.Generic.Collection<VariableDefinition> variables, MethodSignals? methodSignals)
        {
            var findings = new List<ScanFinding>();

            if (!_config.AnalyzeLocalVariables)
                return findings;

            try
            {
                // Get the SuspiciousLocalVariableRule
                var localVarRule = _rules.FirstOrDefault(r => r is SuspiciousLocalVariableRule);
                if (localVarRule == null)
                    return findings;

                // Run the rule's analysis
                var ruleFindings = localVarRule.AnalyzeInstructions(method, method.Body.Instructions, methodSignals);

                foreach (var finding in ruleFindings)
                {
                    // Only add if companion finding requirement is met
                    if (localVarRule.RequiresCompanionFinding)
                    {
                        bool hasOtherTriggeredRules = methodSignals != null &&
                            methodSignals.HasTriggeredRuleOtherThan(localVarRule.RuleId);

                        if (!hasOtherTriggeredRules)
                            continue;
                    }

                    findings.Add(finding);

                    // Mark rule as triggered and update signals
                    if (methodSignals != null)
                    {
                        _signalTracker.MarkRuleTriggered(methodSignals, method.DeclaringType, localVarRule.RuleId);
                        _signalTracker.MarkSuspiciousLocalVariables(methodSignals, method.DeclaringType);
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

