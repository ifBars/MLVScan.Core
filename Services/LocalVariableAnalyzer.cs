using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.ComponentModel;

namespace MLVScan.Services
{
    /// <summary>
    /// Analyzes local variables in method bodies for suspicious types.
    /// This provides context for multi-signal detection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class LocalVariableAnalyzer
    {
        private readonly IReadOnlyList<IScanRule> _localVariableRules;
        private readonly SignalTracker _signalTracker;
        private readonly ScanConfig _config;

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalVariableAnalyzer"/> class.
        /// </summary>
        /// <param name="rules">The rules available to the local-variable pass.</param>
        /// <param name="signalTracker">Tracks method and type-level signals.</param>
        /// <param name="config">Controls whether local-variable analysis is enabled.</param>
        public LocalVariableAnalyzer(IEnumerable<IScanRule> rules, SignalTracker signalTracker, ScanConfig config)
        {
            if (rules == null)
                throw new ArgumentNullException(nameof(rules));
            _signalTracker = signalTracker ?? throw new ArgumentNullException(nameof(signalTracker));
            _config = config ?? new ScanConfig();
            // Only rules that explicitly inspect local-variable state participate in this early pass.
            _localVariableRules = rules
                .Where(static rule => rule is SuspiciousLocalVariableRule)
                .ToArray();
        }

        /// <summary>
        /// Analyzes method locals and updates supporting signals used by later rule passes.
        /// </summary>
        /// <param name="method">The method whose locals are being inspected.</param>
        /// <param name="variables">The local variables declared in the method body.</param>
        /// <param name="methodSignals">The current method signal bag.</param>
        /// <returns>Any findings emitted by local-variable-aware rules.</returns>
        public IEnumerable<ScanFinding> AnalyzeLocalVariables(MethodDefinition method,
            Mono.Collections.Generic.Collection<VariableDefinition> variables, MethodSignals? methodSignals)
        {
            var findings = new List<ScanFinding>();
            var effectiveMethodSignals = methodSignals ?? _signalTracker.CreateMethodSignals() ?? new MethodSignals();

            if (!_config.AnalyzeLocalVariables)
                return findings;

            try
            {
                foreach (var rule in _localVariableRules)
                {
                    var ruleFindings = rule.AnalyzeInstructions(method, method.Body.Instructions,
                        effectiveMethodSignals);

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
                        }
                    }
                }

                if (effectiveMethodSignals.HasSuspiciousLocalVariables)
                {
                    _signalTracker.MarkSuspiciousLocalVariables(effectiveMethodSignals, method.DeclaringType);
                }
            }
            catch (Exception)
            {
                // Skip if analysis fails
            }

            return findings;
        }

        internal IReadOnlyCollection<string> GetProcessedRuleIds()
        {
            return _localVariableRules.Select(static rule => rule.RuleId).ToArray();
        }
    }
}
