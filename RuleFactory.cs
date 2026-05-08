using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;

namespace MLVScan
{
    /// <summary>
    /// Creates the built-in rule set shipped with <c>MLVScan.Core</c>.
    /// Consumers that want the standard scanner behavior across CLI, API, WASM, or desktop hosts should start here.
    /// </summary>
    public static class RuleFactory
    {
        /// <summary>
        /// Creates the default set of rules in the order expected by the core scanning pipeline.
        /// </summary>
        /// <returns>A read-only list containing the built-in rules registered by the library.</returns>
        public static IReadOnlyList<IScanRule> CreateDefaultRules()
        {
            return CreateCoreRules().AsReadOnly();
        }

        /// <summary>
        /// Creates the default rule set with additional consumer-supplied rules appended.
        /// </summary>
        /// <param name="additionalRules">External rules to run after the built-in rules.</param>
        /// <returns>A read-only list containing the built-in rules followed by the additional rules.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="additionalRules"/> or one of its entries is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any rule ID is blank or duplicated.</exception>
        public static IReadOnlyList<IScanRule> CreateDefaultRulesWith(params IScanRule[] additionalRules)
        {
            if (additionalRules == null)
            {
                throw new ArgumentNullException(nameof(additionalRules));
            }

            var rules = CreateCoreRules();

            foreach (var rule in additionalRules)
            {
                if (rule == null)
                {
                    throw new ArgumentNullException(nameof(additionalRules), "Additional rules cannot contain null entries.");
                }

                rules.Add(rule);
            }

            ValidateRuleIds(rules);
            return rules.AsReadOnly();
        }

        private static List<IScanRule> CreateCoreRules()
        {
            return new List<IScanRule>
            {
                new Base64Rule(),
                new ProcessStartRule(),
                new AssemblyDynamicLoadRule(),
                new ByteArrayManipulationRule(),
                new DllImportRule(),
                new RegistryRule(),
                new EncodedStringLiteralRule(),
                new ReflectionRule(),
                new EncodedStringPipelineRule(),
                new EncodedBlobSplittingRule(),
                new COMReflectionAttackRule(),
                new DataExfiltrationRule(),
                new DataInfiltrationRule(),
                new PersistenceRule(),
                new HexStringRule(),
                new SuspiciousLocalVariableRule(),
                new ObfuscatedReflectiveExecutionRule(),
                new EmbeddedResourceScriptRule(),
                new SuspiciousAssemblyNameRule()
            };
        }

        private static void ValidateRuleIds(IEnumerable<IScanRule> rules)
        {
            var seenRuleIds = new HashSet<string>(StringComparer.Ordinal);

            foreach (var rule in rules)
            {
                if (string.IsNullOrWhiteSpace(rule.RuleId))
                {
                    throw new ArgumentException("Rule IDs cannot be null, empty, or whitespace.", nameof(rules));
                }

                if (!seenRuleIds.Add(rule.RuleId))
                {
                    throw new ArgumentException($"Duplicate rule ID '{rule.RuleId}' was registered.", nameof(rules));
                }
            }
        }
    }
}
