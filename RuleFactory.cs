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
                new SuspiciousAssemblyNameRule()
            }.AsReadOnly();
        }
    }
}
