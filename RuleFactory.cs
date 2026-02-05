using MLVScan.Models;
using MLVScan.Models.Rules;

namespace MLVScan
{
    /// <summary>
    /// Factory for creating the default set of scan rules.
    /// Use this to get a consistent set of rules across all platforms.
    /// </summary>
    public static class RuleFactory
    {
        /// <summary>
        /// Creates the default set of scan rules for detecting malicious patterns.
        /// </summary>
        /// <returns>A read-only list of all default scan rules.</returns>
        public static IReadOnlyList<IScanRule> CreateDefaultRules()
        {
            return new List<IScanRule>
            {
                new Base64Rule(),
                new ProcessStartRule(),
                new Shell32Rule(),
                new AssemblyDynamicLoadRule(),
                new ByteArrayManipulationRule(),
                new DllImportRule(),
                new RegistryRule(),
                new EncodedStringLiteralRule(),
                new ReflectionRule(),
                new EnvironmentPathRule(),
                new EncodedStringPipelineRule(),
                new EncodedBlobSplittingRule(),
                new COMReflectionAttackRule(),
                new DataExfiltrationRule(),
                new DataInfiltrationRule(),
                new PersistenceRule(),
                new HexStringRule(),
                new SuspiciousLocalVariableRule()
            }.AsReadOnly();
        }
    }
}
