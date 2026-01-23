using MLVScan.Models;

namespace MLVScan.Services.Helpers
{
    /// <summary>
    /// Extension methods for enriching ScanFindings with rule metadata.
    /// </summary>
    public static class ScanFindingExtensions
    {
        /// <summary>
        /// Enriches a ScanFinding with rule metadata (RuleId and DeveloperGuidance).
        /// This should be called after creating a finding to attach the originating rule's information.
        /// </summary>
        /// <param name="finding">The finding to enrich.</param>
        /// <param name="rule">The rule that generated this finding.</param>
        /// <returns>The enriched finding (for fluent chaining).</returns>
        public static ScanFinding WithRuleMetadata(this ScanFinding finding, IScanRule rule)
        {
            if (finding == null || rule == null)
                return finding;

            finding.RuleId = rule.RuleId;
            finding.DeveloperGuidance = rule.DeveloperGuidance;

            return finding;
        }
    }
}
