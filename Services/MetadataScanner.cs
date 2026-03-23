using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using System.ComponentModel;
using MLVScan.Abstractions;

namespace MLVScan.Services
{
    /// <summary>
    /// Scans assembly-level metadata for rule matches.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class MetadataScanner
    {
        private readonly IEnumerable<IScanRule> _rules;

        /// <summary>
        /// Creates a metadata scanner that evaluates the supplied rules against assembly metadata.
        /// </summary>
        /// <param name="rules">The rules to run during metadata scanning.</param>
        public MetadataScanner(IEnumerable<IScanRule> rules)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        }

        /// <summary>
        /// Evaluates assembly-level metadata and returns any findings produced by registered rules.
        /// </summary>
        /// <param name="assembly">The assembly definition to inspect.</param>
        /// <returns>The findings emitted by metadata-aware rules.</returns>
        public IEnumerable<ScanFinding> ScanAssemblyMetadata(AssemblyDefinition assembly)
        {
            var findings = new List<ScanFinding>();

            try
            {
                foreach (var rule in _rules)
                {
                    var ruleFindings = rule.AnalyzeAssemblyMetadata(assembly);
                    foreach (var finding in ruleFindings)
                    {
                        finding.WithRuleMetadata(rule);
                        findings.Add(finding);
                    }
                }
            }
            catch (Exception)
            {
                // Skip metadata scanning if it fails
            }

            return findings;
        }
    }
}
