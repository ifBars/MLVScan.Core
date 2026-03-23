using System.Collections.Generic;
using System.Text.RegularExpressions;
using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects generic throwaway assembly names that commonly appear in disposable or repackaged malware samples.
    /// </summary>
    public class SuspiciousAssemblyNameRule : IScanRule
    {
        private static readonly Regex MelonLoaderModPattern =
            new(@"^MelonLoaderMod\d+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Gets the description emitted when the assembly name matches the generic pattern.
        /// </summary>
        public string Description =>
            "Detected suspicious generic assembly naming often associated with throwaway malware samples.";

        /// <summary>
        /// Gets the severity assigned to suspicious assembly names.
        /// </summary>
        public Severity Severity => Severity.Medium;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "SuspiciousAssemblyNameRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Returns false because this rule evaluates assembly metadata instead of method signatures.
        /// </summary>
        public bool IsSuspicious(MethodReference method)
        {
            return false;
        }

        /// <summary>
        /// Analyzes the assembly name and emits a finding when it matches the generic throwaway pattern.
        /// </summary>
        /// <param name="assembly">The assembly definition to inspect.</param>
        /// <returns>Findings for assemblies named with the generic <c>MelonLoaderMod##</c> pattern.</returns>
        public IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            string? assemblyName = assembly?.Name?.Name;
            if (string.IsNullOrWhiteSpace(assemblyName) || !MelonLoaderModPattern.IsMatch(assemblyName))
                yield break;

            yield return new ScanFinding(
                $"Assembly: {assemblyName}",
                "Assembly uses the generic name pattern 'MelonLoaderMod##', which is commonly seen in disposable malware-laced fake mods.",
                Severity,
                $"Assembly name: {assemblyName}");
        }
    }
}
