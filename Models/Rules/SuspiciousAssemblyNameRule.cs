using System.Collections.Generic;
using System.Text.RegularExpressions;
using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    public class SuspiciousAssemblyNameRule : IScanRule
    {
        private static readonly Regex MelonLoaderModPattern =
            new(@"^MelonLoaderMod\d+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public string Description =>
            "Detected suspicious generic assembly naming often associated with throwaway malware samples.";

        public Severity Severity => Severity.Medium;
        public string RuleId => "SuspiciousAssemblyNameRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            return false;
        }

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
