using System.Text;
using System.Text.RegularExpressions;
using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects referenced embedded text resources that contain script-like command execution or
    /// anti-analysis payloads. This targets resource droppers without flagging unused bundled text.
    /// </summary>
    public class EmbeddedResourceScriptRule : IScanRule
    {
        private const int MaxResourceBytes = 2 * 1024 * 1024;

        private static readonly Regex SuspiciousExecutionPattern = new(
            @"(?i)(powershell|pwsh|cmd\.exe|start-process|shellexecute|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|net\.webclient|download(file|string)|executionpolicy|windowstyle\s+hidden|-noprofile|-nolog[o]?)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex AntiAnalysisPattern = new(
            @"(?i)(get-ciminstance|win32_videocontroller|win32_computersystem|remote display adapter|totalphysicalmemory|virtualbox|vmware|sandbox|analysis)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex StagedPayloadPattern = new(
            @"(?i)(%temp%|\\temp\\|\.(cmd|bat|ps1|vbs|js|hta)\b|out-file|set-content|add-content|start-sleep|remove-item)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        /// <summary>
        /// Gets the description emitted for suspicious embedded script resources.
        /// </summary>
        public string Description =>
            "Detected referenced embedded script resource with command execution or anti-analysis indicators.";

        /// <summary>
        /// Gets the default severity for suspicious embedded script resources.
        /// </summary>
        public Severity Severity => Severity.High;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "EmbeddedResourceScriptRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Returns false because this rule evaluates embedded resources after method scanning.
        /// </summary>
        public bool IsSuspicious(MethodReference method)
        {
            return false;
        }

        /// <summary>
        /// Scans referenced embedded resources for script payloads.
        /// </summary>
        /// <param name="module">The module being scanned.</param>
        /// <param name="existingFindings">Findings emitted by earlier rule passes.</param>
        /// <returns>Findings for referenced resource text with suspicious execution markers.</returns>
        public IEnumerable<ScanFinding> PostAnalysisRefine(
            ModuleDefinition module,
            IEnumerable<ScanFinding> existingFindings)
        {
            if (module == null || module.Resources.Count == 0)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            HashSet<string> referencedResources = CollectReferencedResourceNames(module);
            if (referencedResources.Count == 0)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            var findings = new List<ScanFinding>();
            foreach (Resource resource in module.Resources)
            {
                if (resource is not EmbeddedResource embedded ||
                    !referencedResources.Contains(embedded.Name) ||
                    !TryReadTextResource(embedded, out string resourceText))
                {
                    continue;
                }

                bool hasExecution = SuspiciousExecutionPattern.IsMatch(resourceText);
                bool hasAntiAnalysis = AntiAnalysisPattern.IsMatch(resourceText);
                bool hasStagedPayload = StagedPayloadPattern.IsMatch(resourceText);

                if (!hasExecution || (!hasAntiAnalysis && !hasStagedPayload))
                {
                    continue;
                }

                string risk = hasAntiAnalysis
                    ? "anti-analysis command markers"
                    : "staged script payload markers";

                findings.Add(new ScanFinding(
                    $"Embedded resource: {embedded.Name}",
                    $"Referenced embedded resource '{embedded.Name}' contains script execution with {risk}.",
                    Severity.High,
                    BuildSnippet(resourceText))
                {
                    RuleId = RuleId,
                    BypassCompanionCheck = true,
                    RiskScore = hasAntiAnalysis && hasStagedPayload ? 82 : 76
                });
            }

            return findings;
        }

        private static HashSet<string> CollectReferencedResourceNames(ModuleDefinition module)
        {
            var resourceNames = new HashSet<string>(StringComparer.Ordinal);

            foreach (TypeDefinition type in EnumerateTypes(module))
            {
                foreach (MethodDefinition method in type.Methods)
                {
                    if (!method.HasBody)
                    {
                        continue;
                    }

                    var instructions = method.Body.Instructions;
                    for (int i = 0; i < instructions.Count; i++)
                    {
                        Instruction instruction = instructions[i];
                        if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                            instruction.Operand is not MethodReference calledMethod ||
                            calledMethod.DeclaringType?.FullName != "System.Reflection.Assembly" ||
                            calledMethod.Name != "GetManifestResourceStream")
                        {
                            continue;
                        }

                        for (int j = i - 1; j >= Math.Max(0, i - 8); j--)
                        {
                            if (instructions[j].OpCode == OpCodes.Ldstr &&
                                instructions[j].Operand is string resourceName &&
                                !string.IsNullOrWhiteSpace(resourceName))
                            {
                                resourceNames.Add(resourceName);
                                break;
                            }
                        }
                    }
                }
            }

            return resourceNames;
        }

        private static bool TryReadTextResource(EmbeddedResource resource, out string text)
        {
            text = string.Empty;
            byte[] data;
            try
            {
                data = resource.GetResourceData();
            }
            catch
            {
                return false;
            }

            if (data.Length == 0 || data.Length > MaxResourceBytes || !LooksTextual(data))
            {
                return false;
            }

            text = Encoding.UTF8.GetString(data);
            return !string.IsNullOrWhiteSpace(text);
        }

        private static bool LooksTextual(byte[] data)
        {
            int sampleLength = Math.Min(data.Length, 4096);
            int printable = 0;

            for (int i = 0; i < sampleLength; i++)
            {
                byte value = data[i];
                if (value == 9 || value == 10 || value == 13 || (value >= 32 && value < 127) || value >= 128)
                {
                    printable++;
                }
            }

            return sampleLength == 0 || printable >= sampleLength * 0.85;
        }

        private static IEnumerable<TypeDefinition> EnumerateTypes(ModuleDefinition module)
        {
            foreach (TypeDefinition type in module.Types)
            {
                foreach (TypeDefinition nested in EnumerateTypes(type))
                {
                    yield return nested;
                }
            }
        }

        private static IEnumerable<TypeDefinition> EnumerateTypes(TypeDefinition type)
        {
            yield return type;

            foreach (TypeDefinition nestedType in type.NestedTypes)
            {
                foreach (TypeDefinition nested in EnumerateTypes(nestedType))
                {
                    yield return nested;
                }
            }
        }

        private static string BuildSnippet(string text)
        {
            string normalized = text.Replace("\r", " ").Replace("\n", " ").Trim();
            int markerIndex = FindFirstMarkerIndex(normalized);
            if (markerIndex > 120)
            {
                normalized = normalized[(markerIndex - 120)..];
            }

            if (normalized.Length > 420)
            {
                normalized = normalized[..420] + "...";
            }

            return normalized;
        }

        private static int FindFirstMarkerIndex(string text)
        {
            int best = -1;

            foreach (Regex pattern in new[] { AntiAnalysisPattern, SuspiciousExecutionPattern, StagedPayloadPattern })
            {
                Match match = pattern.Match(text);
                if (match.Success && (best < 0 || match.Index < best))
                {
                    best = match.Index;
                }
            }

            return best;
        }
    }
}
