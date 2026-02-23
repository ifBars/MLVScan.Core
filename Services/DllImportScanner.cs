using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;

namespace MLVScan.Services
{
    public class DllImportScanner
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly CallGraphBuilder? _callGraphBuilder;

        public DllImportScanner(IEnumerable<IScanRule> rules, CallGraphBuilder? callGraphBuilder = null)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _callGraphBuilder = callGraphBuilder;
        }

        /// <summary>
        /// Scans for suspicious P/Invoke declarations and registers them with the call graph builder.
        /// Returns an empty list when call graph builder is provided (findings are generated later by BuildCallChainFindings).
        /// Returns direct findings when no call graph builder is provided (legacy behavior).
        /// </summary>
        public IEnumerable<ScanFinding> ScanForDllImports(ModuleDefinition module)
        {
            var findings = new List<ScanFinding>();

            try
            {
                foreach (var type in TypeCollectionHelper.GetAllTypes(module))
                {
                    foreach (var method in type.Methods)
                    {
                        try
                        {
                            // Check if this is a PInvoke method
                            if ((method.Attributes & MethodAttributes.PInvokeImpl) == 0)
                                continue;

                            if (method.PInvokeInfo == null)
                                continue;

                            var matchedRule = _rules.FirstOrDefault(rule => rule.IsSuspicious(method));
                            if (matchedRule != null)
                            {
                                var severity = matchedRule.Severity;
                                var ruleDescription = matchedRule.Description;
                                var developerGuidance = matchedRule.DeveloperGuidance;

                                var dllName = method.PInvokeInfo.Module.Name;
                                var entryPoint = method.PInvokeInfo.EntryPoint ?? method.Name;
                                var snippet = $"[DllImport(\"{dllName}\", EntryPoint = \"{entryPoint}\")]\n{method.ReturnType.Name} {method.Name}({string.Join(", ", method.Parameters.Select(p => $"{p.ParameterType.Name} {p.Name}"))});";
                                var description = $"P/Invoke declaration imports {entryPoint} from {dllName}";

                                if (_callGraphBuilder != null)
                                {
                                    // Register with call graph builder for consolidation
                                    _callGraphBuilder.RegisterSuspiciousDeclaration(
                                        method,
                                        matchedRule,
                                        snippet,
                                        description,
                                        severity,
                                        ruleDescription,
                                        developerGuidance
                                    );
                                }
                                else
                                {
                                    // Legacy behavior: create direct finding
                                    var finding = new ScanFinding(
                                        $"{method.DeclaringType.FullName}.{method.Name}",
                                        ruleDescription,
                                        severity,
                                        snippet).WithRuleMetadata(matchedRule);

                                    finding.DeveloperGuidance = developerGuidance;
                                    findings.Add(finding);
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // Skip methods that can't be properly analyzed
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Skip module if it can't be properly analyzed
            }

            return findings;
        }
    }
}
