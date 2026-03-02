using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;

namespace MLVScan.Services
{
    /// <summary>
    /// Tracks call relationships between methods and builds call chains for suspicious patterns.
    /// This allows consolidating multiple related findings into a single finding with full attack path visibility.
    /// </summary>
    public class CallGraphBuilder
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly IEntryPointProvider _entryPointProvider;

        /// <summary>
        /// Suspicious method declarations (e.g., P/Invoke methods) indexed by their full name.
        /// </summary>
        private readonly Dictionary<string, SuspiciousDeclaration> _suspiciousDeclarations = new();

        /// <summary>
        /// Call sites where suspicious methods are invoked, indexed by the callee's full name.
        /// </summary>
        private readonly Dictionary<string, List<CallSite>> _callSites = new();

        public CallGraphBuilder(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder,
            IEntryPointProvider? entryPointProvider = null)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _entryPointProvider = entryPointProvider ?? new GenericEntryPointProvider();
        }

        /// <summary>
        /// Clears all tracked data. Call before scanning a new assembly.
        /// </summary>
        public void Clear()
        {
            _suspiciousDeclarations.Clear();
            _callSites.Clear();
        }

        /// <summary>
        /// Registers a suspicious P/Invoke or method declaration.
        /// </summary>
        public void RegisterSuspiciousDeclaration(
            MethodDefinition method,
            IScanRule triggeringRule,
            string codeSnippet,
            string description,
            Severity? capturedSeverity = null,
            string? capturedRuleDescription = null,
            IDeveloperGuidance? capturedDeveloperGuidance = null)
        {
            var key = GetMethodKey(method);
            if (_suspiciousDeclarations.ContainsKey(key))
                return; // Already registered

            _suspiciousDeclarations[key] = new SuspiciousDeclaration
            {
                Method = method,
                MethodKey = key,
                RuleId = triggeringRule.RuleId,
                RuleSeverity = capturedSeverity ?? triggeringRule.Severity,
                RuleDescription = capturedRuleDescription ?? triggeringRule.Description,
                DeveloperGuidance = capturedDeveloperGuidance ?? triggeringRule.DeveloperGuidance,
                CodeSnippet = codeSnippet,
                Description = description,
                Location = $"{method.DeclaringType?.FullName}.{method.Name}"
            };
        }

        /// <summary>
        /// Registers a call site where a method calls another method.
        /// </summary>
        public void RegisterCallSite(
            MethodDefinition callerMethod,
            MethodReference calledMethod,
            int instructionOffset,
            string codeSnippet,
            string? contextDescription = null)
        {
            var calleeKey = GetMethodKey(calledMethod);

            if (!_callSites.TryGetValue(calleeKey, out var sites))
            {
                sites = new List<CallSite>();
                _callSites[calleeKey] = sites;
            }

            // Avoid duplicates
            var callerKey = GetMethodKey(callerMethod);
            var existingSite = sites.FirstOrDefault(s =>
                s.CallerMethodKey == callerKey && s.InstructionOffset == instructionOffset);
            if (existingSite != null)
            {
                if (string.IsNullOrWhiteSpace(existingSite.ContextDescription) &&
                    !string.IsNullOrWhiteSpace(contextDescription))
                {
                    existingSite.ContextDescription = contextDescription;
                }

                return;
            }

            sites.Add(new CallSite
            {
                CallerMethod = callerMethod,
                CallerMethodKey = callerKey,
                CalledMethodKey = calleeKey,
                InstructionOffset = instructionOffset,
                CodeSnippet = codeSnippet,
                Location = $"{callerMethod.DeclaringType?.FullName}.{callerMethod.Name}:{instructionOffset}",
                ContextDescription = contextDescription
            });
        }

        /// <summary>
        /// Checks if a method reference points to a registered suspicious declaration.
        /// </summary>
        public bool IsSuspiciousMethod(MethodReference method)
        {
            var key = GetMethodKey(method);
            return _suspiciousDeclarations.ContainsKey(key);
        }

        /// <summary>
        /// Checks if any rule considers this method suspicious (for tracking calls to suspicious methods).
        /// </summary>
        public bool IsMethodSuspiciousByRule(MethodReference method)
        {
            return _rules.Any(rule => rule.IsSuspicious(method));
        }

        /// <summary>
        /// Builds consolidated call chain findings from all tracked data.
        /// Returns findings with full attack path visibility.
        /// </summary>
        public IEnumerable<ScanFinding> BuildCallChainFindings()
        {
            var findings = new List<ScanFinding>();
            var processedDeclarations = new HashSet<string>();

            foreach (var (declKey, declaration) in _suspiciousDeclarations)
            {
                if (processedDeclarations.Contains(declKey))
                    continue;

                // Check if there are any call sites for this suspicious declaration
                if (_callSites.TryGetValue(declKey, out var callSites) && callSites.Count > 0)
                {
                    // Build a consolidated finding with call chain
                    var callChain = BuildCallChain(declaration, callSites);
                    var finding = CreateCallChainFinding(callChain, declaration);
                    findings.Add(finding);
                }
                else
                {
                    // No callers found - emit as standalone finding (declaration without usage)
                    var finding = CreateStandaloneDeclarationFinding(declaration);
                    findings.Add(finding);
                }

                processedDeclarations.Add(declKey);
            }

            return findings;
        }

        /// <summary>
        /// Gets the count of registered suspicious declarations.
        /// </summary>
        public int SuspiciousDeclarationCount => _suspiciousDeclarations.Count;

        /// <summary>
        /// Gets the count of registered call sites.
        /// </summary>
        public int CallSiteCount => _callSites.Values.Sum(list => list.Count);

        private CallChain BuildCallChain(SuspiciousDeclaration declaration, List<CallSite> callSites)
        {
            var callChain = new CallChain(
                chainId: $"{declaration.RuleId}:{declaration.MethodKey}",
                ruleId: declaration.RuleId,
                severity: declaration.RuleSeverity,
                summary: BuildChainSummary(declaration, callSites)
            );

            // Add callers as entry points (we show all call sites for this malicious method)
            foreach (var callSite in callSites)
            {
                // Try to determine if this is a well-known entry point using the configured provider
                var nodeType = _entryPointProvider.IsEntryPoint(callSite.CallerMethod)
                    ? CallChainNodeType.EntryPoint
                    : CallChainNodeType.IntermediateCall;

                var callerDescription = nodeType == CallChainNodeType.EntryPoint
                    ? $"Entry point calls {declaration.Method.Name}"
                    : $"Calls {declaration.Method.Name}";

                if (!string.IsNullOrWhiteSpace(callSite.ContextDescription))
                {
                    callerDescription += $" ({callSite.ContextDescription})";
                }

                callChain.AppendNode(new CallChainNode(
                    callSite.Location,
                    callerDescription,
                    nodeType,
                    callSite.CodeSnippet
                ));
            }

            // Add the suspicious declaration as the final node
            callChain.AppendNode(new CallChainNode(
                declaration.Location,
                declaration.Description,
                CallChainNodeType.SuspiciousDeclaration,
                declaration.CodeSnippet
            ));

            return callChain;
        }

        private string BuildChainSummary(SuspiciousDeclaration declaration, List<CallSite> callSites)
        {
            var callerNames = callSites
                .Select(cs => cs.CallerMethod.Name)
                .Distinct()
                .Take(3);

            var callersStr = string.Join(", ", callerNames);
            if (callSites.Count > 3)
                callersStr += $" (+{callSites.Count - 3} more)";

            var summary =
                $"{declaration.RuleDescription} - Hidden in {declaration.Method.DeclaringType?.Name}.{declaration.Method.Name}, invoked from: {callersStr}";

            var contextDescriptions = callSites
                .Select(cs => cs.ContextDescription)
                .Where(context => !string.IsNullOrWhiteSpace(context))
                .Distinct(StringComparer.Ordinal)
                .Take(2)
                .ToList();

            if (contextDescriptions.Count == 1)
            {
                summary += $". {contextDescriptions[0]}";
            }
            else if (contextDescriptions.Count > 1)
            {
                summary += $". Invocation contexts: {string.Join(" | ", contextDescriptions)}";
            }

            return summary;
        }

        private ScanFinding CreateCallChainFinding(CallChain callChain, SuspiciousDeclaration declaration)
        {
            // Use the first caller as the primary location (this is where the attack is initiated)
            var primaryLocation = callChain.Nodes.Count > 1
                ? callChain.Nodes[0].Location
                : declaration.Location;

            // Use the concise summary for Description; the full call chain is available via CallChain property
            var finding = new ScanFinding(
                primaryLocation,
                callChain.Summary,
                callChain.Severity,
                callChain.ToCombinedCodeSnippet()
            );

            finding.RuleId = declaration.RuleId;
            finding.DeveloperGuidance = declaration.DeveloperGuidance;
            finding.CallChain = callChain;

            return finding;
        }

        private ScanFinding CreateStandaloneDeclarationFinding(SuspiciousDeclaration declaration)
        {
            var finding = new ScanFinding(
                declaration.Location,
                $"{declaration.RuleDescription} - {declaration.Description} (no callers detected - may be dead code or called via reflection)",
                declaration.RuleSeverity,
                declaration.CodeSnippet
            );

            finding.RuleId = declaration.RuleId;
            finding.DeveloperGuidance = declaration.DeveloperGuidance;

            return finding;
        }

        private static string GetMethodKey(MethodReference method)
        {
            return $"{method.DeclaringType?.FullName}.{method.Name}";
        }

        private static string GetMethodKey(MethodDefinition method)
        {
            return $"{method.DeclaringType?.FullName}.{method.Name}";
        }

        /// <summary>
        /// Internal representation of a suspicious method declaration.
        /// </summary>
        private class SuspiciousDeclaration
        {
            public MethodDefinition Method { get; set; } = null!;
            public string MethodKey { get; set; } = null!;
            public string RuleId { get; set; } = null!;
            public Severity RuleSeverity { get; set; }
            public string RuleDescription { get; set; } = null!;
            public IDeveloperGuidance? DeveloperGuidance { get; set; }
            public string CodeSnippet { get; set; } = null!;
            public string Description { get; set; } = null!;
            public string Location { get; set; } = null!;
        }

        /// <summary>
        /// Internal representation of a call site.
        /// </summary>
        private class CallSite
        {
            public MethodDefinition CallerMethod { get; set; } = null!;
            public string CallerMethodKey { get; set; } = null!;
            public string CalledMethodKey { get; set; } = null!;
            public int InstructionOffset { get; set; }
            public string CodeSnippet { get; set; } = null!;
            public string Location { get; set; } = null!;
            public string? ContextDescription { get; set; }
        }
    }
}
