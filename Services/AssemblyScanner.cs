using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.DeepBehavior;
using Mono.Cecil;

namespace MLVScan.Services
{
    /// <summary>
    /// Core assembly scanner that analyzes .NET assemblies for malicious patterns.
    /// Supports both file-based and stream-based scanning.
    /// </summary>
    public class AssemblyScanner : Abstractions.IAssemblyScanner
    {
        private static readonly HashSet<string> DeepCorrelationRuleIds = new(StringComparer.Ordinal)
        {
            "ProcessStartRule",
            "Shell32Rule",
            "AssemblyDynamicLoadRule",
            "DllImportRule",
            "ReflectionRule",
            "EnvironmentPathRule",
            "Base64Rule",
            "HexStringRule",
            "EncodedStringLiteralRule",
            "EncodedStringPipelineRule",
            "EncodedBlobSplittingRule",
            "ByteArrayManipulationRule",
            "RegistryRule",
            "COMReflectionAttackRule",
            "DataExfiltrationRule",
            "DataInfiltrationRule",
            "PersistenceRule"
        };

        private readonly IEnumerable<IScanRule> _rules;
        private readonly TypeScanner _typeScanner;
        private readonly MetadataScanner _metadataScanner;
        private readonly DllImportScanner _dllImportScanner;
        private readonly CallGraphBuilder _callGraphBuilder;
        private readonly DataFlowAnalyzer _dataFlowAnalyzer;
        private readonly DeepBehaviorOrchestrator _deepBehaviorOrchestrator;
        private readonly IAssemblyResolverProvider _resolverProvider;
        private readonly ScanConfig _config;

        /// <summary>
        /// Creates a new AssemblyScanner with the specified rules and configuration.
        /// </summary>
        /// <param name="rules">The scan rules to apply during analysis.</param>
        /// <param name="config">Optional configuration. Uses defaults if not specified.</param>
        /// <param name="resolverProvider">Optional assembly resolver provider for resolving referenced assemblies.</param>
        /// <param name="entryPointProvider">Optional entry point provider for environment-specific entry point detection. Uses generic provider if not specified.</param>
        public AssemblyScanner(
            IEnumerable<IScanRule> rules,
            ScanConfig? config = null,
            IAssemblyResolverProvider? resolverProvider = null,
            IEntryPointProvider? entryPointProvider = null)
        {
            _config = config ?? new ScanConfig();
            _resolverProvider = resolverProvider ?? DefaultAssemblyResolverProvider.Instance;
            _rules = rules;

            // Create all services using composition
            var snippetBuilder = new CodeSnippetBuilder();
            var signalTracker = new SignalTracker(_config);
            var stringPatternDetector = new StringPatternDetector();

            // Create call graph builder for finding consolidation
            _callGraphBuilder = new CallGraphBuilder(rules, snippetBuilder, entryPointProvider);

            // Create data flow analyzer for tracking data movement through operations
            _dataFlowAnalyzer = new DataFlowAnalyzer(rules, snippetBuilder);

            // Create deep behavior orchestrator for practical Unity-mod threat correlation
            _deepBehaviorOrchestrator = new DeepBehaviorOrchestrator(_config.DeepAnalysis, snippetBuilder, entryPointProvider);

            var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
            var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, _config, _callGraphBuilder);
            var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, _config);
            var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, _config);
            var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, localVariableAnalyzer, exceptionHandlerAnalyzer, _config);
            var propertyEventScanner = new PropertyEventScanner(methodScanner, _config);

            _typeScanner = new TypeScanner(methodScanner, signalTracker, reflectionDetector, snippetBuilder, propertyEventScanner, rules, _config);
            _metadataScanner = new MetadataScanner(rules);
            _dllImportScanner = new DllImportScanner(rules, _callGraphBuilder);
        }

        /// <summary>
        /// Scans an assembly from a file path.
        /// </summary>
        /// <param name="assemblyPath">The absolute path to the assembly file.</param>
        /// <returns>A collection of scan findings.</returns>
        /// <exception cref="ArgumentException">Thrown when the assembly path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the assembly file is not found.</exception>
        public IEnumerable<ScanFinding> Scan(string assemblyPath)
        {
            if (string.IsNullOrWhiteSpace(assemblyPath))
                throw new ArgumentException("Assembly path must be provided", nameof(assemblyPath));

            if (!File.Exists(assemblyPath))
                throw new FileNotFoundException("Assembly file not found", assemblyPath);

            var findings = new List<ScanFinding>();

            try
            {
                // Clear builders for fresh scan
                _callGraphBuilder.Clear();
                _dataFlowAnalyzer.Clear();
                _deepBehaviorOrchestrator.Reset();

                var readerParameters = new ReaderParameters
                {
                    ReadWrite = false,
                    InMemory = true,
                    ReadSymbols = false,
                    AssemblyResolver = _resolverProvider.CreateResolver(),
                };

                var assembly = AssemblyDefinition.ReadAssembly(assemblyPath, readerParameters);
                ScanAssembly(assembly, findings);

                // Build consolidated call chain findings
                var callChainFindings = _callGraphBuilder.BuildCallChainFindings();
                findings.AddRange(callChainFindings);

                // Build data flow findings
                var dataFlowFindings = _dataFlowAnalyzer.BuildDataFlowFindings();
                findings.AddRange(dataFlowFindings);
            }
            catch (Exception)
            {
                findings.Add(new ScanFinding(
                    "Assembly scanning",
                    "Warning: Some parts of the assembly could not be scanned. This doesn't necessarily mean the mod is malicious.",
                    Severity.Low)
                {
                    RuleId = "AssemblyScanner"
                });
            }

            return FilterEmptyFindings(findings);
        }

        /// <summary>
        /// Scans an assembly from a stream.
        /// Suitable for web scenarios where the assembly is uploaded as a file.
        /// </summary>
        /// <param name="assemblyStream">A readable stream containing the assembly bytes.</param>
        /// <param name="virtualPath">Optional virtual path for error messages.</param>
        /// <returns>A collection of scan findings.</returns>
        /// <exception cref="ArgumentException">Thrown when the stream is null or not readable.</exception>
        public IEnumerable<ScanFinding> Scan(Stream assemblyStream, string? virtualPath = null)
        {
            if (assemblyStream == null || !assemblyStream.CanRead)
                throw new ArgumentException("Assembly stream must be readable", nameof(assemblyStream));

            // Ensure stream is at the beginning
            if (assemblyStream.CanSeek)
                assemblyStream.Position = 0;

            var findings = new List<ScanFinding>();

            try
            {
                // Clear builders for fresh scan
                _callGraphBuilder.Clear();
                _dataFlowAnalyzer.Clear();
                _deepBehaviorOrchestrator.Reset();

                var readerParameters = new ReaderParameters
                {
                    ReadWrite = false,
                    InMemory = true,
                    ReadSymbols = false,
                    AssemblyResolver = _resolverProvider.CreateResolver(),
                };

                var assembly = AssemblyDefinition.ReadAssembly(assemblyStream, readerParameters);
                ScanAssembly(assembly, findings);

                // Build consolidated call chain findings
                var callChainFindings = _callGraphBuilder.BuildCallChainFindings();
                findings.AddRange(callChainFindings);

                // Build data flow findings
                var dataFlowFindings = _dataFlowAnalyzer.BuildDataFlowFindings();
                findings.AddRange(dataFlowFindings);
            }
            catch (Exception)
            {
                findings.Add(new ScanFinding(
                    virtualPath ?? "Assembly scanning",
                    "Warning: Some parts of the assembly could not be scanned. Please ensure this is a valid Unity mod. This doesn't necessarily mean the mod is malicious.",
                    Severity.Low)
                {
                    RuleId = "AssemblyScanner"
                });
            }

            return FilterEmptyFindings(findings);
        }

        private void ScanAssembly(AssemblyDefinition assembly, List<ScanFinding> findings)
        {
            foreach (var module in assembly.Modules)
            {
                // Scan assembly metadata for hidden payloads
                if (_config.DetectAssemblyMetadata)
                {
                    findings.AddRange(_metadataScanner.ScanAssemblyMetadata(assembly));
                }

                // Scan for P/Invoke declarations - these are registered with CallGraphBuilder
                // and findings are generated later in BuildCallChainFindings()
                _dllImportScanner.ScanForDllImports(module);

                foreach (var type in module.Types)
                {
                    findings.AddRange(_typeScanner.ScanType(type));

                    // Phase 1: Analyze data flow for each method in the type (single-method analysis)
                    foreach (var method in type.Methods)
                    {
                        _dataFlowAnalyzer.AnalyzeMethod(method);
                    }
                }
            }

            // Phase 2: Analyze cross-method data flows after all methods have been processed
            _dataFlowAnalyzer.AnalyzeCrossMethodFlows();

            // Phase 3: Allow rules to refine findings using post-analysis information
            // (e.g., recursive embedded resource scanning, DataFlowAnalyzer chain correlation)
            foreach (var module in assembly.Modules)
            {
                foreach (var rule in _rules)
                {
                    var refinedFindings = rule.PostAnalysisRefine(module, findings);
                    findings.AddRange(refinedFindings);
                }
            }

            // Phase 4: Deep behavior analysis (if enabled)
            // Run practical behavior correlation on flagged methods.
            if (_config.DeepAnalysis.EnableDeepAnalysis)
            {
                RunDeepBehaviorAnalysis(assembly, findings);
            }
        }

        /// <summary>
        /// Runs deep behavior analysis on methods flagged by quick scan.
        /// </summary>
        private void RunDeepBehaviorAnalysis(AssemblyDefinition assembly, List<ScanFinding> findings)
        {
            foreach (var module in assembly.Modules)
            {
                foreach (var type in module.Types)
                {
                    var typeFindings = GetTypeFindings(findings, type);
                    var namespaceFindings = GetNamespaceFindings(findings, type.Namespace);

                    foreach (var method in type.Methods)
                    {
                        if (method.Body == null)
                            continue;

                        var methodFindings = GetMethodFindings(findings, method);
                        var scopedFindings = methodFindings.Concat(typeFindings).Concat(namespaceFindings).ToList();
                        var signals = BuildMethodSignals(scopedFindings);

                        if (_deepBehaviorOrchestrator.ShouldDeepScan(method, signals, scopedFindings))
                        {
                            var deepFindings = _deepBehaviorOrchestrator.AnalyzeMethod(method, signals, methodFindings, typeFindings, namespaceFindings);

                            if (!_config.DeepAnalysis.EmitDiagnosticFindings)
                            {
                                continue;
                            }

                            if (_config.DeepAnalysis.RequireCorrelatedBaseFinding &&
                                !HasCorrelatedBaseFinding(scopedFindings, signals))
                            {
                                continue;
                            }

                            findings.AddRange(deepFindings);
                        }
                    }
                }
            }
        }

        private static List<ScanFinding> GetMethodFindings(IEnumerable<ScanFinding> findings, MethodDefinition method)
        {
            var methodPrefix = method.DeclaringType?.FullName + "." + method.Name;
            return findings
                .Where(f => f.Location.StartsWith(methodPrefix, StringComparison.Ordinal))
                .ToList();
        }

        private static List<ScanFinding> GetTypeFindings(IEnumerable<ScanFinding> findings, TypeDefinition type)
        {
            var typePrefix = type.FullName + ".";
            return findings
                .Where(f => f.Location.StartsWith(typePrefix, StringComparison.Ordinal))
                .ToList();
        }

        private static List<ScanFinding> GetNamespaceFindings(IEnumerable<ScanFinding> findings, string? @namespace)
        {
            if (string.IsNullOrWhiteSpace(@namespace))
            {
                return new List<ScanFinding>();
            }

            var namespacePrefix = @namespace + ".";
            return findings
                .Where(f => f.Location.StartsWith(namespacePrefix, StringComparison.Ordinal))
                .ToList();
        }

        private static MethodSignals BuildMethodSignals(IEnumerable<ScanFinding> methodFindings)
        {
            var findings = methodFindings.ToList();
            var signals = new MethodSignals
            {
                HasSuspiciousReflection = findings.Any(f =>
                    f.RuleId == "ReflectionRule" ||
                    f.Description.Contains("reflection invocation", StringComparison.OrdinalIgnoreCase) ||
                    f.Description.Contains("Activator::CreateInstance", StringComparison.OrdinalIgnoreCase)),
                HasEncodedStrings = findings.Any(f => f.RuleId != null && DeepBehaviorRuleSets.EncodedRuleIds.Contains(f.RuleId)),
                HasBase64 = findings.Any(f => f.RuleId == "Base64Rule"),
                HasProcessLikeCall = findings.Any(f => f.RuleId == "ProcessStartRule" || f.RuleId == "Shell32Rule"),
                HasNetworkCall = findings.Any(f => f.RuleId == "DataExfiltrationRule" || f.RuleId == "DataInfiltrationRule"),
                HasFileWrite = findings.Any(f => f.Description.Contains("write", StringComparison.OrdinalIgnoreCase)),
                UsesSensitiveFolder = findings.Any(f => f.RuleId == "EnvironmentPathRule"),
                HasPathManipulation = findings.Any(f =>
                    f.Description.Contains("path", StringComparison.OrdinalIgnoreCase) ||
                    f.RuleId == "EnvironmentPathRule")
            };

            foreach (var finding in findings)
            {
                if (!string.IsNullOrEmpty(finding.RuleId))
                {
                    signals.MarkRuleTriggered(finding.RuleId);
                }
            }

            return signals;
        }

        private static bool HasCorrelatedBaseFinding(IEnumerable<ScanFinding> methodFindings, MethodSignals signals)
        {
            if (signals.IsCriticalCombination() || signals.IsHighRiskCombination())
            {
                return true;
            }

            foreach (var finding in methodFindings)
            {
                if (finding.RuleId == null)
                {
                    continue;
                }

                if (!DeepCorrelationRuleIds.Contains(finding.RuleId))
                {
                    continue;
                }

                if (finding.Severity >= Severity.High)
                {
                    return true;
                }
            }

            return false;
        }

        private static IEnumerable<ScanFinding> FilterEmptyFindings(List<ScanFinding> findings)
        {
            // Filter out single low-severity warning when nothing else was found
            if (findings.Count == 1 &&
                findings[0].Location == "Assembly scanning" &&
                string.IsNullOrEmpty(findings[0].CodeSnippet))
            {
                return new List<ScanFinding>();
            }

            return findings;
        }
    }
}
