using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Diagnostics;
using Mono.Cecil;

namespace MLVScan.Services
{
    /// <summary>
    /// Core assembly scanner that analyzes .NET assemblies for malicious patterns.
    /// Supports both file-based and stream-based scanning.
    /// </summary>
    public class AssemblyScanner : Abstractions.IAssemblyScanner
    {
        private static readonly HashSet<string> ExecutionCorrelationRuleIds = new(StringComparer.Ordinal)
        {
            "DllImportRule",
            "ProcessStartRule",
            "Shell32Rule"
        };

        private readonly IEnumerable<IScanRule> _rules;
        private readonly TypeScanner _typeScanner;
        private readonly MetadataScanner _metadataScanner;
        private readonly DllImportScanner _dllImportScanner;
        private readonly CallGraphBuilder _callGraphBuilder;
        private readonly DataFlowAnalyzer _dataFlowAnalyzer;
        private readonly IAssemblyResolverProvider _resolverProvider;
        private readonly ScanConfig _config;
        private readonly ScanTelemetryHub _telemetry;

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
            _telemetry = new ScanTelemetryHub();

            // Create all services using composition
            var snippetBuilder = new CodeSnippetBuilder();
            var signalTracker = new SignalTracker(_config);
            var stringPatternDetector = new StringPatternDetector();

            // Create call graph builder for finding consolidation
            _callGraphBuilder = new CallGraphBuilder(rules, snippetBuilder, entryPointProvider);

            // Create data flow analyzer for tracking data movement through operations
            _dataFlowAnalyzer = new DataFlowAnalyzer(rules, snippetBuilder, _telemetry);

            var reflectionDetector =
                new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
            var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector,
                stringPatternDetector, snippetBuilder, _config, _telemetry, _callGraphBuilder);
            var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, _config);
            var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, _config);
            var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder,
                localVariableAnalyzer, exceptionHandlerAnalyzer, _config, _telemetry);
            var propertyEventScanner = new PropertyEventScanner(methodScanner, _config);

            _typeScanner = new TypeScanner(methodScanner, signalTracker, reflectionDetector, snippetBuilder,
                propertyEventScanner, rules, _config, _telemetry);
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

            var assemblyId = CreateAssemblyTelemetryId(assemblyPath);
            _telemetry.BeginAssembly(assemblyId);
            _telemetry.IncrementCounter("Assemblies.Scanned");
            var totalStart = _telemetry.StartTimestamp();
            var findings = new List<ScanFinding>();

            try
            {
                // Clear builders for fresh scan
                _callGraphBuilder.Clear();
                _dataFlowAnalyzer.Clear();

                var readerParameters = new ReaderParameters
                {
                    ReadWrite = false,
                    InMemory = true,
                    ReadSymbols = false,
                    AssemblyResolver = _resolverProvider.CreateResolver(),
                };

                var readAssemblyStart = _telemetry.StartTimestamp();
                using var assembly = AssemblyDefinition.ReadAssembly(assemblyPath, readerParameters);
                _telemetry.AddPhaseElapsed("AssemblyScanner.ReadAssembly", readAssemblyStart);
                var scanAssemblyStart = _telemetry.StartTimestamp();
                ScanAssembly(assembly, findings);
                _telemetry.AddPhaseElapsed("AssemblyScanner.ScanAssembly", scanAssemblyStart);

                // Build consolidated call chain findings
                var callChainStart = _telemetry.StartTimestamp();
                var callChainFindings = _callGraphBuilder.BuildCallChainFindings();
                _telemetry.AddPhaseElapsed("AssemblyScanner.BuildCallChainFindings", callChainStart);
                findings.AddRange(callChainFindings);

                // Build data flow findings
                var dataFlowFindingsStart = _telemetry.StartTimestamp();
                var dataFlowFindings = _dataFlowAnalyzer.BuildDataFlowFindings();
                _telemetry.AddPhaseElapsed("AssemblyScanner.BuildDataFlowFindings", dataFlowFindingsStart);
                findings.AddRange(dataFlowFindings);

                var correlationStart = _telemetry.StartTimestamp();
                CorrelateDataFlowIntoExecutionFindings(findings);
                _telemetry.AddPhaseElapsed("AssemblyScanner.CorrelateDataFlowIntoExecutionFindings",
                    correlationStart);
            }
            catch (Exception)
            {
                findings.Add(new ScanFinding(
                    "Assembly scanning",
                    "Warning: Some parts of the assembly could not be scanned. This doesn't necessarily mean the mod is malicious.",
                    Severity.Low) { RuleId = "AssemblyScanner" });
            }

            _telemetry.AddPhaseElapsed("AssemblyScanner.Total", totalStart);
            var filteredFindings = FilterEmptyFindings(findings).ToList();
            _telemetry.CompleteAssembly(findings.Count, filteredFindings.Count);
            return filteredFindings;
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

            var assemblyId = CreateStreamTelemetryId(virtualPath);
            _telemetry.BeginAssembly(assemblyId);
            _telemetry.IncrementCounter("Assemblies.Scanned");
            var totalStart = _telemetry.StartTimestamp();
            var findings = new List<ScanFinding>();

            try
            {
                // Clear builders for fresh scan
                _callGraphBuilder.Clear();
                _dataFlowAnalyzer.Clear();

                var readerParameters = new ReaderParameters
                {
                    ReadWrite = false,
                    InMemory = true,
                    ReadSymbols = false,
                    AssemblyResolver = _resolverProvider.CreateResolver(),
                };

                var readAssemblyStart = _telemetry.StartTimestamp();
                using var assembly = AssemblyDefinition.ReadAssembly(assemblyStream, readerParameters);
                _telemetry.AddPhaseElapsed("AssemblyScanner.ReadAssembly", readAssemblyStart);
                var scanAssemblyStart = _telemetry.StartTimestamp();
                ScanAssembly(assembly, findings);
                _telemetry.AddPhaseElapsed("AssemblyScanner.ScanAssembly", scanAssemblyStart);

                // Build consolidated call chain findings
                var callChainStart = _telemetry.StartTimestamp();
                var callChainFindings = _callGraphBuilder.BuildCallChainFindings();
                _telemetry.AddPhaseElapsed("AssemblyScanner.BuildCallChainFindings", callChainStart);
                findings.AddRange(callChainFindings);

                // Build data flow findings
                var dataFlowFindingsStart = _telemetry.StartTimestamp();
                var dataFlowFindings = _dataFlowAnalyzer.BuildDataFlowFindings();
                _telemetry.AddPhaseElapsed("AssemblyScanner.BuildDataFlowFindings", dataFlowFindingsStart);
                findings.AddRange(dataFlowFindings);

                var correlationStart = _telemetry.StartTimestamp();
                CorrelateDataFlowIntoExecutionFindings(findings);
                _telemetry.AddPhaseElapsed("AssemblyScanner.CorrelateDataFlowIntoExecutionFindings",
                    correlationStart);
            }
            catch (Exception)
            {
                findings.Add(new ScanFinding(
                    virtualPath ?? "Assembly scanning",
                    "Warning: Some parts of the assembly could not be scanned. Please ensure this is a valid managed .NET assembly. This doesn't necessarily mean the assembly is malicious.",
                    Severity.Low) { RuleId = "AssemblyScanner" });
            }

            _telemetry.AddPhaseElapsed("AssemblyScanner.Total", totalStart);
            var filteredFindings = FilterEmptyFindings(findings).ToList();
            _telemetry.CompleteAssembly(findings.Count, filteredFindings.Count);
            return filteredFindings;
        }

        private void ScanAssembly(AssemblyDefinition assembly, List<ScanFinding> findings)
        {
            if (_config.DetectAssemblyMetadata)
            {
                var metadataStart = _telemetry.StartTimestamp();
                findings.AddRange(_metadataScanner.ScanAssemblyMetadata(assembly));
                _telemetry.AddPhaseElapsed("AssemblyScanner.MetadataScanner", metadataStart);
            }

            foreach (var module in assembly.Modules)
            {
                _telemetry.IncrementCounter("Assembly.ModulesScanned");
                _telemetry.IncrementCounter("Assembly.TopLevelTypesScanned", module.Types.Count);

                // Scan for P/Invoke declarations - these are registered with CallGraphBuilder
                // and findings are generated later in BuildCallChainFindings()
                var dllImportStart = _telemetry.StartTimestamp();
                _dllImportScanner.ScanForDllImports(module);
                _telemetry.AddPhaseElapsed("AssemblyScanner.DllImportScanner", dllImportStart);

                foreach (var type in module.Types)
                {
                    var typeScanStart = _telemetry.StartTimestamp();
                    findings.AddRange(_typeScanner.ScanType(type));
                    _telemetry.AddPhaseElapsed("AssemblyScanner.TypeScanner", typeScanStart);

                    // Phase 1: Analyze data flow for each method in the type (single-method analysis)
                    foreach (var method in EnumerateMethodsRecursively(type))
                    {
                        var dataFlowMethodStart = _telemetry.StartTimestamp();
                        _dataFlowAnalyzer.AnalyzeMethod(method);
                        _telemetry.AddPhaseElapsed("AssemblyScanner.DataFlowAnalyzeMethod",
                            dataFlowMethodStart);
                    }
                }
            }

            // Phase 2: Analyze cross-method data flows after all methods have been processed
            var crossMethodStart = _telemetry.StartTimestamp();
            _dataFlowAnalyzer.AnalyzeCrossMethodFlows();
            _telemetry.AddPhaseElapsed("AssemblyScanner.DataFlowAnalyzeCrossMethodFlows", crossMethodStart);

            // Phase 3: Allow rules to refine findings using post-analysis information
            // (e.g., recursive embedded resource scanning, DataFlowAnalyzer chain correlation)
            foreach (var module in assembly.Modules)
            {
                foreach (var rule in _rules)
                {
                    _telemetry.IncrementCounter("Assembly.PostAnalysisRuleInvocations");
                    var postAnalysisStart = _telemetry.StartTimestamp();
                    var refinedFindings = rule.PostAnalysisRefine(module, findings);
                    _telemetry.AddPhaseElapsed("AssemblyScanner.PostAnalysisRefine", postAnalysisStart);
                    findings.AddRange(refinedFindings);
                }
            }
        }

        private static IEnumerable<MethodDefinition> EnumerateMethodsRecursively(TypeDefinition type)
        {
            foreach (var method in type.Methods)
            {
                yield return method;
            }

            foreach (var nestedType in type.NestedTypes)
            {
                foreach (var method in EnumerateMethodsRecursively(nestedType))
                {
                    yield return method;
                }
            }
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

        internal static string CreateAssemblyTelemetryId(string assemblyPath)
        {
            return GetPathLeaf(assemblyPath);
        }

        internal static string CreateStreamTelemetryId(string? virtualPath)
        {
            if (string.IsNullOrWhiteSpace(virtualPath))
            {
                return "<stream>";
            }

            if (IsAbsoluteLikePath(virtualPath))
            {
                return GetPathLeaf(virtualPath);
            }

            return virtualPath;
        }

        private static bool IsAbsoluteLikePath(string path)
        {
            if (Path.IsPathRooted(path))
            {
                return true;
            }

            if (path.Length >= 3 &&
                char.IsLetter(path[0]) &&
                path[1] == ':' &&
                (path[2] == Path.DirectorySeparatorChar ||
                 path[2] == Path.AltDirectorySeparatorChar ||
                 path[2] == '\\' ||
                 path[2] == '/'))
            {
                return true;
            }

            return path.StartsWith(@"\\", StringComparison.Ordinal) ||
                   path.StartsWith("//", StringComparison.Ordinal);
        }

        private static string GetPathLeaf(string path)
        {
            int separatorIndex = Math.Max(path.LastIndexOf('/'), path.LastIndexOf('\\'));
            return separatorIndex >= 0 ? path[(separatorIndex + 1)..] : path;
        }

        internal ScanProfileSnapshot? GetLastProfileSnapshot()
        {
            return _telemetry.GetLastSnapshot();
        }

        private static void CorrelateDataFlowIntoExecutionFindings(List<ScanFinding> findings)
        {
            if (findings.Count == 0)
            {
                return;
            }

            var dataFlowFindings = findings
                .Where(f => f.RuleId == "DataFlowAnalysis" && f.HasDataFlow)
                .ToList();

            if (dataFlowFindings.Count == 0)
            {
                return;
            }

            var mergedDataFlowFindings = new HashSet<ScanFinding>();

            foreach (var dataFlowFinding in dataFlowFindings)
            {
                var dataFlowChain = dataFlowFinding.DataFlowChain;
                if (dataFlowChain == null)
                {
                    continue;
                }

                var executionSink = dataFlowChain.Nodes.FirstOrDefault(node =>
                    node.NodeType == DataFlowNodeType.Sink && IsExecutionSinkOperation(node.Operation));

                if (executionSink == null)
                {
                    continue;
                }

                var sinkMethodLocation = TrimOffset(executionSink.Location);
                if (string.IsNullOrWhiteSpace(sinkMethodLocation))
                {
                    continue;
                }

                int? sinkOffset = ExtractOffset(executionSink.Location);

                var correlatedExecutionFinding = findings
                    .Where(f =>
                        f != dataFlowFinding &&
                        f.RuleId != null &&
                        ExecutionCorrelationRuleIds.Contains(f.RuleId) &&
                        string.Equals(TrimOffset(f.Location), sinkMethodLocation, StringComparison.Ordinal))
                    .OrderByDescending(f =>
                        sinkOffset.HasValue &&
                        ExtractOffset(f.Location).HasValue &&
                        ExtractOffset(f.Location) == sinkOffset)
                    .ThenByDescending(f => f.Severity)
                    .FirstOrDefault();

                if (correlatedExecutionFinding == null)
                {
                    continue;
                }

                correlatedExecutionFinding.DataFlowChain = dataFlowChain;

                if (dataFlowFinding.Severity > correlatedExecutionFinding.Severity)
                {
                    correlatedExecutionFinding.Severity = dataFlowFinding.Severity;
                }

                if (!correlatedExecutionFinding.Description.Contains("Correlated data flow:",
                        StringComparison.OrdinalIgnoreCase))
                {
                    correlatedExecutionFinding.Description +=
                        $" Correlated data flow: {dataFlowChain.Summary}.";
                }

                mergedDataFlowFindings.Add(dataFlowFinding);
            }

            if (mergedDataFlowFindings.Count > 0)
            {
                findings.RemoveAll(f => mergedDataFlowFindings.Contains(f));
            }
        }

        private static bool IsExecutionSinkOperation(string operation)
        {
            if (string.IsNullOrWhiteSpace(operation))
            {
                return false;
            }

            return operation.Contains("Process.Start", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("PInvoke.ShellExecute", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("PInvoke.CreateProcess", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("PInvoke.WinExec", StringComparison.OrdinalIgnoreCase);
        }

        private static string TrimOffset(string location)
        {
            if (string.IsNullOrWhiteSpace(location))
            {
                return location;
            }

            int lastColon = location.LastIndexOf(':');
            if (lastColon < 0 || lastColon == location.Length - 1)
            {
                return location;
            }

            var suffix = location[(lastColon + 1)..];
            return int.TryParse(suffix, out _) ? location[..lastColon] : location;
        }

        private static int? ExtractOffset(string location)
        {
            if (string.IsNullOrWhiteSpace(location))
            {
                return null;
            }

            int lastColon = location.LastIndexOf(':');
            if (lastColon < 0 || lastColon == location.Length - 1)
            {
                return null;
            }

            var suffix = location[(lastColon + 1)..];
            return int.TryParse(suffix, out int offset) ? offset : null;
        }
    }
}
