using System.Text;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    /// <summary>
    /// Configuration for cross-method data flow analysis.
    /// </summary>
    public class DataFlowAnalyzerConfig
    {
        /// <summary>
        /// Enable cross-method data flow analysis (traces data across method boundaries).
        /// </summary>
        public bool EnableCrossMethodAnalysis { get; set; } = true;

        /// <summary>
        /// Maximum depth for cross-method call chain analysis (higher = more thorough but slower).
        /// </summary>
        public int MaxCallChainDepth { get; set; } = 5;

        /// <summary>
        /// Enable return value data flow tracking (callee returns data → caller uses it).
        /// </summary>
        public bool EnableReturnValueTracking { get; set; } = true;
    }

    /// <summary>
    /// Analyzes data flow through IL instructions to track how data moves between suspicious operations.
    /// Supports both single-method and cross-method data flow analysis.
    /// Helps distinguish legitimate operations from malicious attack chains.
    /// </summary>
    public class DataFlowAnalyzer
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly DataFlowAnalyzerConfig _config;

        // Phase 1: Single-method data flows (keyed by method.FullName which is unique)
        private readonly Dictionary<string, List<DataFlowChain>> _methodDataFlows = new();

        // Phase 2: Inter-method tracking
        private readonly Dictionary<string, MethodFlowInfo> _methodFlowInfos = new();
        private readonly List<DataFlowChain> _crossMethodChains = new();

        // Instruction caching for snippet building in cross-method analysis
        private readonly Dictionary<string, Mono.Collections.Generic.Collection<Instruction>> _methodInstructions = new();

        public DataFlowAnalyzer(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder)
            : this(rules, snippetBuilder, new DataFlowAnalyzerConfig())
        {
        }

        public DataFlowAnalyzer(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder, DataFlowAnalyzerConfig config)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        /// <summary>
        /// Clears all tracked data flows. Call before scanning a new assembly.
        /// </summary>
        public void Clear()
        {
            _methodDataFlows.Clear();
            _methodFlowInfos.Clear();
            _crossMethodChains.Clear();
            _methodInstructions.Clear();
        }

        /// <summary>
        /// Analyzes a method for suspicious data flow patterns (Phase 1: single-method analysis).
        /// Also tracks method calls for later cross-method analysis.
        /// Returns data flow chains that match known attack patterns.
        /// </summary>
        public List<DataFlowChain> AnalyzeMethod(MethodDefinition method)
        {
            if (method?.Body == null || method.Body.Instructions.Count == 0)
                return new List<DataFlowChain>();

            var chains = new List<DataFlowChain>();
            var instructions = method.Body.Instructions;

            // Cache instructions for cross-method snippet building
            _methodInstructions[method.FullName] = instructions;

            // Build list of interesting operations (sources, transforms, sinks)
            var interestingOps = IdentifyInterestingOperations(method, instructions);

            // Track method flow info for inter-method analysis
            var flowInfo = BuildMethodFlowInfo(method, instructions, interestingOps);
            _methodFlowInfos[method.FullName] = flowInfo;

            if (interestingOps.Count < 2)
            {
                // Even with < 2 ops, we still track the method for cross-method flows
                var methodKey = method.FullName;
                _methodDataFlows[methodKey] = chains;
                return chains;
            }

            // Try to build data flow chains by tracking local variables
            chains.AddRange(BuildDataFlowChains(method, instructions, interestingOps));

            // Cache the results using FullName (which is unique: includes return type, params)
            _methodDataFlows[method.FullName] = chains;

            return chains;
        }

        /// <summary>
        /// Performs Phase 2 analysis: connects data flows across method boundaries.
        /// Call this after all methods have been analyzed with AnalyzeMethod.
        /// </summary>
        public void AnalyzeCrossMethodFlows()
        {
            if (!_config.EnableCrossMethodAnalysis)
            {
                return;
            }

            // Find methods that pass data to other methods with dangerous operations (direct calls)
            foreach (var (callerKey, callerInfo) in _methodFlowInfos)
            {
                foreach (var callSite in callerInfo.OutgoingCalls)
                {
                    // Check if the called method has interesting operations
                    if (_methodFlowInfos.TryGetValue(callSite.TargetMethodKey, out var calleeInfo))
                    {
                        // Try to connect data flows across the call boundary
                        var crossMethodChain = TryBuildCrossMethodChain(callerInfo, callSite, calleeInfo);
                        if (crossMethodChain != null && crossMethodChain.IsSuspicious)
                        {
                            _crossMethodChains.Add(crossMethodChain);
                        }

                        // Try to connect return value flows (callee returns data → caller uses it)
                        if (_config.EnableReturnValueTracking &&
                            callSite.CalledMethodReturnsData &&
                            callSite.ReturnValueUsed)
                        {
                            var returnFlowChain = TryBuildReturnValueChain(callerInfo, callSite, calleeInfo);
                            if (returnFlowChain != null && returnFlowChain.IsSuspicious)
                            {
                                _crossMethodChains.Add(returnFlowChain);
                            }
                        }
                    }
                }
            }

            // Perform deep call chain analysis (A → B → C patterns)
            if (_config.MaxCallChainDepth > 2)
            {
                AnalyzeDeepCallChains();
            }
        }

        /// <summary>
        /// Builds consolidated findings from all tracked data flows.
        /// Includes both single-method and cross-method chains.
        /// </summary>
        public IEnumerable<ScanFinding> BuildDataFlowFindings()
        {
            var findings = new List<ScanFinding>();

            // Single-method findings
            foreach (var (methodKey, chains) in _methodDataFlows)
            {
                foreach (var chain in chains.Where(c => c.IsSuspicious))
                {
                    var finding = CreateDataFlowFinding(chain);
                    findings.Add(finding);
                }
            }

            // Cross-method findings
            foreach (var chain in _crossMethodChains.Where(c => c.IsSuspicious))
            {
                var finding = CreateDataFlowFinding(chain);
                findings.Add(finding);
            }

            return findings;
        }

        /// <summary>
        /// Gets the count of tracked data flow chains (single-method only).
        /// </summary>
        public int DataFlowChainCount => _methodDataFlows.Values.Sum(list => list.Count);

        /// <summary>
        /// Gets the count of suspicious data flow chains (single-method only).
        /// </summary>
        public int SuspiciousChainCount => _methodDataFlows.Values.SelectMany(list => list).Count(c => c.IsSuspicious);

        /// <summary>
        /// Gets the count of cross-method data flow chains.
        /// </summary>
        public int CrossMethodChainCount => _crossMethodChains.Count;

        /// <summary>
        /// Gets the count of suspicious cross-method chains.
        /// </summary>
        public int SuspiciousCrossMethodChainCount => _crossMethodChains.Count(c => c.IsSuspicious);

        private List<InterestingOperation> IdentifyInterestingOperations(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            var operations = new List<InterestingOperation>();

            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];

                // Check for method calls
                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                    instruction.Operand is MethodReference calledMethod)
                {
                    var opInfo = ClassifyOperation(calledMethod, instructions, i);
                    if (opInfo != null)
                    {
                        operations.Add(new InterestingOperation
                        {
                            Instruction = instruction,
                            InstructionIndex = i,
                            MethodReference = calledMethod,
                            NodeType = opInfo.Value.NodeType,
                            Operation = opInfo.Value.Operation,
                            DataDescription = opInfo.Value.DataDescription,
                            LocalVariableIndex = TryGetTargetLocalVariable(instructions, i)
                        });
                    }
                }
            }

            return operations;
        }

        private (DataFlowNodeType NodeType, string Operation, string DataDescription)? ClassifyOperation(
            MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int index)
        {
            var declType = method.DeclaringType?.FullName ?? "";
            var methodName = method.Name;

            // Source operations (where data originates)
            if (IsNetworkSource(declType, methodName))
                return (DataFlowNodeType.Source, $"{method.DeclaringType?.Name}.{methodName}", "byte[]/string (network data)");

            if (IsFileSource(declType, methodName))
                return (DataFlowNodeType.Source, $"{method.DeclaringType?.Name}.{methodName}", "byte[]/string (file data)");

            if (IsRegistrySource(declType, methodName))
                return (DataFlowNodeType.Source, $"{method.DeclaringType?.Name}.{methodName}", "string (registry data)");

            if (IsResourceSource(declType, methodName))
                return (DataFlowNodeType.Source, $"{method.DeclaringType?.Name}.{methodName}", "stream/byte[] (embedded resource)");

            // Transform operations (data is modified)
            if (IsBase64Decode(declType, methodName))
                return (DataFlowNodeType.Transform, "Convert.FromBase64String", "byte[] (decoded)");

            if (IsEncoding(declType, methodName))
                return (DataFlowNodeType.Transform, $"{method.DeclaringType?.Name}.{methodName}", "byte[]/string (encoded)");

            if (IsCryptoOperation(declType, methodName))
                return (DataFlowNodeType.Transform, $"{method.DeclaringType?.Name}.{methodName}", "byte[] (crypto operation)");

            if (IsCompressionOperation(declType, methodName))
                return (DataFlowNodeType.Transform, $"{method.DeclaringType?.Name}.{methodName}", "byte[]/stream (decompressed)");

            if (IsStreamMaterialization(declType, methodName))
                return (DataFlowNodeType.Transform, $"{method.DeclaringType?.Name}.{methodName}", "byte[] (materialized from stream)");

            // Sink operations (where data is consumed in a dangerous way)
            if (IsAssemblyLoad(declType, methodName))
                return (DataFlowNodeType.Sink, $"{method.DeclaringType?.Name}.{methodName}", "Assembly (dynamic code loaded)");

            if (IsNativeExecutionSink(method))
                return (DataFlowNodeType.Sink, GetNativeExecutionOperationName(method), "Executes native shell/process");

            if (IsProcessStart(declType, methodName))
                return (DataFlowNodeType.Sink, "Process.Start", "Executes process");

            if (IsFileSink(declType, methodName))
                return (DataFlowNodeType.Sink, $"{method.DeclaringType?.Name}.{methodName}", "Writes to file");

            if (IsFileStreamSink(declType, methodName))
                return (DataFlowNodeType.Sink, $"{method.DeclaringType?.Name}.{methodName}", "Writes to file");

            if (IsNetworkSink(declType, methodName))
                return (DataFlowNodeType.Sink, $"{method.DeclaringType?.Name}.{methodName}", "Sends to network");

            if (IsRegistrySink(declType, methodName))
                return (DataFlowNodeType.Sink, $"{method.DeclaringType?.Name}.{methodName}", "Writes to registry");

            return null;
        }

        private List<DataFlowChain> BuildDataFlowChains(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            List<InterestingOperation> operations)
        {
            var chains = new List<DataFlowChain>();

            // Group operations by local variable (simple data flow tracking)
            var operationsByVariable = operations
                .Where(op => op.LocalVariableIndex.HasValue)
                .GroupBy(op => op.LocalVariableIndex!.Value)
                .Where(g => g.Count() > 1) // At least 2 operations on same variable
                .ToList();

            foreach (var group in operationsByVariable)
            {
                var opsInChain = group.OrderBy(op => op.InstructionIndex).ToList();

                // Check if we have a source and a sink (minimum for interesting flow)
                var hasSource = opsInChain.Any(op => op.NodeType == DataFlowNodeType.Source);
                var hasSink = opsInChain.Any(op => op.NodeType == DataFlowNodeType.Sink);
                var hasTransform = opsInChain.Any(op => op.NodeType == DataFlowNodeType.Transform);

                if ((hasSource || hasTransform) && hasSink)
                {
                    var chain = BuildChain(method, instructions, opsInChain);
                    chains.Add(chain);
                }
            }

            // Also look for sequential suspicious operations (even without variable tracking)
            chains.AddRange(BuildSequentialChains(method, instructions, operations));

            return chains;
        }

        private List<DataFlowChain> BuildSequentialChains(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            List<InterestingOperation> operations)
        {
            var chains = new List<DataFlowChain>();

            // Look for patterns like: Network call → Base64 decode → File write → Process start
            // within a reasonable instruction window (< 100 instructions apart)
            const int maxInstructionDistance = 100;

            for (int i = 0; i < operations.Count - 1; i++)
            {
                var op1 = operations[i];

                // Find operations that come shortly after this one
                var subsequentOps = operations
                    .Skip(i + 1)
                    .Where(op => op.InstructionIndex - op1.InstructionIndex <= maxInstructionDistance)
                    .ToList();

                if (subsequentOps.Count == 0)
                    continue;

                // Check for suspicious sequential patterns
                var chainOps = new List<InterestingOperation> { op1 };
                chainOps.AddRange(subsequentOps.Take(5)); // Limit chain length

                // Only create chain if it has a dangerous sink
                if (chainOps.Any(op => op.NodeType == DataFlowNodeType.Sink))
                {
                    var pattern = RecognizePattern(chainOps);
                    if (pattern != DataFlowPattern.Legitimate && pattern != DataFlowPattern.Unknown)
                    {
                        var chain = BuildChain(method, instructions, chainOps);
                        chains.Add(chain);
                    }
                }
            }

            return chains;
        }

        private DataFlowChain BuildChain(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            List<InterestingOperation> operations)
        {
            var pattern = RecognizePattern(operations);
            var severity = DetermineSeverity(pattern, operations);
            var confidence = CalculateConfidence(pattern, operations);
            var summary = BuildSummary(pattern, operations);
            var methodLocation = $"{method.DeclaringType?.FullName}.{method.Name}";

            var chainId = $"{methodLocation}:{string.Join("-", operations.Select(op => op.Instruction.Offset))}";
            var chain = new DataFlowChain(chainId, pattern, severity, confidence, summary, methodLocation);

            foreach (var op in operations)
            {
                var snippet = _snippetBuilder.BuildSnippet(instructions, op.InstructionIndex, 1);
                var location = $"{methodLocation}:{op.Instruction.Offset}";

                var node = new DataFlowNode(
                    location,
                    op.Operation,
                    op.NodeType,
                    op.DataDescription,
                    op.Instruction.Offset,
                    snippet
                );

                chain.AppendNode(node);
            }

            return chain;
        }

        private DataFlowPattern RecognizePattern(List<InterestingOperation> operations)
        {
            var nodeTypes = operations.Select(op => op.NodeType).ToList();
            var opNames = operations.Select(op => op.Operation.ToLowerInvariant()).ToList();

            _ = nodeTypes;
            _ = opNames;

            // Embedded resource dropper: Resource stream -> file write -> native execution sink.
            if (HasResourceSource(operations) &&
                HasProcessStart(operations) &&
                (HasFileWrite(operations) || HasTransform(operations)))
            {
                return DataFlowPattern.EmbeddedResourceDropAndExecute;
            }

            // Download and Execute: Network → [Transform] → File Write → Process.Start
            if (HasNetworkSource(operations) &&
                HasFileWrite(operations) &&
                HasProcessStart(operations))
            {
                return DataFlowPattern.DownloadAndExecute;
            }

            // Data Exfiltration: File/Registry Read → [Transform] → Network Send
            if ((HasFileSource(operations) || HasRegistrySource(operations)) &&
                HasNetworkSink(operations))
            {
                return DataFlowPattern.DataExfiltration;
            }

            // Dynamic Code Loading: Network/File → Decode → Assembly.Load
            if ((HasNetworkSource(operations) || HasFileSource(operations)) &&
                HasAssemblyLoad(operations))
            {
                return DataFlowPattern.DynamicCodeLoading;
            }

            // Credential Theft: Sensitive path read → Network
            if (HasFileSource(operations) && HasNetworkSink(operations))
            {
                return DataFlowPattern.CredentialTheft;
            }

            // Obfuscated Persistence: Encode → Registry/Startup write
            if (HasTransform(operations) && HasRegistrySink(operations))
            {
                return DataFlowPattern.ObfuscatedPersistence;
            }

            // Remote Config Load: Network → Parse (no dangerous sink)
            if (HasNetworkSource(operations) && !HasDangerousSink(operations))
            {
                return DataFlowPattern.RemoteConfigLoad;
            }

            return DataFlowPattern.Unknown;
        }

        private Severity DetermineSeverity(DataFlowPattern pattern, List<InterestingOperation> operations)
        {
            return pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => Severity.Critical,
                DataFlowPattern.DownloadAndExecute => Severity.Critical,
                DataFlowPattern.DataExfiltration => Severity.Critical,
                DataFlowPattern.DynamicCodeLoading => Severity.Critical,
                DataFlowPattern.CredentialTheft => Severity.Critical,
                DataFlowPattern.ObfuscatedPersistence => Severity.High,
                DataFlowPattern.RemoteConfigLoad => Severity.Medium,
                _ => Severity.Low
            };
        }

        private double CalculateConfidence(DataFlowPattern pattern, List<InterestingOperation> operations)
        {
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
                return 0.5;

            // Base confidence
            double confidence = 0.7;

            // Increase confidence based on chain length
            if (operations.Count >= 3)
                confidence += 0.1;

            if (operations.Count >= 4)
                confidence += 0.1;

            // Increase confidence if we have all three types (source, transform, sink)
            var hasAllTypes = operations.Any(op => op.NodeType == DataFlowNodeType.Source) &&
                             operations.Any(op => op.NodeType == DataFlowNodeType.Transform) &&
                             operations.Any(op => op.NodeType == DataFlowNodeType.Sink);

            if (hasAllTypes)
                confidence += 0.1;

            return Math.Min(confidence, 1.0);
        }

        private string BuildSummary(DataFlowPattern pattern, List<InterestingOperation> operations)
        {
            var summary = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute =>
                    "Suspicious data flow: Extracts embedded resource to disk and executes it via native shell API",
                DataFlowPattern.DownloadAndExecute =>
                    "Suspicious data flow: Downloads data from network, processes it, and executes as a program",
                DataFlowPattern.DataExfiltration =>
                    "Suspicious data flow: Reads sensitive data and sends it over the network",
                DataFlowPattern.DynamicCodeLoading =>
                    "Suspicious data flow: Loads and executes code dynamically at runtime",
                DataFlowPattern.CredentialTheft =>
                    "Suspicious data flow: Accesses files and sends data to network (potential credential theft)",
                DataFlowPattern.ObfuscatedPersistence =>
                    "Suspicious data flow: Encodes data before writing to registry (persistence with obfuscation)",
                DataFlowPattern.RemoteConfigLoad =>
                    "Data flow: Downloads configuration from network",
                _ => "Suspicious data flow detected"
            };

            return $"{summary} ({operations.Count} operations)";
        }

        private ScanFinding CreateDataFlowFinding(DataFlowChain chain)
        {
            var finding = new ScanFinding(
                chain.MethodLocation,
                chain.ToDetailedDescription(),
                chain.Severity,
                chain.ToCombinedCodeSnippet()
            );

            finding.RuleId = "DataFlowAnalysis";
            finding.DataFlowChain = chain;

            return finding;
        }

        // Helper methods for pattern recognition
        private bool HasNetworkSource(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Source &&
                         (op.Operation.Contains("Http") || op.Operation.Contains("Web") || op.Operation.Contains("Network")));

        private bool HasFileSource(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Source && op.Operation.Contains("File"));

        private bool HasRegistrySource(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Source && op.Operation.Contains("Registry"));

        private bool HasResourceSource(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Source &&
                         (op.Operation.Contains("GetManifestResourceStream", StringComparison.OrdinalIgnoreCase) ||
                          op.DataDescription.Contains("embedded resource", StringComparison.OrdinalIgnoreCase)));

        private bool HasTransform(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Transform);

        private bool HasFileWrite(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Sink &&
                         ((op.Operation.Contains("Write") || op.Operation.Contains("Create")) && op.Operation.Contains("File") ||
                          op.Operation.Contains("FileStream", StringComparison.OrdinalIgnoreCase)));

        private bool HasProcessStart(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Sink &&
                         (op.Operation.Contains("Process.Start", StringComparison.OrdinalIgnoreCase) ||
                          op.Operation.Contains("PInvoke.ShellExecute", StringComparison.OrdinalIgnoreCase) ||
                          op.Operation.Contains("PInvoke.CreateProcess", StringComparison.OrdinalIgnoreCase) ||
                          op.Operation.Contains("PInvoke.WinExec", StringComparison.OrdinalIgnoreCase)));

        private bool HasNetworkSink(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Sink &&
                         (op.Operation.Contains("Http") || op.Operation.Contains("Web") || op.Operation.Contains("Network")));

        private bool HasRegistrySink(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Sink && op.Operation.Contains("Registry"));

        private bool HasAssemblyLoad(List<InterestingOperation> ops) =>
            ops.Any(op => op.Operation.Contains("Assembly") && op.Operation.Contains("Load"));

        private bool HasDangerousSink(List<InterestingOperation> ops) =>
            HasProcessStart(ops) || HasFileWrite(ops) || HasRegistrySink(ops);

        // Operation classification helpers
        private bool IsNetworkSource(string declType, string methodName) =>
            (declType.StartsWith("System.Net") || declType.Contains("HttpClient") ||
             declType.Contains("WebClient") || declType.Contains("UnityWebRequest")) &&
            (methodName.Contains("Get") || methodName.Contains("Download") || methodName.Contains("Receive"));

        private bool IsFileSource(string declType, string methodName) =>
            declType.StartsWith("System.IO.File") &&
            (methodName.Contains("Read") || methodName == "ReadAllBytes" || methodName == "ReadAllText");

        private bool IsRegistrySource(string declType, string methodName) =>
            declType.Contains("Microsoft.Win32.Registry") && methodName.Contains("GetValue");

        private bool IsResourceSource(string declType, string methodName) =>
            (declType == "System.Reflection.Assembly" && methodName == "GetManifestResourceStream") ||
            (declType.Contains("ResourceManager") &&
             (methodName == "GetObject" || methodName == "GetStream"));

        private bool IsBase64Decode(string declType, string methodName) =>
            declType == "System.Convert" && methodName == "FromBase64String";

        private bool IsEncoding(string declType, string methodName) =>
            declType.Contains("System.Text.Encoding") ||
            (declType == "System.Convert" && methodName == "ToBase64String");

        private bool IsCryptoOperation(string declType, string methodName) =>
            // Crypto context creation
            (declType.Contains("System.Security.Cryptography") &&
             (methodName == "Create" || methodName == "CreateDecryptor" || methodName == "CreateEncryptor" ||
              methodName == "TransformFinalBlock" || methodName == "TransformBlock")) ||
            // CryptoStream construction
            (declType == "System.Security.Cryptography.CryptoStream" && methodName == ".ctor") ||
            // Known crypto type constructors
            (declType.Contains("RijndaelManaged") && methodName == ".ctor") ||
            (declType.Contains("DESCryptoServiceProvider") && methodName == ".ctor") ||
            (declType.Contains("TripleDESCryptoServiceProvider") && methodName == ".ctor") ||
            (declType.Contains("RC2CryptoServiceProvider") && methodName == ".ctor");

        private bool IsCompressionOperation(string declType, string methodName) =>
            (declType == "System.IO.Compression.GZipStream" && methodName == ".ctor") ||
            (declType == "System.IO.Compression.DeflateStream" && methodName == ".ctor") ||
            (declType == "System.IO.Compression.BrotliStream" && methodName == ".ctor") ||
            // CopyTo on compression streams
            (declType.Contains("System.IO.Compression") && methodName == "CopyTo");

        private bool IsStreamMaterialization(string declType, string methodName) =>
            (declType == "System.IO.MemoryStream" && methodName == "ToArray") ||
            (declType == "System.IO.MemoryStream" && methodName == "GetBuffer") ||
            (declType == "System.IO.Stream" && methodName == "CopyTo");

        private bool IsAssemblyLoad(string declType, string methodName) =>
            (declType == "System.Reflection.Assembly" &&
             (methodName == "Load" || methodName == "LoadFrom" || methodName == "LoadFile")) ||
            (declType.Contains("AssemblyLoadContext") &&
             (methodName == "LoadFromStream" || methodName == "LoadFromAssemblyPath"));

        private bool IsProcessStart(string declType, string methodName) =>
            declType.Contains("System.Diagnostics.Process") && methodName == "Start";

        private bool IsNativeExecutionSink(MethodReference method)
        {
            return DllImportInvocationContextExtractor.IsNativeExecutionPInvoke(method);
        }

        private string GetNativeExecutionOperationName(MethodReference method)
        {
            try
            {
                if (method.Resolve() is not { } methodDef || methodDef.PInvokeInfo == null)
                    return $"PInvoke.{method.Name}";

                var entryPoint = methodDef.PInvokeInfo.EntryPoint ?? method.Name;
                return $"PInvoke.{entryPoint}";
            }
            catch
            {
                return $"PInvoke.{method.Name}";
            }
        }

        private bool IsFileSink(string declType, string methodName) =>
            declType.StartsWith("System.IO.File") &&
            (methodName.Contains("Write") || methodName.Contains("Create"));

        private bool IsFileStreamSink(string declType, string methodName) =>
            declType == "System.IO.FileStream" && methodName == ".ctor";

        private bool IsNetworkSink(string declType, string methodName) =>
            (declType.StartsWith("System.Net") || declType.Contains("HttpClient") ||
             declType.Contains("WebClient")) &&
            (methodName.Contains("Post") || methodName.Contains("Send") || methodName.Contains("Upload"));

        private bool IsRegistrySink(string declType, string methodName) =>
            declType.Contains("Microsoft.Win32.Registry") &&
            (methodName.Contains("SetValue") || methodName.Contains("CreateSubKey"));

        private int? TryGetTargetLocalVariable(Mono.Collections.Generic.Collection<Instruction> instructions, int callIndex)
        {
            // Look ahead for stloc (store to local variable)
            if (callIndex + 1 < instructions.Count)
            {
                var nextInstr = instructions[callIndex + 1];
                if (nextInstr.OpCode == OpCodes.Stloc_0)
                    return 0;
                if (nextInstr.OpCode == OpCodes.Stloc_1)
                    return 1;
                if (nextInstr.OpCode == OpCodes.Stloc_2)
                    return 2;
                if (nextInstr.OpCode == OpCodes.Stloc_3)
                    return 3;
                if (nextInstr.OpCode == OpCodes.Stloc_S && nextInstr.Operand is VariableDefinition varS)
                    return varS.Index;
                if (nextInstr.OpCode == OpCodes.Stloc && nextInstr.Operand is VariableDefinition var)
                    return var.Index;
            }

            return null;
        }

        private static string GetMethodKey(MethodDefinition method)
        {
            // Use FullName which is unique (includes return type, declaring type, method name, and parameters)
            // Example: "System.Void MyNamespace.MyClass::MyMethod(System.String,System.Int32)"
            return method.FullName;
        }

        /// <summary>
        /// Gets cached instructions for a method, or empty collection if not found.
        /// Used for building code snippets in cross-method analysis.
        /// </summary>
        private Mono.Collections.Generic.Collection<Instruction> GetInstructionsForMethod(string methodKey)
        {
            if (_methodInstructions.TryGetValue(methodKey, out var instructions))
            {
                return instructions;
            }
            return new Mono.Collections.Generic.Collection<Instruction>();
        }

        /// <summary>
        /// Builds flow info for a method, tracking its operations and calls to other methods.
        /// </summary>
        private MethodFlowInfo BuildMethodFlowInfo(
            MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            List<InterestingOperation> operations)
        {
            // Check if method returns data (non-void return type with source/transform operations)
            bool returnsData = false;
            string? returnTypeName = null;

            if (method.ReturnType.FullName != "System.Void")
            {
                returnTypeName = method.ReturnType.FullName;
                // If the method has source or transform operations, it's likely returning data
                returnsData = operations.Any(op =>
                    op.NodeType == DataFlowNodeType.Source ||
                    op.NodeType == DataFlowNodeType.Transform);
            }

            var info = new MethodFlowInfo
            {
                MethodKey = method.FullName,
                DisplayName = $"{method.DeclaringType?.Name}.{method.Name}",
                HasSource = operations.Any(op => op.NodeType == DataFlowNodeType.Source),
                HasSink = operations.Any(op => op.NodeType == DataFlowNodeType.Sink),
                HasTransform = operations.Any(op => op.NodeType == DataFlowNodeType.Transform),
                ReturnsData = returnsData,
                ReturnTypeName = returnTypeName,
                Operations = operations,
                ReturnProducingOperations = operations
                    .Where(op => op.NodeType == DataFlowNodeType.Source || op.NodeType == DataFlowNodeType.Transform)
                    .ToList()
            };

            // Track calls to other methods (potential cross-method data flow)
            for (int i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                    instruction.Operand is MethodReference calledMethod)
                {
                    // Track which parameter index is passed (if any data-carrying local is passed)
                    var parameterMapping = TryGetParameterMapping(instructions, i, calledMethod);

                    info.OutgoingCalls.Add(new MethodCallSite
                    {
                        TargetMethodKey = calledMethod.FullName,
                        TargetDisplayName = $"{calledMethod.DeclaringType?.Name}.{calledMethod.Name}",
                        InstructionOffset = instruction.Offset,
                        InstructionIndex = i,
                        ParameterMapping = parameterMapping,
                        ReturnValueUsed = IsReturnValueUsed(instructions, i),
                        CalledMethodReturnsData = calledMethod.ReturnType.FullName != "System.Void"
                    });
                }
            }

            return info;
        }

        /// <summary>
        /// Tries to determine which local variables are passed as parameters to a method call.
        /// </summary>
        private Dictionary<int, int> TryGetParameterMapping(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod)
        {
            var mapping = new Dictionary<int, int>(); // paramIndex -> localVarIndex

            // Walk backwards from the call to find ldloc instructions that load parameters
            int paramCount = calledMethod.Parameters.Count;
            int foundParams = 0;

            for (int i = callIndex - 1; i >= 0 && foundParams < paramCount; i--)
            {
                var instr = instructions[i];
                int? localIndex = GetLocalVariableIndex(instr);

                if (localIndex.HasValue)
                {
                    // This local variable is being passed as a parameter
                    int paramIndex = paramCount - 1 - foundParams;
                    mapping[paramIndex] = localIndex.Value;
                    foundParams++;
                }
                else if (instr.OpCode == OpCodes.Ldarg_0 || instr.OpCode == OpCodes.Ldarg_1 ||
                         instr.OpCode == OpCodes.Ldarg_2 || instr.OpCode == OpCodes.Ldarg_3 ||
                         instr.OpCode == OpCodes.Ldarg_S || instr.OpCode == OpCodes.Ldarg)
                {
                    // It's a parameter passthrough, count it but don't track
                    foundParams++;
                }
                else if (instr.OpCode == OpCodes.Ldstr || instr.OpCode == OpCodes.Ldc_I4 ||
                         instr.OpCode == OpCodes.Ldc_I4_S || instr.OpCode == OpCodes.Ldnull)
                {
                    // Constant value, count it
                    foundParams++;
                }
            }

            return mapping;
        }

        /// <summary>
        /// Gets the local variable index from a load instruction, if applicable.
        /// </summary>
        private int? GetLocalVariableIndex(Instruction instr)
        {
            if (instr.OpCode == OpCodes.Ldloc_0)
                return 0;
            if (instr.OpCode == OpCodes.Ldloc_1)
                return 1;
            if (instr.OpCode == OpCodes.Ldloc_2)
                return 2;
            if (instr.OpCode == OpCodes.Ldloc_3)
                return 3;
            if (instr.OpCode == OpCodes.Ldloc_S && instr.Operand is VariableDefinition varS)
                return varS.Index;
            if (instr.OpCode == OpCodes.Ldloc && instr.Operand is VariableDefinition var)
                return var.Index;
            return null;
        }

        /// <summary>
        /// Checks if the return value of a call is used (stored to local or passed to another call).
        /// </summary>
        private bool IsReturnValueUsed(Mono.Collections.Generic.Collection<Instruction> instructions, int callIndex)
        {
            if (callIndex + 1 >= instructions.Count)
                return false;

            var nextInstr = instructions[callIndex + 1];

            // Check if stored to local
            if (nextInstr.OpCode == OpCodes.Stloc_0 || nextInstr.OpCode == OpCodes.Stloc_1 ||
                nextInstr.OpCode == OpCodes.Stloc_2 || nextInstr.OpCode == OpCodes.Stloc_3 ||
                nextInstr.OpCode == OpCodes.Stloc_S || nextInstr.OpCode == OpCodes.Stloc)
                return true;

            // Check if passed to another call (stays on stack)
            if (nextInstr.OpCode == OpCodes.Call || nextInstr.OpCode == OpCodes.Callvirt)
                return true;

            // Check if stored to field
            if (nextInstr.OpCode == OpCodes.Stfld || nextInstr.OpCode == OpCodes.Stsfld)
                return true;

            return false;
        }

        /// <summary>
        /// Tries to build a cross-method data flow chain by connecting caller and callee operations.
        /// </summary>
        private DataFlowChain? TryBuildCrossMethodChain(
            MethodFlowInfo callerInfo,
            MethodCallSite callSite,
            MethodFlowInfo calleeInfo)
        {
            // Look for patterns where:
            // 1. Caller has a source, callee has a sink
            // 2. Caller has a source + transform, callee has a sink
            // 3. Data flows through parameter passing

            bool callerHasDataOrigin = callerInfo.HasSource || callerInfo.HasTransform;
            bool calleeHasDataConsumption = calleeInfo.HasSink;

            if (!callerHasDataOrigin || !calleeHasDataConsumption)
                return null;

            // Build the combined operations list
            var combinedOps = new List<InterestingOperation>();

            // Add caller's source/transform operations
            combinedOps.AddRange(callerInfo.Operations
                .Where(op => op.NodeType == DataFlowNodeType.Source || op.NodeType == DataFlowNodeType.Transform)
                .OrderBy(op => op.InstructionIndex));

            // Add callee's sink operations
            combinedOps.AddRange(calleeInfo.Operations
                .Where(op => op.NodeType == DataFlowNodeType.Sink)
                .OrderBy(op => op.InstructionIndex));

            if (combinedOps.Count < 2)
                return null;

            // Recognize the pattern
            var pattern = RecognizePattern(combinedOps);
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
                return null;

            // Build the cross-method chain
            var severity = DetermineSeverity(pattern, combinedOps);
            var confidence = CalculateCrossMethodConfidence(pattern, combinedOps, callerInfo, calleeInfo);
            var summary = BuildCrossMethodSummary(pattern, callerInfo, calleeInfo);
            var chainId = $"cross:{callerInfo.MethodKey}->{calleeInfo.MethodKey}";

            var chain = new DataFlowChain(chainId, pattern, severity, confidence, summary, callerInfo.MethodKey)
            {
                IsCrossMethod = true,
                InvolvedMethods = new List<string> { callerInfo.MethodKey, calleeInfo.MethodKey }
            };

            // Add nodes from caller
            foreach (var op in callerInfo.Operations.Where(op =>
                op.NodeType == DataFlowNodeType.Source || op.NodeType == DataFlowNodeType.Transform))
            {
                var snippet = _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(callerInfo.MethodKey),
                    op.InstructionIndex,
                    1
                );
                var node = new DataFlowNode(
                    $"{callerInfo.DisplayName}:{op.Instruction.Offset}",
                    op.Operation,
                    op.NodeType,
                    op.DataDescription,
                    op.Instruction.Offset,
                    snippet,
                    callerInfo.MethodKey
                );
                chain.AppendNode(node);
            }

            // Add a boundary node showing the method call with snippet
            var callSiteSnippet = _snippetBuilder.BuildSnippet(
                GetInstructionsForMethod(callerInfo.MethodKey),
                callSite.InstructionIndex,
                1
            );
            var boundaryNode = new DataFlowNode(
                $"{callerInfo.DisplayName}:{callSite.InstructionOffset}",
                $"calls {calleeInfo.DisplayName}",
                DataFlowNodeType.Intermediate,
                "data passed via parameter",
                callSite.InstructionOffset,
                callSiteSnippet,
                callerInfo.MethodKey
            )
            {
                IsMethodBoundary = true,
                TargetMethodKey = calleeInfo.MethodKey
            };
            chain.AppendNode(boundaryNode);

            // Add nodes from callee
            foreach (var op in calleeInfo.Operations.Where(op => op.NodeType == DataFlowNodeType.Sink))
            {
                var calleeSnippet = _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(calleeInfo.MethodKey),
                    op.InstructionIndex,
                    1
                );
                var node = new DataFlowNode(
                    $"{calleeInfo.DisplayName}:{op.Instruction.Offset}",
                    op.Operation,
                    op.NodeType,
                    op.DataDescription,
                    op.Instruction.Offset,
                    calleeSnippet,
                    calleeInfo.MethodKey
                );
                chain.AppendNode(node);
            }

            return chain;
        }

        private double CalculateCrossMethodConfidence(
            DataFlowPattern pattern,
            List<InterestingOperation> operations,
            MethodFlowInfo callerInfo,
            MethodFlowInfo calleeInfo)
        {
            var baseConfidence = CalculateConfidence(pattern, operations);

            // Lower confidence slightly for cross-method (less certain about data flow)
            baseConfidence -= 0.1;

            // Increase confidence if we have parameter mapping
            if (callerInfo.OutgoingCalls.Any(c => c.TargetMethodKey == calleeInfo.MethodKey && c.ParameterMapping.Count > 0))
            {
                baseConfidence += 0.1;
            }

            return Math.Max(0.3, Math.Min(baseConfidence, 1.0));
        }

        private string BuildCrossMethodSummary(
            DataFlowPattern pattern,
            MethodFlowInfo callerInfo,
            MethodFlowInfo calleeInfo)
        {
            var patternDesc = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => "Embedded resource drop-and-execute pattern",
                DataFlowPattern.DownloadAndExecute => "Download and execute pattern",
                DataFlowPattern.DataExfiltration => "Data exfiltration pattern",
                DataFlowPattern.DynamicCodeLoading => "Dynamic code loading pattern",
                DataFlowPattern.CredentialTheft => "Credential theft pattern",
                DataFlowPattern.ObfuscatedPersistence => "Obfuscated persistence pattern",
                _ => "Suspicious data flow"
            };

            return $"Cross-method {patternDesc}: {callerInfo.DisplayName} → {calleeInfo.DisplayName}";
        }

        /// <summary>
        /// Tries to build a chain when a callee returns data and the caller uses it.
        /// This handles the pattern where: callee returns data (via return value) → caller uses it (sink)
        /// </summary>
        private DataFlowChain? TryBuildReturnValueChain(
            MethodFlowInfo callerInfo,
            MethodCallSite callSite,
            MethodFlowInfo calleeInfo)
        {
            // For return value flows, we need:
            // 1. Callee has source/transform operations that produce data
            // 2. Caller has sink operations that consume the return value

            bool calleeProducesData = calleeInfo.ReturnsData || calleeInfo.ReturnProducingOperations.Count > 0;
            bool callerHasSinkAfterCall = HasSinkAfterCall(callerInfo, callSite);

            if (!calleeProducesData || !callerHasSinkAfterCall)
            {
                return null;
            }

            // Build combined operations list
            var combinedOps = new List<InterestingOperation>();

            // Add callee's return-producing operations (treated as sources for the return flow)
            foreach (var op in calleeInfo.ReturnProducingOperations.OrderBy(op => op.InstructionIndex))
            {
                combinedOps.Add(op);
            }

            // Add caller's sink operations that come after the call
            var callerSinksAfterCall = GetSinksAfterCall(callerInfo, callSite);
            foreach (var op in callerSinksAfterCall.OrderBy(op => op.InstructionIndex))
            {
                combinedOps.Add(op);
            }

            if (combinedOps.Count < 2)
            {
                return null;
            }

            // Recognize the pattern
            var pattern = RecognizePattern(combinedOps);
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
            {
                return null;
            }

            // Build the return value chain
            var severity = DetermineSeverity(pattern, combinedOps);
            var confidence = CalculateReturnValueConfidence(pattern, combinedOps, callerInfo, calleeInfo);
            var summary = BuildReturnValueSummary(pattern, callerInfo, calleeInfo);
            var chainId = $"return:{calleeInfo.MethodKey}->{callerInfo.MethodKey}";

            var chain = new DataFlowChain(chainId, pattern, severity, confidence, summary, calleeInfo.MethodKey)
            {
                IsCrossMethod = true,
                InvolvedMethods = new List<string> { calleeInfo.MethodKey, callerInfo.MethodKey }
            };

            // Add nodes from callee (return-producing operations)
            foreach (var op in calleeInfo.ReturnProducingOperations)
            {
                var snippet = _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(calleeInfo.MethodKey),
                    op.InstructionIndex,
                    1
                );
                var node = new DataFlowNode(
                    $"{calleeInfo.DisplayName}:{op.Instruction.Offset}",
                    op.Operation,
                    op.NodeType,
                    $"returns {op.DataDescription}",
                    op.Instruction.Offset,
                    snippet,
                    calleeInfo.MethodKey
                );
                chain.AppendNode(node);
            }

            // Add return value boundary node
            var returnBoundaryNode = new DataFlowNode(
                $"{callerInfo.DisplayName}:{callSite.InstructionOffset}",
                $"receives return from {calleeInfo.DisplayName}",
                DataFlowNodeType.Intermediate,
                "return value passed to caller",
                callSite.InstructionOffset,
                _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(callerInfo.MethodKey),
                    callSite.InstructionIndex,
                    1
                ),
                callerInfo.MethodKey
            )
            {
                IsMethodBoundary = true,
                TargetMethodKey = calleeInfo.MethodKey
            };
            chain.AppendNode(returnBoundaryNode);

            // Add nodes from caller (sinks after the call)
            foreach (var op in callerSinksAfterCall)
            {
                var snippet = _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(callerInfo.MethodKey),
                    op.InstructionIndex,
                    1
                );
                var node = new DataFlowNode(
                    $"{callerInfo.DisplayName}:{op.Instruction.Offset}",
                    op.Operation,
                    op.NodeType,
                    op.DataDescription,
                    op.Instruction.Offset,
                    snippet,
                    callerInfo.MethodKey
                );
                chain.AppendNode(node);
            }

            return chain;
        }

        /// <summary>
        /// Checks if the caller method has sink operations after the specified call site.
        /// </summary>
        private bool HasSinkAfterCall(MethodFlowInfo callerInfo, MethodCallSite callSite)
        {
            return GetSinksAfterCall(callerInfo, callSite).Count > 0;
        }

        /// <summary>
        /// Gets sink operations that occur after the specified call site in the caller.
        /// </summary>
        private List<InterestingOperation> GetSinksAfterCall(
            MethodFlowInfo callerInfo,
            MethodCallSite callSite)
        {
            // Find operations that use the return value (typically after the call instruction)
            // Look for sink operations that come after the call
            return callerInfo.Operations
                .Where(op =>
                    op.NodeType == DataFlowNodeType.Sink &&
                    op.InstructionIndex > callSite.InstructionIndex)
                .ToList();
        }

        /// <summary>
        /// Calculates confidence score for a return value chain.
        /// </summary>
        private double CalculateReturnValueConfidence(
            DataFlowPattern pattern,
            List<InterestingOperation> operations,
            MethodFlowInfo callerInfo,
            MethodFlowInfo calleeInfo)
        {
            var baseConfidence = CalculateConfidence(pattern, operations);

            // Higher confidence for return value flows (more explicit data transfer)
            baseConfidence += 0.05;

            // Increase if we have clear return type
            if (!string.IsNullOrEmpty(calleeInfo.ReturnTypeName))
            {
                baseConfidence += 0.05;
            }

            return Math.Max(0.3, Math.Min(baseConfidence, 1.0));
        }

        /// <summary>
        /// Builds a summary for a return value chain.
        /// </summary>
        private string BuildReturnValueSummary(
            DataFlowPattern pattern,
            MethodFlowInfo callerInfo,
            MethodFlowInfo calleeInfo)
        {
            var patternDesc = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => "Return-value embedded resource execution",
                DataFlowPattern.DownloadAndExecute => "Return-value download and execute",
                DataFlowPattern.DataExfiltration => "Return-value exfiltration",
                DataFlowPattern.DynamicCodeLoading => "Return-value code loading",
                DataFlowPattern.CredentialTheft => "Return-value credential theft",
                DataFlowPattern.ObfuscatedPersistence => "Return-value persistence",
                _ => "Return-value suspicious flow"
            };

            return $"{patternDesc}: {calleeInfo.DisplayName} returns → {callerInfo.DisplayName}";
        }

        /// <summary>
        /// Internal representation of an interesting operation.
        /// </summary>
        private class InterestingOperation
        {
            public Instruction Instruction { get; set; } = null!;
            public int InstructionIndex { get; set; }
            public MethodReference MethodReference { get; set; } = null!;
            public DataFlowNodeType NodeType { get; set; }
            public string Operation { get; set; } = null!;
            public string DataDescription { get; set; } = null!;
            public int? LocalVariableIndex { get; set; }
        }

        /// <summary>
        /// Tracks data flow information for a single method (for inter-method analysis).
        /// </summary>
        private class MethodFlowInfo
        {
            /// <summary>
            /// Unique method identifier (FullName from Cecil)
            /// </summary>
            public string MethodKey { get; set; } = null!;

            /// <summary>
            /// Display-friendly name (Type.Method)
            /// </summary>
            public string DisplayName { get; set; } = null!;

            /// <summary>
            /// Whether this method has data source operations
            /// </summary>
            public bool HasSource { get; set; }

            /// <summary>
            /// Whether this method has data sink operations
            /// </summary>
            public bool HasSink { get; set; }

            /// <summary>
            /// Whether this method has data transform operations
            /// </summary>
            public bool HasTransform { get; set; }

            /// <summary>
            /// Whether this method returns data (has non-void return type with interesting operations)
            /// </summary>
            public bool ReturnsData { get; set; }

            /// <summary>
            /// The return type name if the method returns data
            /// </summary>
            public string? ReturnTypeName { get; set; }

            /// <summary>
            /// All interesting operations in this method
            /// </summary>
            public List<InterestingOperation> Operations { get; set; } = new();

            /// <summary>
            /// Calls made from this method to other methods
            /// </summary>
            public List<MethodCallSite> OutgoingCalls { get; set; } = new();

            /// <summary>
            /// Operations that produce return values (e.g., network downloads)
            /// </summary>
            public List<InterestingOperation> ReturnProducingOperations { get; set; } = new();
        }

        /// <summary>
        /// Represents a call site where one method calls another.
        /// </summary>
        private class MethodCallSite
        {
            /// <summary>
            /// The called method's unique identifier (FullName)
            /// </summary>
            public string TargetMethodKey { get; set; } = null!;

            /// <summary>
            /// Display-friendly name of the target
            /// </summary>
            public string TargetDisplayName { get; set; } = null!;

            /// <summary>
            /// IL offset of the call instruction
            /// </summary>
            public int InstructionOffset { get; set; }

            /// <summary>
            /// Index in the instructions collection
            /// </summary>
            public int InstructionIndex { get; set; }

            /// <summary>
            /// Maps parameter index to local variable index (for data flow tracking)
            /// </summary>
            public Dictionary<int, int> ParameterMapping { get; set; } = new();

            /// <summary>
            /// Whether the return value is used
            /// </summary>
            public bool ReturnValueUsed { get; set; }

            /// <summary>
            /// Whether the called method returns data (non-void return type)
            /// </summary>
            public bool CalledMethodReturnsData { get; set; }
        }

        /// <summary>
        /// Represents a node in a deep call chain for cross-method analysis.
        /// </summary>
        private class CallChainNode
        {
            public MethodFlowInfo MethodInfo { get; set; } = null!;
            public MethodCallSite? IncomingCallSite { get; set; }
            public List<CallChainNode> ChildNodes { get; set; } = new();
            public HashSet<string> VisitedMethods { get; set; } = new();
        }

        /// <summary>
        /// Performs deep call chain analysis to detect patterns spanning multiple method boundaries.
        /// This extends AnalyzeCrossMethodFlows to handle chains like A → B → C.
        /// </summary>
        private void AnalyzeDeepCallChains()
        {
            var maxChainDepth = _config.MaxCallChainDepth;

            foreach (var (methodKey, methodInfo) in _methodFlowInfos)
            {
                foreach (var callSite in methodInfo.OutgoingCalls)
                {
                    if (!_methodFlowInfos.TryGetValue(callSite.TargetMethodKey, out var targetInfo))
                    {
                        continue;
                    }

                    // Start building a deep call chain from this call site
                    var rootNode = new CallChainNode
                    {
                        MethodInfo = methodInfo,
                        IncomingCallSite = null,
                        VisitedMethods = new HashSet<string> { methodKey, callSite.TargetMethodKey }
                    };

                    var targetNode = new CallChainNode
                    {
                        MethodInfo = targetInfo,
                        IncomingCallSite = callSite,
                        VisitedMethods = rootNode.VisitedMethods
                    };
                    rootNode.ChildNodes.Add(targetNode);

                    // Recursively explore the call chain
                    ExploreCallChain(targetNode, targetInfo, 2, maxChainDepth);

                    // Build and analyze the deep chain
                    var deepChain = TryBuildDeepCallChain(rootNode, targetNode, 1);
                    if (deepChain != null && deepChain.IsSuspicious)
                    {
                        _crossMethodChains.Add(deepChain);
                    }
                }
            }
        }

        /// <summary>
        /// Recursively explores a call chain up to a maximum depth.
        /// </summary>
        private void ExploreCallChain(
            CallChainNode currentNode,
            MethodFlowInfo currentInfo,
            int currentDepth,
            int maxDepth)
        {
            if (currentDepth >= maxDepth)
            {
                return;
            }

            foreach (var callSite in currentInfo.OutgoingCalls)
            {
                if (currentNode.VisitedMethods.Contains(callSite.TargetMethodKey))
                {
                    continue; // Skip to prevent cycles
                }

                if (!_methodFlowInfos.TryGetValue(callSite.TargetMethodKey, out var nextInfo))
                {
                    continue;
                }

                var childNode = new CallChainNode
                {
                    MethodInfo = nextInfo,
                    IncomingCallSite = callSite,
                    VisitedMethods = new HashSet<string>(currentNode.VisitedMethods) { callSite.TargetMethodKey }
                };

                currentNode.ChildNodes.Add(childNode);
                ExploreCallChain(childNode, nextInfo, currentDepth + 1, maxDepth);
            }
        }

        /// <summary>
        /// Attempts to build a deep call chain from a root node to a target node.
        /// Returns null if no suspicious pattern is detected.
        /// </summary>
        private DataFlowChain? TryBuildDeepCallChain(
            CallChainNode rootNode,
            CallChainNode targetNode,
            int chainLength)
        {
            // Collect all operations across the chain
            var allSourceOps = new List<(MethodFlowInfo Info, InterestingOperation Op)>();
            var allSinkOps = new List<(MethodFlowInfo Info, InterestingOperation Op)>();
            var allTransformOps = new List<(MethodFlowInfo Info, InterestingOperation Op)>();
            var callSites = new List<(MethodFlowInfo Caller, MethodCallSite Site)>();

            CollectChainOperations(rootNode, allSourceOps, allSinkOps, allTransformOps, callSites);

            // Check if we have enough for a suspicious pattern
            bool hasSource = allSourceOps.Count > 0;
            bool hasSink = allSinkOps.Count > 0;

            if (!hasSource || !hasSink)
            {
                return null;
            }

            // Build the combined operations list for pattern recognition
            var combinedOps = new List<InterestingOperation>();

            // Add source operations
            foreach (var (info, op) in allSourceOps)
            {
                combinedOps.Add(op);
            }

            // Build the deep chain
            var pattern = RecognizePattern(combinedOps);
            if (pattern == DataFlowPattern.Legitimate || pattern == DataFlowPattern.Unknown)
            {
                return null;
            }

            var severity = DetermineSeverity(pattern, combinedOps);
            var confidence = CalculateDeepChainConfidence(pattern, combinedOps, chainLength);
            var summary = BuildDeepChainSummary(pattern, rootNode, targetNode);
            var chainId = $"deep:{string.Join("->", rootNode.VisitedMethods)}";

            var chain = new DataFlowChain(chainId, pattern, severity, confidence, summary, rootNode.MethodInfo.MethodKey)
            {
                IsCrossMethod = true,
                InvolvedMethods = rootNode.VisitedMethods.ToList()
            };

            // Add all source nodes
            foreach (var (info, op) in allSourceOps)
            {
                var snippet = _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(info.MethodKey),
                    op.InstructionIndex,
                    1
                );
                var node = new DataFlowNode(
                    $"{info.DisplayName}:{op.Instruction.Offset}",
                    op.Operation,
                    op.NodeType,
                    op.DataDescription,
                    op.Instruction.Offset,
                    snippet,
                    info.MethodKey
                );
                chain.AppendNode(node);
            }

            // Add intermediate nodes and call sites
            AddIntermediateNodesToChain(rootNode, chain, callSites);

            // Add sink nodes
            foreach (var (info, op) in allSinkOps)
            {
                var snippet = _snippetBuilder.BuildSnippet(
                    GetInstructionsForMethod(info.MethodKey),
                    op.InstructionIndex,
                    1
                );
                var node = new DataFlowNode(
                    $"{info.DisplayName}:{op.Instruction.Offset}",
                    op.Operation,
                    op.NodeType,
                    op.DataDescription,
                    op.Instruction.Offset,
                    snippet,
                    info.MethodKey
                );
                chain.AppendNode(node);
            }

            return chain;
        }

        /// <summary>
        /// Collects all operations across a call chain.
        /// </summary>
        private void CollectChainOperations(
            CallChainNode node,
            List<(MethodFlowInfo Info, InterestingOperation Op)> sources,
            List<(MethodFlowInfo Info, InterestingOperation Op)> sinks,
            List<(MethodFlowInfo Info, InterestingOperation Op)> transforms,
            List<(MethodFlowInfo Caller, MethodCallSite Site)> callSites)
        {
            // Add operations from this method
            foreach (var op in node.MethodInfo.Operations)
            {
                if (op.NodeType == DataFlowNodeType.Source)
                {
                    sources.Add((node.MethodInfo, op));
                }
                else if (op.NodeType == DataFlowNodeType.Sink)
                {
                    sinks.Add((node.MethodInfo, op));
                }
                else if (op.NodeType == DataFlowNodeType.Transform)
                {
                    transforms.Add((node.MethodInfo, op));
                }
            }

            // Record call site if this node was entered via a call
            if (node.IncomingCallSite != null)
            {
                callSites.Add((node.MethodInfo, node.IncomingCallSite));
            }

            // Recursively collect from child nodes
            foreach (var child in node.ChildNodes)
            {
                CollectChainOperations(child, sources, sinks, transforms, callSites);
            }
        }

        /// <summary>
        /// Adds intermediate nodes for call sites to the chain.
        /// </summary>
        private void AddIntermediateNodesToChain(
            CallChainNode node,
            DataFlowChain chain,
            List<(MethodFlowInfo Caller, MethodCallSite Site)> callSites)
        {
            foreach (var (caller, site) in callSites)
            {
                if (_methodFlowInfos.TryGetValue(site.TargetMethodKey, out var targetInfo))
                {
                    var snippet = _snippetBuilder.BuildSnippet(
                        GetInstructionsForMethod(caller.MethodKey),
                        site.InstructionIndex,
                        1
                    );
                    var boundaryNode = new DataFlowNode(
                        $"{caller.DisplayName}:{site.InstructionOffset}",
                        $"calls {targetInfo.DisplayName}",
                        DataFlowNodeType.Intermediate,
                        "data passed via parameter",
                        site.InstructionOffset,
                        snippet,
                        caller.MethodKey
                    )
                    {
                        IsMethodBoundary = true,
                        TargetMethodKey = targetInfo.MethodKey
                    };
                    chain.AppendNode(boundaryNode);
                }
            }

            // Recursively add from child nodes
            foreach (var child in node.ChildNodes)
            {
                if (child.IncomingCallSite != null)
                {
                    AddIntermediateNodesToChain(child, chain, callSites);
                }
            }
        }

        /// <summary>
        /// Calculates confidence score for a deep call chain.
        /// </summary>
        private double CalculateDeepChainConfidence(
            DataFlowPattern pattern,
            List<InterestingOperation> operations,
            int chainLength)
        {
            var baseConfidence = CalculateConfidence(pattern, operations);

            // Reduce confidence for longer chains (more uncertainty)
            if (chainLength > 2)
            {
                baseConfidence -= 0.05 * (chainLength - 2);
            }

            // Increase confidence if we have clear data flow across methods
            baseConfidence += 0.05;

            return Math.Max(0.2, Math.Min(baseConfidence, 1.0));
        }

        /// <summary>
        /// Builds a summary for a deep call chain.
        /// </summary>
        private string BuildDeepChainSummary(
            DataFlowPattern pattern,
            CallChainNode rootNode,
            CallChainNode targetNode)
        {
            var patternDesc = pattern switch
            {
                DataFlowPattern.EmbeddedResourceDropAndExecute => "Multi-method embedded resource drop-and-execute pattern",
                DataFlowPattern.DownloadAndExecute => "Multi-method download and execute pattern",
                DataFlowPattern.DataExfiltration => "Multi-method data exfiltration pattern",
                DataFlowPattern.DynamicCodeLoading => "Multi-method dynamic code loading pattern",
                DataFlowPattern.CredentialTheft => "Multi-method credential theft pattern",
                DataFlowPattern.ObfuscatedPersistence => "Multi-method obfuscated persistence pattern",
                _ => "Multi-method suspicious data flow"
            };

            var methods = string.Join(" → ", rootNode.VisitedMethods.Select(m =>
            {
                var lastDot = m.LastIndexOf('.');
                return lastDot > 0 ? m[(lastDot + 1)..] : m;
            }));

            return $"{patternDesc}: {methods}";
        }
    }
}
