using System.Text;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services
{
    /// <summary>
    /// Analyzes data flow through IL instructions to track how data moves between suspicious operations.
    /// Helps distinguish legitimate operations from malicious attack chains.
    /// </summary>
    public class DataFlowAnalyzer
    {
        private readonly IEnumerable<IScanRule> _rules;
        private readonly CodeSnippetBuilder _snippetBuilder;
        private readonly Dictionary<string, List<DataFlowChain>> _methodDataFlows = new();

        public DataFlowAnalyzer(IEnumerable<IScanRule> rules, CodeSnippetBuilder snippetBuilder)
        {
            _rules = rules ?? throw new ArgumentNullException(nameof(rules));
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
        }

        /// <summary>
        /// Clears all tracked data flows. Call before scanning a new assembly.
        /// </summary>
        public void Clear()
        {
            _methodDataFlows.Clear();
        }

        /// <summary>
        /// Analyzes a method for suspicious data flow patterns.
        /// Returns data flow chains that match known attack patterns.
        /// </summary>
        public List<DataFlowChain> AnalyzeMethod(MethodDefinition method)
        {
            if (method?.Body == null || method.Body.Instructions.Count == 0)
                return new List<DataFlowChain>();

            var chains = new List<DataFlowChain>();
            var instructions = method.Body.Instructions;

            // Build list of interesting operations (sources, transforms, sinks)
            var interestingOps = IdentifyInterestingOperations(method, instructions);

            if (interestingOps.Count < 2)
                return chains; // Need at least 2 operations to form a chain

            // Try to build data flow chains by tracking local variables
            chains.AddRange(BuildDataFlowChains(method, instructions, interestingOps));

            // Cache the results
            var methodKey = GetMethodKey(method);
            _methodDataFlows[methodKey] = chains;

            return chains;
        }

        /// <summary>
        /// Builds consolidated findings from all tracked data flows.
        /// </summary>
        public IEnumerable<ScanFinding> BuildDataFlowFindings()
        {
            var findings = new List<ScanFinding>();

            foreach (var (methodKey, chains) in _methodDataFlows)
            {
                foreach (var chain in chains.Where(c => c.IsSuspicious))
                {
                    var finding = CreateDataFlowFinding(chain);
                    findings.Add(finding);
                }
            }

            return findings;
        }

        /// <summary>
        /// Gets the count of tracked data flow chains.
        /// </summary>
        public int DataFlowChainCount => _methodDataFlows.Values.Sum(list => list.Count);

        /// <summary>
        /// Gets the count of suspicious data flow chains.
        /// </summary>
        public int SuspiciousChainCount => _methodDataFlows.Values.SelectMany(list => list).Count(c => c.IsSuspicious);

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

            // Transform operations (data is modified)
            if (IsBase64Decode(declType, methodName))
                return (DataFlowNodeType.Transform, "Convert.FromBase64String", "byte[] (decoded)");

            if (IsEncoding(declType, methodName))
                return (DataFlowNodeType.Transform, $"{method.DeclaringType?.Name}.{methodName}", "byte[]/string (encoded)");

            if (IsAssemblyLoad(declType, methodName))
                return (DataFlowNodeType.Transform, $"{method.DeclaringType?.Name}.{methodName}", "Assembly (loaded code)");

            // Sink operations (where data is consumed)
            if (IsProcessStart(declType, methodName))
                return (DataFlowNodeType.Sink, "Process.Start", "Executes process");

            if (IsFileSink(declType, methodName))
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

        private bool HasTransform(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Transform);

        private bool HasFileWrite(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Sink &&
                         (op.Operation.Contains("Write") || op.Operation.Contains("Create")) &&
                         op.Operation.Contains("File"));

        private bool HasProcessStart(List<InterestingOperation> ops) =>
            ops.Any(op => op.NodeType == DataFlowNodeType.Sink && op.Operation.Contains("Process.Start"));

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

        private bool IsBase64Decode(string declType, string methodName) =>
            declType == "System.Convert" && methodName == "FromBase64String";

        private bool IsEncoding(string declType, string methodName) =>
            declType.Contains("System.Text.Encoding") ||
            (declType == "System.Convert" && methodName == "ToBase64String");

        private bool IsAssemblyLoad(string declType, string methodName) =>
            declType == "System.Reflection.Assembly" &&
            (methodName == "Load" || methodName == "LoadFrom" || methodName == "LoadFile");

        private bool IsProcessStart(string declType, string methodName) =>
            declType.Contains("System.Diagnostics.Process") && methodName == "Start";

        private bool IsFileSink(string declType, string methodName) =>
            declType.StartsWith("System.IO.File") &&
            (methodName.Contains("Write") || methodName.Contains("Create"));

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
            return $"{method.DeclaringType?.FullName}.{method.Name}";
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
    }
}
