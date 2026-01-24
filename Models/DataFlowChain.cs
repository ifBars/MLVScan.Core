namespace MLVScan.Models
{
    /// <summary>
    /// Represents a single node in a data flow chain showing how data moves through operations.
    /// </summary>
    public class DataFlowNode
    {
        /// <summary>
        /// Location where this operation occurs (method:offset).
        /// </summary>
        public string Location { get; set; }

        /// <summary>
        /// The operation being performed (e.g., "Base64.FromBase64String", "File.WriteAllBytes").
        /// </summary>
        public string Operation { get; set; }

        /// <summary>
        /// Type of node in the data flow (source, transform, sink, etc).
        /// </summary>
        public DataFlowNodeType NodeType { get; set; }

        /// <summary>
        /// Description of the data at this point (e.g., "byte[] (encoded payload)", "string URL").
        /// </summary>
        public string DataDescription { get; set; }

        /// <summary>
        /// IL instruction offset.
        /// </summary>
        public int InstructionOffset { get; set; }

        /// <summary>
        /// Optional code snippet showing the operation.
        /// </summary>
        public string? CodeSnippet { get; set; }

        /// <summary>
        /// The method key where this node occurs (for cross-method tracking).
        /// Format: Namespace.Type.Method
        /// </summary>
        public string? MethodKey { get; set; }

        /// <summary>
        /// Whether this node represents a method call that passes data to another method.
        /// </summary>
        public bool IsMethodBoundary { get; set; }

        /// <summary>
        /// For method boundary nodes, the target method being called.
        /// </summary>
        public string? TargetMethodKey { get; set; }

        public DataFlowNode(string location, string operation, DataFlowNodeType nodeType, string dataDescription, int instructionOffset, string? codeSnippet = null, string? methodKey = null)
        {
            Location = location;
            Operation = operation;
            NodeType = nodeType;
            DataDescription = dataDescription;
            InstructionOffset = instructionOffset;
            CodeSnippet = codeSnippet;
            MethodKey = methodKey;
        }

        public override string ToString()
        {
            var prefix = NodeType switch
            {
                DataFlowNodeType.Source => "[SOURCE]",
                DataFlowNodeType.Transform => "[TRANSFORM]",
                DataFlowNodeType.Sink => "[SINK]",
                DataFlowNodeType.Intermediate => "[PASS]",
                _ => "[???]"
            };
            var methodInfo = IsMethodBoundary && TargetMethodKey != null ? $" → calls {TargetMethodKey}" : "";
            return $"{prefix} {Operation} → {DataDescription}{methodInfo}";
        }
    }

    /// <summary>
    /// Type of node in a data flow chain.
    /// </summary>
    public enum DataFlowNodeType
    {
        /// <summary>
        /// Data originates here (network call, file read, hardcoded string).
        /// </summary>
        Source,

        /// <summary>
        /// Data is transformed (decode, decrypt, decompress, parse).
        /// </summary>
        Transform,

        /// <summary>
        /// Data is consumed in a potentially dangerous way (file write, process start, network send).
        /// </summary>
        Sink,

        /// <summary>
        /// Data passes through without transformation (variable assignment, parameter passing).
        /// </summary>
        Intermediate
    }

    /// <summary>
    /// Represents a complete data flow from source to sink(s).
    /// Used to track how suspicious data moves through operations.
    /// Supports both single-method and cross-method data flows.
    /// </summary>
    public class DataFlowChain
    {
        /// <summary>
        /// Unique identifier for this data flow chain.
        /// </summary>
        public string ChainId { get; set; }

        /// <summary>
        /// The IL variable or stack slot being tracked (for debugging).
        /// </summary>
        public string? SourceVariable { get; set; }

        /// <summary>
        /// The nodes in this data flow, ordered from source to sink(s).
        /// </summary>
        public List<DataFlowNode> Nodes { get; set; } = new();

        /// <summary>
        /// Recognized attack pattern (if any).
        /// </summary>
        public DataFlowPattern Pattern { get; set; }

        /// <summary>
        /// Overall risk level of this data flow.
        /// </summary>
        public Severity Severity { get; set; }

        /// <summary>
        /// Confidence score (0.0 - 1.0) in the pattern detection.
        /// </summary>
        public double Confidence { get; set; }

        /// <summary>
        /// Human-readable summary of the data flow.
        /// </summary>
        public string Summary { get; set; }

        /// <summary>
        /// The method where this data flow occurs (primary method for single-method flows).
        /// </summary>
        public string MethodLocation { get; set; }

        /// <summary>
        /// True if this data flow matches a known malicious pattern.
        /// </summary>
        public bool IsSuspicious => Pattern != DataFlowPattern.Legitimate && Pattern != DataFlowPattern.Unknown;

        /// <summary>
        /// True if this data flow spans multiple methods.
        /// </summary>
        public bool IsCrossMethod { get; set; }

        /// <summary>
        /// All methods involved in this data flow (for cross-method flows).
        /// </summary>
        public List<string> InvolvedMethods { get; set; } = new();

        /// <summary>
        /// The depth of the call chain (1 = single method, 2+ = cross-method).
        /// </summary>
        public int CallDepth => InvolvedMethods.Count > 0 ? InvolvedMethods.Count : 1;

        public DataFlowChain(string chainId, DataFlowPattern pattern, Severity severity, double confidence, string summary, string methodLocation)
        {
            ChainId = chainId;
            Pattern = pattern;
            Severity = severity;
            Confidence = confidence;
            Summary = summary;
            MethodLocation = methodLocation;
        }

        /// <summary>
        /// Adds a node to the end of the chain.
        /// </summary>
        public void AppendNode(DataFlowNode node)
        {
            Nodes.Add(node);
        }

        /// <summary>
        /// Adds a node to the beginning of the chain.
        /// </summary>
        public void PrependNode(DataFlowNode node)
        {
            Nodes.Insert(0, node);
        }

        /// <summary>
        /// Generates a detailed description of the data flow with all steps.
        /// </summary>
        public string ToDetailedDescription()
        {
            if (Nodes.Count == 0)
                return Summary;

            var lines = new List<string>
            {
                Summary,
                "",
                $"Data Flow Chain (Confidence: {Confidence * 100:F0}%):"
            };

            for (int i = 0; i < Nodes.Count; i++)
            {
                var node = Nodes[i];
                var arrow = i > 0 ? "  → " : "    ";
                lines.Add($"{arrow}{node}");
                lines.Add($"      Location: {node.Location}");
            }

            return string.Join("\n", lines);
        }

        /// <summary>
        /// Creates a combined code snippet showing all operations in the flow.
        /// </summary>
        public string? ToCombinedCodeSnippet()
        {
            var snippets = Nodes
                .Where(n => !string.IsNullOrEmpty(n.CodeSnippet))
                .Select(n => $"// {n.Location} - {n.Operation}\n{n.CodeSnippet}")
                .ToList();

            return snippets.Count > 0 ? string.Join("\n\n", snippets) : null;
        }

        /// <summary>
        /// Gets the source node (where data originates).
        /// </summary>
        public DataFlowNode? GetSource()
        {
            return Nodes.FirstOrDefault(n => n.NodeType == DataFlowNodeType.Source);
        }

        /// <summary>
        /// Gets all sink nodes (where data is consumed).
        /// </summary>
        public IEnumerable<DataFlowNode> GetSinks()
        {
            return Nodes.Where(n => n.NodeType == DataFlowNodeType.Sink);
        }

        /// <summary>
        /// Gets all transform nodes (where data is modified).
        /// </summary>
        public IEnumerable<DataFlowNode> GetTransforms()
        {
            return Nodes.Where(n => n.NodeType == DataFlowNodeType.Transform);
        }
    }

    /// <summary>
    /// Known data flow patterns that indicate specific attack types.
    /// </summary>
    public enum DataFlowPattern
    {
        /// <summary>
        /// Normal, legitimate mod behavior.
        /// </summary>
        Legitimate,

        /// <summary>
        /// Downloads data from network, decodes/decrypts it, writes to disk, then executes.
        /// Classic dropper/downloader malware pattern.
        /// </summary>
        DownloadAndExecute,

        /// <summary>
        /// Reads sensitive files or registry keys, encodes them, sends over network.
        /// Classic data exfiltration pattern.
        /// </summary>
        DataExfiltration,

        /// <summary>
        /// Loads code dynamically at runtime (Assembly.Load, Assembly.LoadFrom).
        /// Used to evade static analysis.
        /// </summary>
        DynamicCodeLoading,

        /// <summary>
        /// Reads browser data, saved passwords, or tokens, then sends to network.
        /// Credential theft pattern.
        /// </summary>
        CredentialTheft,

        /// <summary>
        /// Downloads configuration or commands from network to change behavior.
        /// Remote configuration/command and control pattern.
        /// </summary>
        RemoteConfigLoad,

        /// <summary>
        /// Encodes/obfuscates data before writing to registry or startup locations.
        /// Persistence mechanism with obfuscation.
        /// </summary>
        ObfuscatedPersistence,

        /// <summary>
        /// Suspicious data flow detected but doesn't match known patterns.
        /// </summary>
        Unknown
    }
}
