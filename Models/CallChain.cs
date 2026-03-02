namespace MLVScan.Models
{
    /// <summary>
    /// Represents a single node in a call chain (one method call or declaration site).
    /// </summary>
    public class CallChainNode
    {
        /// <summary>
        /// Full method signature (e.g., "Namespace.Type.Method:offset" or "Namespace.Type.Method" for declarations).
        /// </summary>
        public string Location { get; set; }

        /// <summary>
        /// The code snippet at this location.
        /// </summary>
        public string? CodeSnippet { get; set; }

        /// <summary>
        /// Description of what happens at this node (e.g., "P/Invoke declaration for shell32.dll", "Calls southwards.ShellExecuteA").
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// The type of node in the call chain.
        /// </summary>
        public CallChainNodeType NodeType { get; set; }

        public CallChainNode(string location, string description, CallChainNodeType nodeType,
            string? codeSnippet = null)
        {
            Location = location;
            Description = description;
            NodeType = nodeType;
            CodeSnippet = codeSnippet;
        }

        public override string ToString()
        {
            var prefix = NodeType switch
            {
                CallChainNodeType.EntryPoint => "[ENTRY]",
                CallChainNodeType.IntermediateCall => "[CALL]",
                CallChainNodeType.SuspiciousDeclaration => "[DECL]",
                _ => "[???]"
            };
            return $"{prefix} {Location}: {Description}";
        }
    }

    /// <summary>
    /// The type of node in a call chain.
    /// </summary>
    public enum CallChainNodeType
    {
        /// <summary>
        /// The entry point where the malicious flow originates (e.g., OnMelonInitialize calling the wrapper).
        /// </summary>
        EntryPoint,

        /// <summary>
        /// An intermediate method call in the chain.
        /// </summary>
        IntermediateCall,

        /// <summary>
        /// The suspicious declaration itself (e.g., P/Invoke, reflection invoke).
        /// </summary>
        SuspiciousDeclaration
    }

    /// <summary>
    /// Represents a complete call chain from an entry point to a suspicious declaration.
    /// Used to consolidate multiple findings that are part of the same attack pattern.
    /// </summary>
    public class CallChain
    {
        /// <summary>
        /// Unique identifier for this call chain (for deduplication and grouping).
        /// </summary>
        public string ChainId { get; set; }

        /// <summary>
        /// The rule that detected this suspicious pattern.
        /// </summary>
        public string RuleId { get; set; }

        /// <summary>
        /// The nodes in this call chain, ordered from entry point to suspicious declaration.
        /// </summary>
        public List<CallChainNode> Nodes { get; set; } = new();

        /// <summary>
        /// The overall severity of this call chain (inherited from the triggering rule).
        /// </summary>
        public Severity Severity { get; set; }

        /// <summary>
        /// Human-readable summary of the attack pattern.
        /// </summary>
        public string Summary { get; set; }

        public CallChain(string chainId, string ruleId, Severity severity, string summary)
        {
            ChainId = chainId;
            RuleId = ruleId;
            Severity = severity;
            Summary = summary;
        }

        /// <summary>
        /// Adds a node to the beginning of the chain (caller side).
        /// </summary>
        public void PrependNode(CallChainNode node)
        {
            Nodes.Insert(0, node);
        }

        /// <summary>
        /// Adds a node to the end of the chain (callee side).
        /// </summary>
        public void AppendNode(CallChainNode node)
        {
            Nodes.Add(node);
        }

        /// <summary>
        /// Generates a formatted description of the full call chain.
        /// </summary>
        public string ToDetailedDescription()
        {
            if (Nodes.Count == 0)
                return Summary;

            var lines = new List<string> { Summary, "", "Call chain:" };

            for (int i = 0; i < Nodes.Count; i++)
            {
                var node = Nodes[i];
                var indent = new string(' ', i * 2);
                var arrow = i > 0 ? "-> " : "";
                lines.Add($"{indent}{arrow}{node}");
            }

            return string.Join("\n", lines);
        }

        /// <summary>
        /// Creates a combined code snippet showing all nodes in the chain.
        /// </summary>
        public string? ToCombinedCodeSnippet()
        {
            var snippets = Nodes
                .Where(n => !string.IsNullOrEmpty(n.CodeSnippet))
                .Select(n => $"// {n.Location}\n{n.CodeSnippet}")
                .ToList();

            return snippets.Count > 0 ? string.Join("\n\n", snippets) : null;
        }
    }
}
