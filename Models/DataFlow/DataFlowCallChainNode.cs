namespace MLVScan.Models.DataFlow
{
    /// <summary>
    /// Internal node used to build cross-method data-flow call chains.
    /// </summary>
    internal sealed class DataFlowCallChainNode
    {
        /// <summary>
        /// Flow information for the current method in the chain.
        /// </summary>
        public DataFlowMethodFlowInfo MethodInfo { get; set; } = null!;

        /// <summary>
        /// Optional call-site information that led into this method.
        /// </summary>
        public DataFlowMethodCallSite? IncomingCallSite { get; set; }

        /// <summary>
        /// Child nodes reached from this method.
        /// </summary>
        public List<DataFlowCallChainNode> ChildNodes { get; } = new();

        /// <summary>
        /// Methods visited while expanding this chain.
        /// </summary>
        public HashSet<string> VisitedMethods { get; set; } = new(StringComparer.Ordinal);
    }
}
