namespace MLVScan.Models.DataFlow
{
    internal sealed class DataFlowCallChainNode
    {
        public DataFlowMethodFlowInfo MethodInfo { get; set; } = null!;

        public DataFlowMethodCallSite? IncomingCallSite { get; set; }

        public List<DataFlowCallChainNode> ChildNodes { get; } = new();

        public HashSet<string> VisitedMethods { get; set; } = new(StringComparer.Ordinal);
    }
}
