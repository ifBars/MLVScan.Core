namespace MLVScan.Models.DataFlow
{
    internal sealed class DataFlowMethodFlowInfo
    {
        public string MethodKey { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public bool HasSource { get; set; }

        public bool HasSink { get; set; }

        public bool HasTransform { get; set; }

        public bool ReturnsData { get; set; }

        public string? ReturnTypeName { get; set; }

        public List<DataFlowInterestingOperation> Operations { get; set; } = new();

        public List<DataFlowMethodCallSite> OutgoingCalls { get; } = new();

        public List<DataFlowInterestingOperation> ReturnProducingOperations { get; set; } = new();
    }
}
