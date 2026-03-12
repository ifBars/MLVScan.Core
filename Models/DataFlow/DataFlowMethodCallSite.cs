namespace MLVScan.Models.DataFlow
{
    internal sealed class DataFlowMethodCallSite
    {
        public string TargetMethodKey { get; set; } = string.Empty;

        public string TargetDisplayName { get; set; } = string.Empty;

        public int InstructionOffset { get; set; }

        public int InstructionIndex { get; set; }

        public Dictionary<int, int> ParameterMapping { get; set; } = new();

        public bool ReturnValueUsed { get; set; }

        public bool CalledMethodReturnsData { get; set; }
    }
}
