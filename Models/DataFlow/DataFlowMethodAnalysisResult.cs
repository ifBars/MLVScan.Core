using MLVScan.Models;
using MLVScan.Models.DataFlow;
using Mono.Collections.Generic;
using Mono.Cecil.Cil;

namespace MLVScan.Models.DataFlow
{
    internal sealed class DataFlowMethodAnalysisResult
    {
        public string MethodKey { get; set; } = string.Empty;

        public Collection<Instruction> Instructions { get; set; } = new();

        public DataFlowMethodFlowInfo FlowInfo { get; set; } = new();

        public List<DataFlowChain> Chains { get; set; } = new();
    }
}
