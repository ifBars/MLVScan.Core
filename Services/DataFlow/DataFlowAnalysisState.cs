using MLVScan.Models;
using MLVScan.Models.DataFlow;
using Mono.Collections.Generic;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DataFlowAnalysisState
    {
        public Dictionary<string, List<DataFlowChain>> MethodDataFlows { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, DataFlowMethodFlowInfo> MethodFlowInfos { get; } = new(StringComparer.Ordinal);

        public List<DataFlowChain> CrossMethodChains { get; } = new();

        public Dictionary<string, Collection<Instruction>> MethodInstructions { get; } =
            new(StringComparer.Ordinal);

        public HashSet<string> IncompleteMethodKeys { get; } = new(StringComparer.Ordinal);

        public bool CrossMethodAnalysisComplete { get; set; } = true;

        public void Clear()
        {
            MethodDataFlows.Clear();
            MethodFlowInfos.Clear();
            CrossMethodChains.Clear();
            MethodInstructions.Clear();
            IncompleteMethodKeys.Clear();
            CrossMethodAnalysisComplete = true;
        }

        public void StoreMethodAnalysis(DataFlowMethodAnalysisResult analysis)
        {
            MethodInstructions[analysis.MethodKey] = analysis.Instructions;
            MethodFlowInfos[analysis.MethodKey] = analysis.FlowInfo;
            MethodDataFlows[analysis.MethodKey] = analysis.Chains;
            if (!analysis.AnalysisComplete)
            {
                IncompleteMethodKeys.Add(analysis.MethodKey);
            }
            else
            {
                IncompleteMethodKeys.Remove(analysis.MethodKey);
            }
        }

        public Collection<Instruction> GetInstructionsForMethod(string methodKey)
        {
            if (MethodInstructions.TryGetValue(methodKey, out var instructions))
            {
                return instructions;
            }

            return new Collection<Instruction>();
        }
    }
}
