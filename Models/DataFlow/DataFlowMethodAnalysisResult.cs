using MLVScan.Models;
using Mono.Collections.Generic;
using Mono.Cecil.Cil;

namespace MLVScan.Models.DataFlow
{
    /// <summary>
    /// Internal result bundle produced while analyzing a single method for data flow.
    /// </summary>
    internal sealed class DataFlowMethodAnalysisResult
    {
        /// <summary>
        /// Stable method key for the analyzed method.
        /// </summary>
        public string MethodKey { get; set; } = string.Empty;

        /// <summary>
        /// Instructions captured from the method body.
        /// </summary>
        public Collection<Instruction> Instructions { get; set; } = new();

        /// <summary>
        /// Aggregated flow information for the method.
        /// </summary>
        public DataFlowMethodFlowInfo FlowInfo { get; set; } = new();

        /// <summary>
        /// Data-flow chains discovered while analyzing the method.
        /// </summary>
        public List<DataFlowChain> Chains { get; set; } = new();
    }
}
