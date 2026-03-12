using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.DataFlow
{
    internal sealed class DataFlowInterestingOperation
    {
        public Instruction Instruction { get; set; } = null!;

        public int InstructionIndex { get; set; }

        public MethodReference MethodReference { get; set; } = null!;

        public DataFlowNodeType NodeType { get; set; }

        public string Operation { get; set; } = string.Empty;

        public string DataDescription { get; set; } = string.Empty;

        public int? LocalVariableIndex { get; set; }
    }
}
