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

        /// <summary>
        /// Stable identity for the file path consumed by a file-write or process-execution operation.
        /// Local identities include the containing method so unrelated locals in cross-method chains
        /// cannot be mistaken for the same payload.
        /// </summary>
        public string? PayloadPathIdentity { get; set; }
    }
}
