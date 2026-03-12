using MLVScan.Models;
using MLVScan.Models.DataFlow;
using Mono.Collections.Generic;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DataFlowNodeFactory
    {
        private readonly CodeSnippetBuilder _snippetBuilder;

        public DataFlowNodeFactory(CodeSnippetBuilder snippetBuilder)
        {
            _snippetBuilder = snippetBuilder ?? throw new ArgumentNullException(nameof(snippetBuilder));
        }

        public DataFlowNode CreateOperationNode(
            string methodKey,
            string displayName,
            Collection<Instruction> instructions,
            DataFlowInterestingOperation operation,
            string? descriptionOverride = null)
        {
            var snippet = _snippetBuilder.BuildSnippet(instructions, operation.InstructionIndex, 1);

            return new DataFlowNode(
                $"{displayName}:{operation.Instruction.Offset}",
                operation.Operation,
                operation.NodeType,
                descriptionOverride ?? operation.DataDescription,
                operation.Instruction.Offset,
                snippet,
                methodKey);
        }

        public DataFlowNode CreateBoundaryNode(
            string methodKey,
            string displayName,
            Collection<Instruction> instructions,
            int instructionIndex,
            int instructionOffset,
            string operation,
            string description,
            string targetMethodKey)
        {
            var snippet = _snippetBuilder.BuildSnippet(instructions, instructionIndex, 1);

            return new DataFlowNode(
                $"{displayName}:{instructionOffset}",
                operation,
                DataFlowNodeType.Intermediate,
                description,
                instructionOffset,
                snippet,
                methodKey)
            {
                IsMethodBoundary = true,
                TargetMethodKey = targetMethodKey
            };
        }
    }
}
