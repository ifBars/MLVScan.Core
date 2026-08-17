using MLVScan.Services.Helpers;
using Mono.Collections.Generic;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    /// <summary>
    /// Reuses control-flow state and bounds cumulative reaching-definition work for one method.
    /// </summary>
    internal sealed class DataFlowReachingDefinitionAnalysis
    {
        private const int MinimumWorkBudget = 16_384;
        private const int WorkBudgetMultiplier = 256;

        private readonly object _sync = new();
        private readonly Collection<Instruction> _instructions;
        private readonly Dictionary<(int ConsumerIndex, int LocalIndex), IReadOnlyCollection<int>>
            _localStoreCache = new();
        private IReadOnlyDictionary<Instruction, int>? _instructionIndexes;
        private List<int>[]? _predecessors;

        public DataFlowReachingDefinitionAnalysis(Collection<Instruction> instructions)
        {
            _instructions = instructions ?? throw new ArgumentNullException(nameof(instructions));
            WorkBudget = (int)Math.Min(
                int.MaxValue,
                Math.Max(MinimumWorkBudget, (long)Math.Max(1, instructions.Count) * WorkBudgetMultiplier));
        }

        public bool IsComplete { get; private set; } = true;

        internal int ControlFlowGraphBuildCount { get; private set; }

        internal int WorkBudget { get; }

        internal int WorkUnitsConsumed { get; private set; }

        public bool TryGetReachingLocalStoreIndexes(
            int consumerIndex,
            int localIndex,
            out IReadOnlyCollection<int> definitionIndexes)
        {
            lock (_sync)
            {
                if (!IsComplete)
                {
                    definitionIndexes = Array.Empty<int>();
                    return false;
                }

                var cacheKey = (consumerIndex, localIndex);
                if (_localStoreCache.TryGetValue(cacheKey, out definitionIndexes!))
                {
                    return true;
                }

                if (!TryGetReachingInstructionIndexesCore(
                        consumerIndex,
                        index => _instructions[index].TryGetStoredLocalIndex(out var storedLocalIndex) &&
                                 storedLocalIndex == localIndex,
                        out definitionIndexes))
                {
                    definitionIndexes = Array.Empty<int>();
                    return false;
                }

                _localStoreCache[cacheKey] = definitionIndexes;
                return true;
            }
        }

        public bool TryGetReachingInstructionIndexes(
            int consumerIndex,
            Func<int, bool> isDefinition,
            out IReadOnlyCollection<int> definitionIndexes)
        {
            if (isDefinition == null)
            {
                throw new ArgumentNullException(nameof(isDefinition));
            }

            lock (_sync)
            {
                return TryGetReachingInstructionIndexesCore(
                    consumerIndex,
                    isDefinition,
                    out definitionIndexes);
            }
        }

        public bool TryFindTopValueProducer(int beforeIndex, out int producerIndex)
        {
            lock (_sync)
            {
                producerIndex = -1;
                var needed = 1;

                for (var index = beforeIndex; index >= 0; index--)
                {
                    if (!TryConsumeWorkUnit())
                    {
                        return false;
                    }

                    var instruction = _instructions[index];
                    needed -= instruction.GetPushCount();
                    if (needed <= 0)
                    {
                        producerIndex = index;
                        return true;
                    }

                    needed += instruction.GetPopCount();
                }

                return false;
            }
        }

        public bool TryFindValueExpressionStart(int producerIndex, out int expressionStart)
        {
            lock (_sync)
            {
                expressionStart = -1;
                var needed = 1;
                for (var index = producerIndex; index >= 0; index--)
                {
                    if (!TryConsumeWorkUnit())
                    {
                        return false;
                    }

                    needed -= _instructions[index].GetPushCount();
                    needed += _instructions[index].GetPopCount();
                    if (needed <= 0)
                    {
                        expressionStart = index;
                        return true;
                    }
                }

                return false;
            }
        }

        private bool TryGetReachingInstructionIndexesCore(
            int consumerIndex,
            Func<int, bool> isDefinition,
            out IReadOnlyCollection<int> definitionIndexes)
        {
            definitionIndexes = Array.Empty<int>();
            if (!IsComplete || consumerIndex < 0 || consumerIndex >= _instructions.Count || !EnsureControlFlowGraph())
            {
                return false;
            }

            var definitions = new HashSet<int>();
            var pending = new Stack<int>(_predecessors![consumerIndex]);
            var visited = new HashSet<int>();
            while (pending.Count > 0)
            {
                if (!TryConsumeWorkUnit())
                {
                    return false;
                }

                var index = pending.Pop();
                if (!visited.Add(index))
                {
                    continue;
                }

                if (isDefinition(index))
                {
                    definitions.Add(index);
                    continue;
                }

                if (!IsComplete)
                {
                    return false;
                }

                foreach (var predecessor in _predecessors[index])
                {
                    pending.Push(predecessor);
                }
            }

            definitionIndexes = definitions;
            return true;
        }

        private bool EnsureControlFlowGraph()
        {
            if (_predecessors != null)
            {
                return IsComplete;
            }

            ControlFlowGraphBuildCount++;
            _instructionIndexes = _instructions
                .Select((instruction, index) => (instruction, index))
                .ToDictionary(static entry => entry.instruction, static entry => entry.index);
            _predecessors = Enumerable.Range(0, _instructions.Count)
                .Select(_ => new List<int>())
                .ToArray();

            for (var index = 0; index < _instructions.Count; index++)
            {
                foreach (var successor in GetSuccessorIndexes(index))
                {
                    if (!TryConsumeWorkUnit())
                    {
                        return false;
                    }

                    _predecessors[successor].Add(index);
                }
            }

            return true;
        }

        private IEnumerable<int> GetSuccessorIndexes(int index)
        {
            var instruction = _instructions[index];
            if (instruction.Operand is Instruction target)
            {
                if (_instructionIndexes!.TryGetValue(target, out var targetIndex))
                {
                    yield return targetIndex;
                }
            }
            else if (instruction.Operand is Instruction[] targets)
            {
                foreach (var switchTarget in targets)
                {
                    if (_instructionIndexes!.TryGetValue(switchTarget, out var switchTargetIndex))
                    {
                        yield return switchTargetIndex;
                    }
                }
            }

            if (index + 1 >= _instructions.Count ||
                instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Return or FlowControl.Throw)
            {
                yield break;
            }

            yield return index + 1;
        }

        private bool TryConsumeWorkUnit()
        {
            if (!IsComplete || WorkUnitsConsumed >= WorkBudget)
            {
                IsComplete = false;
                return false;
            }

            WorkUnitsConsumed++;
            return true;
        }
    }
}
