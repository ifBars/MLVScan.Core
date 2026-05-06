using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Collects nearby URL-like string candidates, including simple adjacent literal concatenations.
    /// </summary>
    internal static class UrlLiteralCollector
    {
        public static IReadOnlyList<string> CollectCandidates(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int windowStart,
            int windowEnd)
        {
            var candidates = new List<string>();
            var literalRun = new List<string>();

            for (int index = windowStart; index < windowEnd; index++)
            {
                var instruction = instructions[index];
                if (instruction.OpCode == OpCodes.Ldstr &&
                    instruction.Operand is string literal &&
                    !string.IsNullOrWhiteSpace(literal))
                {
                    candidates.Add(literal);
                    literalRun.Add(literal);
                    AddConcatenatedRunCandidates(literalRun, candidates);
                    continue;
                }

                literalRun.Clear();
            }

            return candidates.Distinct(StringComparer.Ordinal).ToList();
        }

        private static void AddConcatenatedRunCandidates(List<string> literalRun, List<string> candidates)
        {
            if (literalRun.Count < 2)
                return;

            const int maxSegments = 6;
            var start = Math.Max(0, literalRun.Count - maxSegments);
            var combined = string.Concat(literalRun.Skip(start));

            if (!string.IsNullOrWhiteSpace(combined))
            {
                candidates.Add(combined);
            }
        }
    }
}
