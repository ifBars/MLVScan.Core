using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Builds obfuscation evidence by combining decode, sink, and context heuristics across IL instructions.
    /// </summary>
    internal static class ObfuscatedExecutionHeuristics
    {
        /// <summary>
        /// Collects the evidence used by <see cref="ObfuscatedReflectiveExecutionRule"/> to score a method body.
        /// </summary>
        /// <param name="instructions">The method body instructions to analyze.</param>
        /// <returns>A populated evidence object with decode, sink, and danger scores.</returns>
        public static ObfuscatedExecutionEvidence CollectEvidence(
            Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            var evidence = new ObfuscatedExecutionEvidence();

            for (int i = 0; i < instructions.Count; i++)
            {
                Instruction instruction = instructions[i];

                if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string literal)
                {
                    ObfuscatedExecutionPatternMatcher.AnalyzeLiteral(literal, i, evidence);
                }

                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                    instruction.Operand is MethodReference calledMethod)
                {
                    ObfuscatedExecutionPatternMatcher.AnalyzeCall(instructions, i, calledMethod, evidence);
                    DetectCharConcatenationChain(instructions, i, calledMethod, evidence);
                }

                if (instruction.OpCode == OpCodes.Conv_U1 || instruction.OpCode == OpCodes.Conv_U2 ||
                    instruction.OpCode == OpCodes.Conv_I1 || instruction.OpCode == OpCodes.Conv_I2)
                {
                    evidence.AddDecode(3, "numeric-to-character conversion", i);
                }

                if (instruction.OpCode == OpCodes.Newarr && instruction.Operand is TypeReference arrayType)
                {
                    string arrayTypeName = arrayType.FullName;
                    if (arrayTypeName == "System.Byte" || arrayTypeName == "System.Char")
                    {
                        evidence.AddDecode(5, $"{arrayTypeName} array materialization", i);
                    }
                }
            }

            evidence.TotalScore = ComputeTotalScore(evidence);
            return evidence;
        }

        private static void DetectCharConcatenationChain(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            ObfuscatedExecutionEvidence evidence)
        {
            string typeName = calledMethod.DeclaringType?.FullName ?? string.Empty;
            string methodName = calledMethod.Name ?? string.Empty;

            if (typeName != "System.String" || methodName != "Concat")
                return;

            int singleCharStringCount = 0;
            int shortStringCount = 0;
            int lookback = Math.Min(15, callIndex);

            for (int i = callIndex - 1; i >= callIndex - lookback; i--)
            {
                Instruction instr = instructions[i];

                if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                    break;

                if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string s)
                {
                    if (s.Length == 1)
                        singleCharStringCount++;
                    else if (s.Length <= 3)
                        shortStringCount++;
                }
            }

            if (singleCharStringCount >= 4)
            {
                evidence.HasStrongDecodePrimitive = true;
                evidence.AddDecode(12, $"single-char concatenation chain ({singleCharStringCount} chars)", callIndex);
            }
            else if (singleCharStringCount + shortStringCount >= 5)
            {
                evidence.HasStrongDecodePrimitive = true;
                evidence.AddDecode(10, "short-string concatenation chain", callIndex);
            }
        }

        private static int ComputeTotalScore(ObfuscatedExecutionEvidence evidence)
        {
            int total = evidence.DecodeScore + evidence.SinkScore + evidence.DangerScore;

            if (evidence.HasEncodedLiteral && evidence.HasDynamicTargetResolution)
            {
                total += 8;
            }

            if (evidence.HasReflectionInvokeSink &&
                (evidence.HasProcessLikeSink || evidence.HasAssemblyLoadSink || evidence.HasNativeSink))
            {
                total += 10;
            }

            if (evidence.HasNetworkCall && evidence.HasFileWriteCall)
            {
                total += 8;
            }

            if (evidence.HasDangerousLiteral && (evidence.HasProcessLikeSink || evidence.HasNativeSink))
            {
                total += 10;
            }

            if (evidence.HasSensitivePathAccess && (evidence.HasFileWriteCall || evidence.HasProcessLikeSink))
            {
                total += 6;
            }

            return Math.Min(total, 100);
        }
    }
}
