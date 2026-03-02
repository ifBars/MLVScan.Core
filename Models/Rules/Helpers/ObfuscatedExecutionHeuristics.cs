using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    internal static class ObfuscatedExecutionHeuristics
    {
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
