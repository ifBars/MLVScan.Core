using System.Text;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    public class ObfuscatedReflectiveExecutionRule : IScanRule
    {
        private const int MinimumDecodeScore = 25;
        private const int MinimumSinkScore = 35;
        private const int MinimumTotalScore = 70;
        private const int ReflectionOnlyDangerFloor = 10;
        private const int ReflectionOnlyDecodeFloor = 45;

        public string Description =>
            "Detected correlated obfuscation/decode behavior reaching reflective or staged execution sinks.";

        public Severity Severity => Severity.High;
        public string RuleId => "ObfuscatedReflectiveExecutionRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeInstructions(
            MethodDefinition methodDef,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            MethodSignals methodSignals)
        {
            if (methodDef == null || instructions == null || instructions.Count == 0)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            ObfuscatedExecutionEvidence evidence = ObfuscatedExecutionHeuristics.CollectEvidence(instructions);
            if (!ShouldReport(evidence))
            {
                return Enumerable.Empty<ScanFinding>();
            }

            Severity severity = DetermineSeverity(evidence);
            if (severity < Severity.High)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            int anchorIndex = evidence.AnchorInstructionIndex;
            if (anchorIndex < 0 || anchorIndex >= instructions.Count)
            {
                anchorIndex = 0;
            }

            int offset = instructions[anchorIndex].Offset;
            string snippet = BuildSnippet(instructions, anchorIndex, 2);

            var finding = new ScanFinding(
                $"{methodDef.DeclaringType?.FullName}.{methodDef.Name}:{offset}",
                BuildDescription(evidence),
                severity,
                snippet) { RiskScore = evidence.TotalScore, BypassCompanionCheck = evidence.TotalScore >= 85 };

            return new[] { finding };
        }

        private static bool ShouldReport(ObfuscatedExecutionEvidence evidence)
        {
            if (evidence.SinkScore < MinimumSinkScore || evidence.DecodeScore < MinimumDecodeScore)
            {
                return false;
            }

            if (!evidence.HasStrongDecodePrimitive)
            {
                return false;
            }

            if (evidence.TotalScore < MinimumTotalScore)
            {
                return false;
            }

            bool reflectionOnly = evidence.HasReflectionInvokeSink &&
                                  !evidence.HasProcessLikeSink &&
                                  !evidence.HasAssemblyLoadSink &&
                                  !evidence.HasNativeSink;

            if (reflectionOnly && evidence.DangerScore < ReflectionOnlyDangerFloor &&
                evidence.DecodeScore < ReflectionOnlyDecodeFloor)
            {
                return false;
            }

            if (reflectionOnly &&
                !evidence.HasEncodedLiteral &&
                !evidence.HasDangerousLiteral &&
                !evidence.HasNetworkCall &&
                !evidence.HasFileWriteCall &&
                !evidence.HasSensitivePathAccess)
            {
                return false;
            }

            return true;
        }

        private static Severity DetermineSeverity(ObfuscatedExecutionEvidence evidence)
        {
            bool strongExecutionSink =
                evidence.HasProcessLikeSink || evidence.HasAssemblyLoadSink || evidence.HasNativeSink;
            bool hasDangerPivot = evidence.HasDangerousLiteral ||
                                  evidence.DangerScore >= 15 ||
                                  (evidence.HasNetworkCall && evidence.HasFileWriteCall);

            if (evidence.TotalScore >= 90 && strongExecutionSink && hasDangerPivot)
            {
                return Severity.Critical;
            }

            return Severity.High;
        }

        private static string BuildDescription(ObfuscatedExecutionEvidence evidence)
        {
            string decode = BuildReasonSegment(evidence.DecodeReasons, "decode evidence");
            string sink = BuildReasonSegment(evidence.SinkReasons, "sink evidence");
            string danger = BuildReasonSegment(evidence.DangerReasons, "context evidence");

            return
                $"Detected correlated obfuscation/decode behavior that reaches reflective or staged execution (score {evidence.TotalScore}): {decode}; {sink}; {danger}.";
        }

        private static string BuildReasonSegment(IReadOnlyList<string> reasons, string fallback)
        {
            if (reasons.Count == 0)
            {
                return fallback;
            }

            return string.Join(", ", reasons.Take(3));
        }

        private static string BuildSnippet(Mono.Collections.Generic.Collection<Instruction> instructions,
            int centerIndex, int context)
        {
            var snippetBuilder = new StringBuilder();
            int start = Math.Max(0, centerIndex - context);
            int end = Math.Min(instructions.Count - 1, centerIndex + context);

            for (int i = start; i <= end; i++)
            {
                snippetBuilder.Append(i == centerIndex ? ">>> " : "    ");
                snippetBuilder.AppendLine(instructions[i].ToString());
            }

            return snippetBuilder.ToString().TrimEnd();
        }
    }
}
