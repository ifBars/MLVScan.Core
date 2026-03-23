using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Applies literal and call-site heuristics that feed the obfuscated execution scorer.
    /// </summary>
    internal static class ObfuscatedExecutionPatternMatcher
    {
        /// <summary>
        /// Scores a string literal for obfuscation characteristics and suspicious recovered content.
        /// </summary>
        /// <param name="literal">The literal to inspect.</param>
        /// <param name="index">The instruction index where the literal appears.</param>
        /// <param name="evidence">The evidence bag to update.</param>
        public static void AnalyzeLiteral(string literal, int index, ObfuscatedExecutionEvidence evidence)
        {
            if (string.IsNullOrWhiteSpace(literal))
            {
                return;
            }

            if (ObfuscatedDecodeMatcher.IsTokenizedNumericLiteral(literal))
            {
                evidence.HasEncodedLiteral = true;
                evidence.HasStrongDecodePrimitive = true;
                evidence.AddDecode(18, "tokenized numeric literal", index);
            }

            if (ObfuscatedDecodeMatcher.IsBase64LikeLiteral(literal))
            {
                evidence.HasEncodedLiteral = true;
                evidence.HasStrongDecodePrimitive = true;
                evidence.AddDecode(10, "base64-like literal", index);
            }

            if (ObfuscatedDecodeMatcher.IsHexLikeLiteral(literal))
            {
                evidence.HasEncodedLiteral = true;
                evidence.HasStrongDecodePrimitive = true;
                evidence.AddDecode(8, "hex-like literal", index);
            }

            if (ObfuscatedDecodeMatcher.TryGetInvisibleUnicodeLiteralReason(literal, out string invisibleReason,
                    out bool hasSuspiciousDecodedContent))
            {
                evidence.HasEncodedLiteral = true;
                evidence.HasStrongDecodePrimitive = true;
                evidence.AddDecode(hasSuspiciousDecodedContent ? 20 : 14, invisibleReason, index);

                if (hasSuspiciousDecodedContent)
                {
                    evidence.HasDangerousLiteral = true;
                    evidence.AddDanger(14, "suspicious content recovered from invisible Unicode payload", index);
                }
            }

            if (ObfuscatedDecodeMatcher.TryGetDangerLiteralMarker(literal, out string marker))
            {
                evidence.HasDangerousLiteral = true;
                evidence.AddDanger(12, $"suspicious literal '{marker}'", index);
            }
        }

        /// <summary>
        /// Scores a method call for decode primitives, execution sinks, and contextual danger signals.
        /// </summary>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="index">The instruction index of the call.</param>
        /// <param name="calledMethod">The method being called.</param>
        /// <param name="evidence">The evidence bag to update.</param>
        public static void AnalyzeCall(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int index,
            MethodReference calledMethod,
            ObfuscatedExecutionEvidence evidence)
        {
            string typeName = calledMethod.DeclaringType?.FullName ?? string.Empty;
            string methodName = calledMethod.Name ?? string.Empty;

            if (ObfuscatedDecodeMatcher.TryGetDecodeCallScore(
                    calledMethod,
                    typeName,
                    methodName,
                    out int decodeScore,
                    out string? decodeReason,
                    out bool isStrongDecodePrimitive))
            {
                evidence.AddDecode(decodeScore, decodeReason!, index);
                if (isStrongDecodePrimitive)
                {
                    evidence.HasStrongDecodePrimitive = true;
                }
            }

            if (ObfuscatedSinkMatcher.IsReflectionInvokeSink(typeName, methodName))
            {
                evidence.HasReflectionInvokeSink = true;
                evidence.AddSink(40, "reflection invoke sink", index);
            }

            if (ObfuscatedSinkMatcher.IsAssemblyLoadSink(typeName, methodName))
            {
                evidence.HasAssemblyLoadSink = true;
                evidence.AddSink(42, "dynamic assembly loading sink", index);
            }

            if (ObfuscatedSinkMatcher.IsProcessSink(typeName, methodName))
            {
                evidence.HasProcessLikeSink = true;
                evidence.AddSink(45, "process execution sink", index);
            }

            if (ObfuscatedSinkMatcher.IsPotentialNativeExecutionSink(calledMethod, typeName, methodName))
            {
                evidence.HasNativeSink = true;
                evidence.AddSink(35, "native execution bridge", index);
            }

            if (ObfuscatedSinkMatcher.IsDynamicTargetResolution(typeName, methodName))
            {
                evidence.HasDynamicTargetResolution = true;
                evidence.AddDecode(4, "dynamic target resolution", index);
            }

            if (ObfuscatedSinkMatcher.IsNetworkCall(typeName, methodName))
            {
                evidence.HasNetworkCall = true;
                evidence.AddDanger(12, "network transfer primitive", index);
            }

            if (ObfuscatedSinkMatcher.IsFileWriteCall(typeName, methodName))
            {
                evidence.HasFileWriteCall = true;
                evidence.AddDanger(12, "file write primitive", index);
            }

            if (typeName == "System.Environment" && methodName == "GetFolderPath")
            {
                int? folderValue = ObfuscatedSinkMatcher.ExtractFolderPathArgument(instructions, index);
                if (folderValue.HasValue && PersistenceRule.IsSensitiveFolder(folderValue.Value))
                {
                    evidence.HasSensitivePathAccess = true;
                    string folderName = PersistenceRule.GetFolderName(folderValue.Value);
                    evidence.AddDanger(8, $"sensitive folder access ({folderName})", index);
                }
            }
        }
    }
}
