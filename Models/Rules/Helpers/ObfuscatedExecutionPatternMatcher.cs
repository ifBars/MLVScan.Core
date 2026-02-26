using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    internal static class ObfuscatedExecutionPatternMatcher
    {
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

            if (ObfuscatedDecodeMatcher.TryGetDangerLiteralMarker(literal, out string marker))
            {
                evidence.HasDangerousLiteral = true;
                evidence.AddDanger(12, $"suspicious literal '{marker}'", index);
            }
        }

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
                if (folderValue.HasValue && EnvironmentPathRule.IsSensitiveFolder(folderValue.Value))
                {
                    evidence.HasSensitivePathAccess = true;
                    string folderName = EnvironmentPathRule.GetFolderName(folderValue.Value);
                    evidence.AddDanger(8, $"sensitive folder access ({folderName})", index);
                }
            }
        }
    }
}
