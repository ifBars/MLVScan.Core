using System.Text;
using MLVScan.Models.Rules;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.Helpers
{
    internal static class DllImportInvocationContextExtractor
    {
        private const int SearchWindow = 240;

        private static readonly string[] ShellExecuteInfoFieldOrder =
        [
            "lpVerb",
            "lpFile",
            "lpParameters",
            "lpDirectory",
            "nShow"
        ];

        public static string? TryBuildContext(
            MethodDefinition callerMethod,
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callInstructionIndex)
        {
            if (!TryGetPInvokeEntryPoint(calledMethod, out var entryPoint))
                return null;

            if (!entryPoint.StartsWith("ShellExecute", StringComparison.OrdinalIgnoreCase))
                return null;

            return BuildShellExecuteContext(callerMethod, instructions, callInstructionIndex);
        }

        public static bool IsNativeExecutionPInvoke(MethodReference calledMethod)
        {
            if (!TryGetPInvokeEntryPoint(calledMethod, out var entryPoint))
                return false;

            return DllImportRule.IsNativeExecutionEntryPoint(entryPoint);
        }

        private static string? BuildShellExecuteContext(
            MethodDefinition callerMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callInstructionIndex)
        {
            var fieldValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (TryGetCallArgumentAddressLocalIndex(instructions, callInstructionIndex, out var structLocalIndex))
            {
                ExtractShellExecuteInfoFieldValues(callerMethod, instructions, callInstructionIndex, structLocalIndex,
                    fieldValues);
            }

            var builder = new StringBuilder();
            if (fieldValues.Count > 0)
            {
                builder.Append("Invocation context: ");
                var orderedFields = new List<string>();

                foreach (var fieldName in ShellExecuteInfoFieldOrder)
                {
                    if (!fieldValues.TryGetValue(fieldName, out var value))
                        continue;

                    orderedFields.Add($"{fieldName}={value}");
                }

                builder.Append(string.Join(", ", orderedFields));
            }

            if (TryBuildPreCallBehaviorHint(instructions, callInstructionIndex, out var preCallHint))
            {
                if (builder.Length > 0)
                    builder.Append(". ");

                builder.Append(preCallHint);
            }

            if (builder.Length == 0)
                return null;

            return builder.ToString();
        }

        private static void ExtractShellExecuteInfoFieldValues(
            MethodDefinition callerMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callInstructionIndex,
            int structLocalIndex,
            IDictionary<string, string> fieldValues)
        {
            var searchStart = Math.Max(0, callInstructionIndex - SearchWindow);

            for (var i = callInstructionIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if (instruction.OpCode != OpCodes.Stfld || instruction.Operand is not FieldReference fieldRef)
                    continue;

                if (!IsTrackedShellExecuteInfoField(fieldRef.Name) || fieldValues.ContainsKey(fieldRef.Name))
                    continue;

                if (!IsFieldStoreForStructLocal(instructions, i, structLocalIndex))
                    continue;

                if (fieldRef.Name.Equals("lpFile", StringComparison.OrdinalIgnoreCase) &&
                    TryReconstructTempScriptLpFilePath(instructions, i, out var reconstructedPath))
                {
                    fieldValues[fieldRef.Name] = NormalizeDisplayValue(reconstructedPath);
                    continue;
                }

                if (InstructionValueResolver.TryResolveStackValueDisplay(callerMethod, instructions, i - 1,
                        out var resolvedValue))
                {
                    fieldValues[fieldRef.Name] = NormalizeDisplayValue(resolvedValue);
                }
            }
        }

        private static bool TryBuildPreCallBehaviorHint(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callInstructionIndex,
            out string hint)
        {
            hint = string.Empty;

            var searchStart = Math.Max(0, callInstructionIndex - SearchWindow);
            var sawResourceLoad = false;
            var sawFileWrite = false;
            var sawTempPath = false;
            var sawScriptLikeLiteral = false;

            for (var i = searchStart; i < callInstructionIndex; i++)
            {
                var instruction = instructions[i];

                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt ||
                     instruction.OpCode == OpCodes.Newobj) &&
                    instruction.Operand is MethodReference methodRef)
                {
                    var declaringType = methodRef.DeclaringType?.FullName ?? string.Empty;
                    var methodName = methodRef.Name;

                    if (declaringType == "System.Reflection.Assembly" && methodName == "GetManifestResourceStream")
                    {
                        sawResourceLoad = true;
                    }

                    if ((declaringType.StartsWith("System.IO.File", StringComparison.Ordinal) &&
                         (methodName.Contains("Write", StringComparison.Ordinal) ||
                          methodName.Contains("Create", StringComparison.Ordinal))) ||
                        (declaringType == "System.IO.FileStream" && methodName == ".ctor") ||
                        (declaringType == "System.IO.Stream" && methodName == "CopyTo"))
                    {
                        sawFileWrite = true;
                    }

                    if (declaringType == "System.IO.Path" && methodName == "GetTempPath")
                    {
                        sawTempPath = true;
                    }
                }

                if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string literal)
                {
                    if (literal.Contains(".cmd", StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains(".bat", StringComparison.OrdinalIgnoreCase) ||
                        literal.Contains(".ps1", StringComparison.OrdinalIgnoreCase))
                    {
                        sawScriptLikeLiteral = true;
                    }
                }
            }

            if (!sawResourceLoad && !sawFileWrite)
                return false;

            if (sawResourceLoad && sawFileWrite)
            {
                hint = "Pre-call behavior: embedded resource is materialized and written to disk";
                if (sawTempPath || sawScriptLikeLiteral)
                {
                    hint += " (temp script dropper pattern)";
                }

                return true;
            }

            if (sawResourceLoad)
            {
                hint = "Pre-call behavior: embedded resource access observed";
                return true;
            }

            if (sawFileWrite)
            {
                hint = "Pre-call behavior: file write observed before native execution";
                return true;
            }

            return false;
        }

        private static bool TryGetCallArgumentAddressLocalIndex(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callInstructionIndex,
            out int localIndex)
        {
            localIndex = -1;
            if (callInstructionIndex <= 0)
                return false;

            if (TryGetAddressedLocalIndex(instructions[callInstructionIndex - 1], out localIndex))
                return true;

            for (var i = callInstructionIndex - 1; i >= Math.Max(0, callInstructionIndex - 6); i--)
            {
                if (!TryGetAddressedLocalIndex(instructions[i], out localIndex))
                    continue;

                return true;
            }

            return false;
        }

        private static bool IsFieldStoreForStructLocal(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int fieldStoreIndex,
            int expectedLocalIndex)
        {
            var searchStart = Math.Max(0, fieldStoreIndex - 6);
            for (var i = fieldStoreIndex - 1; i >= searchStart; i--)
            {
                if (!TryGetAddressedLocalIndex(instructions[i], out var localIndex))
                    continue;

                return localIndex == expectedLocalIndex;
            }

            return false;
        }

        private static bool TryGetAddressedLocalIndex(Instruction instruction, out int localIndex)
        {
            localIndex = -1;

            if (instruction.OpCode == OpCodes.Ldloca_S && instruction.Operand is VariableDefinition localS)
            {
                localIndex = localS.Index;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldloca && instruction.Operand is VariableDefinition local)
            {
                localIndex = local.Index;
                return true;
            }

            return false;
        }

        private static bool TryReconstructTempScriptLpFilePath(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int lpFileStoreIndex,
            out string path)
        {
            path = string.Empty;

            if (lpFileStoreIndex < 2)
                return false;

            if (!instructions[lpFileStoreIndex - 1].TryGetLocalIndex(out var lpFileLocalIndex))
                return false;

            var searchStart = Math.Max(0, lpFileStoreIndex - SearchWindow);
            for (var i = lpFileStoreIndex - 2; i >= searchStart; i--)
            {
                if (!instructions[i].TryGetStoredLocalIndex(out var storedLocalIndex) ||
                    storedLocalIndex != lpFileLocalIndex)
                {
                    continue;
                }

                if (!TryBuildTempScriptPathFromStore(instructions, i, out path))
                    return false;

                return true;
            }

            return false;
        }

        private static bool TryBuildTempScriptPathFromStore(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int localStoreIndex,
            out string path)
        {
            path = string.Empty;

            if (localStoreIndex <= 0)
                return false;

            if (!IsPathCombineCall(instructions[localStoreIndex - 1]))
                return false;

            var searchStart = Math.Max(0, localStoreIndex - SearchWindow);
            bool sawTempPath = false;
            bool sawGuid = false;
            string? scriptExtension = null;

            for (var i = searchStart; i < localStoreIndex; i++)
            {
                var instruction = instructions[i];

                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                    instruction.Operand is MethodReference methodRef)
                {
                    var declaringType = methodRef.DeclaringType?.FullName ?? string.Empty;
                    var methodName = methodRef.Name;

                    if (declaringType == "System.IO.Path" && methodName == "GetTempPath")
                    {
                        sawTempPath = true;
                    }
                    else if (declaringType == "System.Guid" && methodName == "NewGuid")
                    {
                        sawGuid = true;
                    }
                }

                if (scriptExtension == null &&
                    instruction.OpCode == OpCodes.Ldstr &&
                    instruction.Operand is string literal &&
                    TryExtractScriptExtensionFromGuidFormatLiteral(literal, out var ext))
                {
                    scriptExtension = ext;
                }
            }

            if (!sawTempPath || !sawGuid || scriptExtension == null)
                return false;

            path = $"%TEMP%/<guid>{scriptExtension}";
            return true;
        }

        private static bool IsPathCombineCall(Instruction instruction)
        {
            if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                instruction.Operand is not MethodReference methodRef)
            {
                return false;
            }

            var declaringType = methodRef.DeclaringType?.FullName ?? string.Empty;
            return declaringType == "System.IO.Path" && (methodRef.Name == "Combine" || methodRef.Name == "Join");
        }

        private static bool TryExtractScriptExtensionFromGuidFormatLiteral(string literal, out string extension)
        {
            extension = string.Empty;

            if (string.IsNullOrWhiteSpace(literal) || !literal.Contains("{0}", StringComparison.Ordinal))
                return false;

            if (literal.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase))
            {
                extension = ".cmd";
                return true;
            }

            if (literal.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
            {
                extension = ".bat";
                return true;
            }

            if (literal.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
            {
                extension = ".ps1";
                return true;
            }

            return false;
        }

        private static bool IsTrackedShellExecuteInfoField(string fieldName)
        {
            foreach (var candidate in ShellExecuteInfoFieldOrder)
            {
                if (candidate.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool TryGetPInvokeEntryPoint(MethodReference calledMethod, out string entryPoint)
        {
            entryPoint = string.Empty;
            try
            {
                if (calledMethod.Resolve() is not { } methodDef)
                    return false;

                if ((methodDef.Attributes & MethodAttributes.PInvokeImpl) == 0 || methodDef.PInvokeInfo == null)
                    return false;

                entryPoint = methodDef.PInvokeInfo.EntryPoint ?? calledMethod.Name;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeDisplayValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "<unknown/non-literal>";

            var normalized = value.Replace("\r", " ").Replace("\n", " ").Trim();
            if (normalized.Length > 140)
            {
                normalized = normalized[..140] + "...";
            }

            if (normalized.StartsWith("<", StringComparison.Ordinal) &&
                normalized.EndsWith(">", StringComparison.Ordinal))
                return normalized;

            if (int.TryParse(normalized, out _))
                return normalized;

            if (normalized.StartsWith("\"", StringComparison.Ordinal) &&
                normalized.EndsWith("\"", StringComparison.Ordinal))
                return normalized;

            return $"\"{normalized}\"";
        }
    }
}
