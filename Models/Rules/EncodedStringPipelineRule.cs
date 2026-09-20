using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Text;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects encoded string reconstruction pipelines, including numeric parsing, Unicode variation
    /// selector decoding, sequence remapping, and char-array rebuilding.
    /// </summary>
    public class EncodedStringPipelineRule : IScanRule
    {
        /// <summary>
        /// Gets the description emitted when the rule finds an encoded string pipeline.
        /// </summary>
        public string Description =>
            "Detected encoded string to char decoding pipeline (ASCII number or invisible Unicode pattern).";

        /// <summary>
        /// Gets the severity assigned to encoded-string reconstruction patterns.
        /// </summary>
        public Severity Severity => Severity.High;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "EncodedStringPipelineRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Returns false because the rule operates on instruction sequences rather than method signatures.
        /// </summary>
        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze IL instruction patterns in methods
            return false;
        }

        /// <summary>
        /// Correlates fixed-key byte-array XOR decoding with concealed network and process behavior.
        /// This catches constants stored in compiler-generated RVA fields without treating ordinary
        /// byte-array transformations as malicious on their own.
        /// </summary>
        public IEnumerable<ScanFinding> PostAnalysisRefine(
            ModuleDefinition module,
            IEnumerable<ScanFinding> existingFindings)
        {
            if (module == null)
            {
                return [];
            }

            var methods = EnumerateTypes(module)
                .SelectMany(static type => type.Methods)
                .Where(static method => method.HasBody)
                .ToList();
            var xorDecoders = methods
                .Select(method => (Method: method, Keys: CollectFixedXorKeys(method)))
                .Where(static item => item.Keys.Count > 0)
                .ToList();
            if (xorDecoders.Count == 0)
            {
                return [];
            }

            bool hasNetworkCall = methods.Any(method => method.Body.Instructions.Any(instruction =>
                instruction.Operand is MethodReference called &&
                (called.DeclaringType?.FullName?.StartsWith("System.Net", StringComparison.OrdinalIgnoreCase) == true ||
                 called.DeclaringType?.FullName?.Contains("UnityWebRequest", StringComparison.OrdinalIgnoreCase) == true)));
            bool hasConcealedProcess = existingFindings?.Any(finding =>
                string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
                (Contains(finding.Description, "WindowStyle=Hidden") ||
                 Contains(finding.Description, "CreateNoWindow=true") ||
                 Contains(finding.Description, "Redirected I/O"))) == true;
            if (!hasNetworkCall || !hasConcealedProcess)
            {
                return [];
            }

            var decodedIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var keys = xorDecoders.SelectMany(static item => item.Keys).Distinct().ToList();
            int inspectedBytes = 0;

            foreach (var field in EnumerateTypes(module).SelectMany(static type => type.Fields))
            {
                if (!field.HasFieldRVA || field.InitialValue is not { Length: >= 4 and <= 4096 } bytes)
                {
                    continue;
                }

                if (inspectedBytes > 256 * 1024 - bytes.Length)
                {
                    break;
                }

                inspectedBytes += bytes.Length;
                foreach (int key in keys)
                {
                    if (TryDecodeFixedXor(bytes, key, out string decoded) && IsSecurityRelevantDecodedString(decoded))
                    {
                        decodedIndicators.Add(decoded);
                    }
                }
            }

            if (decodedIndicators.Count == 0)
            {
                return [];
            }

            string decoderLocations = string.Join(", ", xorDecoders.Select(static item => item.Method.FullName).Take(3));
            string indicators = string.Join(", ", decodedIndicators.OrderBy(static value => value, StringComparer.Ordinal).Take(16));
            return
            [
                new ScanFinding(
                    xorDecoders[0].Method.FullName,
                    "Detected fixed-key byte-array XOR string reconstruction concealing network, runtime, or payload indicators in an assembly with concealed process execution.",
                    Severity.High,
                    $"decoder(s): {decoderLocations}{Environment.NewLine}decoded indicator(s): {indicators}")
                {
                    RuleId = RuleId,
                    RiskScore = 84,
                    BypassCompanionCheck = true
                }
            ];
        }

        /// <summary>
        /// Scans a method body for string-to-char reconstruction pipelines and variation-selector payloads.
        /// </summary>
        /// <param name="methodDef">The method being analyzed.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="methodSignals">Current method signal state.</param>
        /// <returns>Findings for the encoded string pipelines detected in the method body.</returns>
        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition methodDef,
            Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            try
            {
                // Pattern 1: Int32::Parse → conv.u2 → Select<String,Char> → Concat<Char>
                // Pattern 2: Array.ConvertAll<String,Char> → new String(Char[])
                bool hasInt32Parse = false;
                bool hasConvU2 = false;
                bool hasSelectStringChar = false;
                bool hasConcatChar = false;
                bool hasConvertAllStringChar = false;
                bool hasNewStringCharArray = false;
                bool hasConvertToUtf32 = false;
                bool hasSurrogatePairCheck = false;
                bool hasEncodingGetString = false;
                bool hasByteAccumulator = false;
                bool hasVariationSelectorBounds = false;

                int parseIndex = -1;
                int convU2Index = -1;
                int selectIndex = -1;
                int concatIndex = -1;
                int convertAllIndex = -1;
                int newStringIndex = -1;
                int convertToUtf32Index = -1;
                int surrogatePairIndex = -1;
                int getStringIndex = -1;
                int byteAccumulatorIndex = -1;
                int variationBoundsIndex = -1;

                // First pass: Find all components
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instr = instructions[i];

                    if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                    {
                        if (instr.Operand is MethodReference calledMethod && calledMethod.DeclaringType != null)
                        {
                            string typeName = calledMethod.DeclaringType.FullName;
                            string methodName = calledMethod.Name;

                            // Check for Int32::Parse(System.String)
                            if (typeName == "System.Int32" && methodName == "Parse" &&
                                calledMethod.Parameters.Count == 1 &&
                                calledMethod.Parameters[0].ParameterType.FullName == "System.String")
                            {
                                hasInt32Parse = true;
                                parseIndex = i;
                            }

                            // Check for Select<String,Char>
                            if (typeName == "System.Linq.Enumerable" && methodName == "Select")
                            {
                                if (calledMethod is GenericInstanceMethod genericMethod &&
                                    genericMethod.GenericArguments.Count == 2)
                                {
                                    var arg1 = genericMethod.GenericArguments[0].FullName;
                                    var arg2 = genericMethod.GenericArguments[1].FullName;
                                    if (arg1 == "System.String" && arg2 == "System.Char")
                                    {
                                        hasSelectStringChar = true;
                                        selectIndex = i;
                                    }
                                }
                            }

                            // Check for Concat<Char>
                            if (typeName == "System.String" && methodName == "Concat")
                            {
                                if (calledMethod is GenericInstanceMethod genericMethod &&
                                    genericMethod.GenericArguments.Count == 1 &&
                                    genericMethod.GenericArguments[0].FullName == "System.Char")
                                {
                                    hasConcatChar = true;
                                    concatIndex = i;
                                }
                            }

                            // Check for Array.ConvertAll<String,Char>
                            if (typeName == "System.Array" && methodName == "ConvertAll")
                            {
                                if (calledMethod is GenericInstanceMethod genericMethod &&
                                    genericMethod.GenericArguments.Count == 2)
                                {
                                    var arg1 = genericMethod.GenericArguments[0].FullName;
                                    var arg2 = genericMethod.GenericArguments[1].FullName;
                                    if (arg1 == "System.String" && arg2 == "System.Char")
                                    {
                                        hasConvertAllStringChar = true;
                                        convertAllIndex = i;
                                    }
                                }
                            }

                            if (typeName == "System.Char" && methodName == "ConvertToUtf32")
                            {
                                hasConvertToUtf32 = true;
                                convertToUtf32Index = i;
                            }

                            if (typeName == "System.Char" && methodName == "IsSurrogatePair")
                            {
                                hasSurrogatePairCheck = true;
                                surrogatePairIndex = i;
                            }

                            if (typeName == "System.Text.Encoding" && methodName == "GetString")
                            {
                                hasEncodingGetString = true;
                                getStringIndex = i;
                            }

                            if ((typeName == "System.Collections.Generic.List`1" ||
                                 typeName.StartsWith("System.Collections.Generic.List`1", StringComparison.Ordinal)) &&
                                methodName == "Add" &&
                                calledMethod.Parameters.Count == 1 &&
                                calledMethod.Parameters[0].ParameterType.FullName == "System.Byte")
                            {
                                hasByteAccumulator = true;
                                byteAccumulatorIndex = i;
                            }
                        }
                    }

                    // Check for newobj System.String::.ctor(Char[])
                    if (instr.OpCode == OpCodes.Newobj && instr.Operand is MethodReference ctorMethod)
                    {
                        if (ctorMethod.DeclaringType?.FullName == "System.String" &&
                            ctorMethod.Parameters.Count == 1 &&
                            ctorMethod.Parameters[0].ParameterType.FullName == "System.Char[]")
                        {
                            hasNewStringCharArray = true;
                            newStringIndex = i;
                        }
                    }

                    // Check for conv.u2 (convert to char) near Parse call
                    if (hasInt32Parse && parseIndex >= 0 && i > parseIndex && i <= parseIndex + 3)
                    {
                        if (instr.OpCode == OpCodes.Conv_U2)
                        {
                            hasConvU2 = true;
                            convU2Index = i;
                        }
                    }

                    if (!hasVariationSelectorBounds && TryResolveInt32Literal(instr, out int literalValue) &&
                        IsVariationSelectorBoundary(literalValue))
                    {
                        hasVariationSelectorBounds = true;
                        variationBoundsIndex = i;
                    }
                }

                // Detect pattern 1: Select<String,Char> → Concat<Char>
                // The Select/Concat pair is only suspicious when it follows numeric parsing and
                // conversion to a character; by itself it is a common initials/abbreviation pattern.
                bool hasParseConvPattern = hasInt32Parse && hasConvU2 && parseIndex < convU2Index;
                if (hasParseConvPattern &&
                    hasSelectStringChar &&
                    hasConcatChar &&
                    convU2Index < selectIndex &&
                    selectIndex < concatIndex)
                {
                    var snippetBuilder = new System.Text.StringBuilder();
                    int startIdx = Math.Max(0, Math.Min(parseIndex, selectIndex) - 2);
                    int endIdx = Math.Min(instructions.Count, concatIndex + 3);

                    for (int j = startIdx; j < endIdx; j++)
                    {
                        if (j == selectIndex || j == concatIndex ||
                            j == parseIndex || j == convU2Index)
                            snippetBuilder.Append(">>> ");
                        else
                            snippetBuilder.Append("    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }

                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        "Detected encoded string to char decoding pipeline (Select<String,Char> → Concat<Char>)",
                        Severity.High,
                        snippetBuilder.ToString().TrimEnd()));
                }

                // Detect pattern 2: Array.ConvertAll<String,Char> → new String(Char[])
                if (hasConvertAllStringChar && hasNewStringCharArray && convertAllIndex < newStringIndex)
                {
                    var snippetBuilder = new System.Text.StringBuilder();
                    int startIdx = Math.Max(0, convertAllIndex - 3);
                    int endIdx = Math.Min(instructions.Count, newStringIndex + 3);

                    for (int j = startIdx; j < endIdx; j++)
                    {
                        if (j == convertAllIndex || j == newStringIndex)
                            snippetBuilder.Append(">>> ");
                        else
                            snippetBuilder.Append("    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }

                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        "Detected encoded string to char decoding pipeline (Array.ConvertAll<String,Char> → new String(Char[]))",
                        Severity.High,
                        snippetBuilder.ToString().TrimEnd()));
                }

                if (hasConvertToUtf32 && hasEncodingGetString && hasByteAccumulator && hasVariationSelectorBounds)
                {
                    var highlightIndexes = new[]
                    {
                        convertToUtf32Index,
                        surrogatePairIndex,
                        variationBoundsIndex,
                        byteAccumulatorIndex,
                        getStringIndex
                    }.Where(index => index >= 0).Distinct().OrderBy(index => index).ToList();

                    int startIdx = Math.Max(0, highlightIndexes.First() - 2);
                    int endIdx = Math.Min(instructions.Count, highlightIndexes.Last() + 3);
                    var snippetBuilder = new System.Text.StringBuilder();

                    for (int j = startIdx; j < endIdx; j++)
                    {
                        snippetBuilder.Append(highlightIndexes.Contains(j) ? ">>> " : "    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }

                    string pipelineKind = hasSurrogatePairCheck
                        ? "variation-selector Unicode decode pipeline with surrogate-pair handling"
                        : "variation-selector Unicode decode pipeline";

                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        $"Detected encoded string to char decoding pipeline ({pipelineKind})",
                        Severity.Critical,
                        snippetBuilder.ToString().TrimEnd()));
                }
            }
            catch
            {
                // Skip if detection fails
            }

            return findings;
        }

        private static bool IsVariationSelectorBoundary(int value)
        {
            return value == 65024 || value == 65039 || value == 917760 || value == 917999;
        }

        private static bool TryResolveInt32Literal(Instruction instruction, out int value)
        {
            if (instruction.OpCode == OpCodes.Ldc_I4 && instruction.Operand is int intValue)
            {
                value = intValue;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_S && instruction.Operand is sbyte sbyteValue)
            {
                value = sbyteValue;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_M1)
            {
                value = -1;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_0)
            {
                value = 0;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_1)
            {
                value = 1;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_2)
            {
                value = 2;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_3)
            {
                value = 3;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_4)
            {
                value = 4;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_5)
            {
                value = 5;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_6)
            {
                value = 6;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_7)
            {
                value = 7;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_8)
            {
                value = 8;
                return true;
            }

            value = 0;
            return false;
        }

        private static IReadOnlyList<int> CollectFixedXorKeys(MethodDefinition method)
        {
            var instructions = method.Body.Instructions;
            bool callsEncodingGetString = instructions.Any(instruction =>
                instruction.Operand is MethodReference called &&
                called.DeclaringType?.FullName == "System.Text.Encoding" &&
                called.Name == "GetString");
            if (!callsEncodingGetString)
            {
                return [];
            }

            var keys = new HashSet<int>();
            for (int index = 0; index < instructions.Count; index++)
            {
                if (instructions[index].OpCode != OpCodes.Xor)
                {
                    continue;
                }

                for (int previous = index - 1; previous >= Math.Max(0, index - 8); previous--)
                {
                    if (TryResolveInt32Literal(instructions[previous], out int value) && value is > 0 and <= 255)
                    {
                        keys.Add(value);
                        break;
                    }
                }
            }

            return keys.ToList();
        }

        private static bool TryDecodeFixedXor(byte[] bytes, int key, out string decoded)
        {
            decoded = string.Empty;
            var transformed = new byte[bytes.Length];
            for (int index = 0; index < bytes.Length; index++)
            {
                transformed[index] = (byte)(bytes[index] ^ key);
            }

            string candidate = Encoding.UTF8.GetString(transformed).TrimEnd('\0');
            if (candidate.Length < 4 || candidate.Contains('\uFFFD'))
            {
                return false;
            }

            int printable = candidate.Count(static character =>
                character is >= ' ' and <= '~' || character is '\t' or '\r' or '\n');
            if ((double)printable / candidate.Length < 0.9)
            {
                return false;
            }

            decoded = candidate;
            return true;
        }

        private static bool IsSecurityRelevantDecodedString(string value)
        {
            return value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                   value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("eth_call", StringComparison.OrdinalIgnoreCase) ||
                   (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && value.Length >= 10) ||
                   value.Contains(".jar", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains(".cache", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("javaw", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("com.renderassist.", StringComparison.OrdinalIgnoreCase) ||
                   value.StartsWith("-cp ", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("--cookie", StringComparison.OrdinalIgnoreCase) ||
                   value.Contains("/api/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool Contains(string? value, string needle) =>
            value?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;

        private static IEnumerable<TypeDefinition> EnumerateTypes(ModuleDefinition module)
        {
            foreach (var type in module.Types)
            {
                yield return type;
                foreach (var nested in EnumerateNestedTypes(type))
                {
                    yield return nested;
                }
            }
        }

        private static IEnumerable<TypeDefinition> EnumerateNestedTypes(TypeDefinition type)
        {
            foreach (var nested in type.NestedTypes)
            {
                yield return nested;
                foreach (var descendant in EnumerateNestedTypes(nested))
                {
                    yield return descendant;
                }
            }
        }
    }
}
