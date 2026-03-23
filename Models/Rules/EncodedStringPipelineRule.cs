using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    public class EncodedStringPipelineRule : IScanRule
    {
        public string Description =>
            "Detected encoded string to char decoding pipeline (ASCII number or invisible Unicode pattern).";

        public Severity Severity => Severity.High;
        public string RuleId => "EncodedStringPipelineRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze IL instruction patterns in methods
            return false;
        }

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
                if (hasSelectStringChar && hasConcatChar && selectIndex < concatIndex)
                {
                    bool hasParseConvPattern = hasInt32Parse && hasConvU2 && parseIndex < convU2Index;

                    var snippetBuilder = new System.Text.StringBuilder();
                    int startIdx = Math.Max(0,
                        Math.Min(hasParseConvPattern ? parseIndex : selectIndex, selectIndex) - 2);
                    int endIdx = Math.Min(instructions.Count, concatIndex + 3);

                    for (int j = startIdx; j < endIdx; j++)
                    {
                        if (j == selectIndex || j == concatIndex ||
                            (hasParseConvPattern && (j == parseIndex || j == convU2Index)))
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
    }
}
