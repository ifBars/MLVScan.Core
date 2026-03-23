using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects encoded blob splitting logic where a string is split on suspicious separators and then
    /// consumed inside a loop, which is a common pattern in staged payload reconstruction.
    /// </summary>
    public class EncodedBlobSplittingRule : IScanRule
    {
        /// <summary>
        /// Gets the description emitted when the rule finds a structured blob-splitting pattern.
        /// </summary>
        public string Description =>
            "Detected structured encoded blob splitting pattern (backtick/dash separator in loop).";

        /// <summary>
        /// Gets the severity assigned to blob splitting patterns.
        /// </summary>
        public Severity Severity => Severity.High;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "EncodedBlobSplittingRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Returns false because this rule analyzes IL instruction patterns rather than method signatures.
        /// </summary>
        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze IL instruction patterns in methods
            return false;
        }

        /// <summary>
        /// Scans a method body for split-then-loop blob reconstruction patterns using suspicious separators.
        /// </summary>
        /// <param name="methodDef">The method being analyzed.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="methodSignals">Current method signal state.</param>
        /// <returns>Findings when a suspicious split-and-loop pattern is detected.</returns>
        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition methodDef,
            Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            var findings = new List<ScanFinding>();

            try
            {
                bool hasSplitWithSeparator = false;
                int splitIndex = -1;
                char separatorChar = '\0';

                // Suspicious separator char values: 96=backtick, 45=dash, 46=dot
                var suspiciousSeparators = new HashSet<int> { 96, 45, 46 };

                // Find Split calls with suspicious separators
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instr = instructions[i];

                    if (instr.OpCode == OpCodes.Callvirt && instr.Operand is MethodReference calledMethod &&
                        calledMethod.DeclaringType != null &&
                        calledMethod.DeclaringType.FullName == "System.String" &&
                        calledMethod.Name == "Split")
                    {
                        // Match Split(Char, StringSplitOptions) - 2 params
                        // Match Split(Char[]) - 1 param (array overload)
                        // Match Split(Char[], StringSplitOptions) - 2 params (array overload)
                        if (calledMethod.Parameters.Count >= 1 && calledMethod.Parameters.Count <= 2)
                        {
                            // Look backward for the separator char constant
                            // For array overloads, the separator is loaded via newarr + stelem,
                            // but the ldc.i4 constant will still be in the preceding instructions
                            for (int j = Math.Max(0, i - 10); j < i; j++)
                            {
                                var prevInstr = instructions[j];

                                // Check for ldc.i4.s (load constant byte)
                                if (prevInstr.OpCode == OpCodes.Ldc_I4_S && prevInstr.Operand is sbyte byteVal)
                                {
                                    if (suspiciousSeparators.Contains(byteVal))
                                    {
                                        hasSplitWithSeparator = true;
                                        splitIndex = i;
                                        separatorChar = (char)byteVal;
                                        break;
                                    }
                                }
                                // Also check ldc.i4 (load constant int32)
                                else if (prevInstr.OpCode == OpCodes.Ldc_I4 && prevInstr.Operand is int intVal)
                                {
                                    if (suspiciousSeparators.Contains(intVal))
                                    {
                                        hasSplitWithSeparator = true;
                                        splitIndex = i;
                                        separatorChar = (char)intVal;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if (!hasSplitWithSeparator || splitIndex < 0)
                    return findings;

                // Now check if the split result is used in a loop pattern
                // Look for: ldloc.* → clt → brtrue (back edge)
                bool hasLoopPattern = false;
                int loopStartIndex = -1;
                int loopEndIndex = -1;

                // Search for loop pattern after the split
                // Pattern: clt → brtrue/brtrue.s with backward branch (loop)
                for (int i = splitIndex + 1; i < instructions.Count - 1; i++)
                {
                    var instr = instructions[i];

                    // Check for clt (compare less than)
                    if (instr.OpCode == OpCodes.Clt)
                    {
                        // Look ahead for brtrue/brtrue.s within a few instructions
                        for (int j = i + 1; j < Math.Min(instructions.Count, i + 5); j++)
                        {
                            var branchInstr = instructions[j];

                            // Check for brtrue/brtrue.s (branch if true - loop back)
                            if (branchInstr.OpCode == OpCodes.Brtrue || branchInstr.OpCode == OpCodes.Brtrue_S)
                            {
                                // Verify it's a backward branch (loop)
                                if (branchInstr.Operand is Instruction targetInstr)
                                {
                                    int targetIndex = instructions.IndexOf(targetInstr);
                                    if (targetIndex >= 0 && targetIndex < i)
                                    {
                                        // Check if there's a ldloc before the clt (indicates loop variable)
                                        bool hasLdlocBefore = false;
                                        for (int k = Math.Max(0, i - 10); k < i; k++)
                                        {
                                            var checkInstr = instructions[k];
                                            if (checkInstr.OpCode == OpCodes.Ldloc ||
                                                checkInstr.OpCode == OpCodes.Ldloc_0 ||
                                                checkInstr.OpCode == OpCodes.Ldloc_1 ||
                                                checkInstr.OpCode == OpCodes.Ldloc_2 ||
                                                checkInstr.OpCode == OpCodes.Ldloc_3 ||
                                                checkInstr.OpCode == OpCodes.Ldloc_S)
                                            {
                                                hasLdlocBefore = true;
                                                break;
                                            }
                                        }

                                        if (hasLdlocBefore)
                                        {
                                            hasLoopPattern = true;
                                            loopStartIndex = targetIndex;
                                            loopEndIndex = j;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (hasLoopPattern)
                        break;
                }

                if (hasLoopPattern && loopStartIndex >= 0)
                {
                    var snippetBuilder = new System.Text.StringBuilder();
                    int startIdx = Math.Max(0, splitIndex - 3);
                    int endIdx = Math.Min(instructions.Count, loopEndIndex + 3);

                    for (int j = startIdx; j < endIdx; j++)
                    {
                        if (j == splitIndex || (j >= loopStartIndex && j <= loopEndIndex))
                            snippetBuilder.Append(">>> ");
                        else
                            snippetBuilder.Append("    ");
                        snippetBuilder.AppendLine(instructions[j].ToString());
                    }

                    string separatorName = separatorChar switch
                    {
                        (char)96 => "backtick (`)",
                        (char)46 => "dot (.)",
                        _ => "dash (-)"
                    };
                    findings.Add(new ScanFinding(
                        $"{methodDef.DeclaringType.FullName}.{methodDef.Name}",
                        $"Detected structured encoded blob splitting pattern ({separatorName} separator in loop)",
                        Severity.High,
                        snippetBuilder.ToString().TrimEnd()));
                }
            }
            catch
            {
                // Skip if detection fails
            }

            return findings;
        }
    }
}
