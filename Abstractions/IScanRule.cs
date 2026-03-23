using System.Linq;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Contract implemented by all scan rules.
    /// Rules examine structured metadata from the scanner and emit findings when a suspicious pattern is detected.
    /// </summary>
    public interface IScanRule
    {
        /// <summary>
        /// Human-readable description of what the rule detects.
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Severity assigned to findings emitted by the rule.
        /// </summary>
        Severity Severity { get; }

        /// <summary>
        /// Stable identifier for the rule.
        /// </summary>
        string RuleId { get; }

        /// <summary>
        /// Indicates whether the rule requires a companion signal before a finding is emitted.
        /// </summary>
        bool RequiresCompanionFinding { get; }

        /// <summary>
        /// Determines whether the supplied method reference is a suspicious target for this rule.
        /// </summary>
        /// <param name="method">Method reference to evaluate.</param>
        /// <returns><see langword="true"/> when the method should be analyzed further by this rule.</returns>
        bool IsSuspicious(MethodReference method);

        /// <summary>
        /// Developer-facing guidance for interpreting or remediating a finding.
        /// Return <see langword="null"/> when the rule cannot provide a safe alternative.
        /// </summary>
        IDeveloperGuidance? DeveloperGuidance => null;

        /// <summary>
        /// Analyzes IL instructions in a method for suspicious patterns.
        /// </summary>
        /// <param name="method">Method being analyzed.</param>
        /// <param name="instructions">IL instructions for the method.</param>
        /// <param name="methodSignals">Aggregated signal state for the method.</param>
        /// <returns>Findings derived from instruction-level inspection.</returns>
        IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes string literals found in IL code for suspicious patterns.
        /// </summary>
        /// <param name="literal">String literal to inspect.</param>
        /// <param name="method">Method that contains the literal.</param>
        /// <param name="instructionIndex">Instruction index where the literal occurs.</param>
        /// <returns>Findings derived from literal inspection.</returns>
        IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method, int instructionIndex)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes assembly metadata attributes for hidden payloads.
        /// </summary>
        /// <param name="assembly">Assembly to inspect.</param>
        /// <returns>Findings derived from assembly-level metadata.</returns>
        IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes contextual patterns around method calls.
        /// </summary>
        /// <param name="method">Called method reference.</param>
        /// <param name="instructions">Instruction stream that contains the call.</param>
        /// <param name="instructionIndex">Instruction index of the call site.</param>
        /// <param name="methodSignals">Aggregated signal state for the surrounding method.</param>
        /// <returns>Findings derived from call-site context.</returns>
        IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Determines whether a finding should be suppressed after contextual analysis.
        /// </summary>
        /// <param name="method">Method reference associated with the candidate finding.</param>
        /// <param name="instructions">Instruction stream that contains the candidate.</param>
        /// <param name="instructionIndex">Instruction index of the candidate.</param>
        /// <param name="methodSignals">Aggregated signal state for the method.</param>
        /// <param name="typeSignals">Optional type-level signal state.</param>
        /// <returns><see langword="true"/> to suppress the finding.</returns>
        bool ShouldSuppressFinding(MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals, MethodSignals? typeSignals = null)
        {
            return false;
        }

        /// <summary>
        /// Builds the finding description for a suspicious method call.
        /// </summary>
        /// <param name="method">Called method reference.</param>
        /// <param name="instructions">Instruction stream containing the call.</param>
        /// <param name="instructionIndex">Instruction index of the call site.</param>
        /// <returns>A description to place on the resulting finding.</returns>
        string GetFindingDescription(MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int instructionIndex)
        {
            return Description;
        }

        /// <summary>
        /// Builds the finding description for a suspicious method call with access to the containing method.
        /// </summary>
        /// <param name="containingMethod">Method that contains the call site.</param>
        /// <param name="method">Called method reference.</param>
        /// <param name="instructions">Instruction stream containing the call.</param>
        /// <param name="instructionIndex">Instruction index of the call site.</param>
        /// <returns>A description to place on the resulting finding.</returns>
        string GetFindingDescription(MethodDefinition containingMethod, MethodReference method,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int instructionIndex)
        {
            return GetFindingDescription(method, instructions, instructionIndex);
        }

        /// <summary>
        /// Runs after the main scan passes have completed.
        /// </summary>
        /// <param name="module">Assembly module currently being analyzed.</param>
        /// <param name="existingFindings">Findings already emitted during the primary scan.</param>
        /// <returns>Additional or refined findings derived from post-analysis.</returns>
        IEnumerable<ScanFinding> PostAnalysisRefine(ModuleDefinition module, IEnumerable<ScanFinding> existingFindings)
        {
            return Enumerable.Empty<ScanFinding>();
        }
    }
}
