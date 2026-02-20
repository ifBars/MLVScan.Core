using System.Linq;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models
{
    public interface IScanRule
    {
        string Description { get; }
        Severity Severity { get; }
        string RuleId { get; }
        bool RequiresCompanionFinding { get; }
        bool IsSuspicious(MethodReference method);

        /// <summary>
        /// Developer-facing guidance for fixing false positives.
        /// Returns null if no safe guidance can be provided (e.g., for attack patterns).
        /// Only populated in developer mode to help legitimate mod developers.
        /// </summary>
        IDeveloperGuidance? DeveloperGuidance => null;

        /// <summary>
        /// Analyzes IL instructions in a method for suspicious patterns.
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes string literals found in IL code for suspicious patterns.
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method, int instructionIndex)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes assembly metadata attributes for hidden payloads.
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Analyzes contextual patterns around method calls (nearby instructions, signals, etc.).
        /// Returns empty enumerable by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method, Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        /// <summary>
        /// Determines if a finding should be suppressed based on contextual analysis.
        /// Called when IsSuspicious returns true, before creating a finding.
        /// Return true to suppress the finding entirely.
        /// </summary>
        bool ShouldSuppressFinding(MethodReference method, Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int instructionIndex, MethodSignals methodSignals, MethodSignals? typeSignals = null)
        {
            return false;
        }

        /// <summary>
        /// Builds the finding description for a suspicious method call.
        /// Rules can override this to include contextual details (for example, target executable names).
        /// </summary>
        string GetFindingDescription(MethodReference method, Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int instructionIndex)
        {
            return Description;
        }

        /// <summary>
        /// Builds the finding description for a suspicious method call with access to the containing method.
        /// Rules can override this to perform deeper contextual extraction using the surrounding method body/module.
        /// </summary>
        string GetFindingDescription(MethodDefinition containingMethod, MethodReference method, Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int instructionIndex)
        {
            return GetFindingDescription(method, instructions, instructionIndex);
        }

        /// <summary>
        /// Called after all methods have been scanned and DataFlowAnalyzer has completed analysis.
        /// Allows rules to refine their findings using cross-method data flow information.
        /// The module parameter provides access to embedded resources for recursive scanning.
        /// Returns additional or refined findings; empty by default for backward compatibility.
        /// </summary>
        IEnumerable<ScanFinding> PostAnalysisRefine(ModuleDefinition module, IEnumerable<ScanFinding> existingFindings)
        {
            return Enumerable.Empty<ScanFinding>();
        }
    }
}
