using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.Helpers;

internal static class RuleFindingDescription
{
    internal static string Resolve(IScanRule rule, MethodDefinition owner, MethodReference call,
        Mono.Collections.Generic.Collection<Instruction> instructions, int index, out ScanFinding? diagnostic)
    {
        return Resolve(rule, owner, call, instructions, index, out diagnostic, out _);
    }

    internal static string Resolve(IScanRule rule, MethodDefinition owner, MethodReference call,
        Mono.Collections.Generic.Collection<Instruction> instructions, int index, out ScanFinding? diagnostic,
        out FindingAttributes? attributes)
    {
        diagnostic = null;
        attributes = null;
        if (rule.GetType() != typeof(ProcessStartRule))
            return rule.GetFindingDescription(owner, call, instructions, index);

        var processRule = (ProcessStartRule)rule;
        var description = processRule.BuildFindingDescription(owner, call, instructions, index, out var limitReached,
            out var processAttributes);
        attributes = processAttributes;
        if (limitReached)
        {
            diagnostic = new ScanFinding($"{owner.DeclaringType?.FullName}.{owner.Name}:{instructions[index].Offset}",
                "Process value recovery reached a finite analysis limit. " +
                "Retained candidates are partial; deep analysis can retry with a larger finite budget.", Severity.Low)
            {
                RuleId = ProcessStartRule.ResolutionBudgetRuleId
            };
        }
        return description;
    }
}
