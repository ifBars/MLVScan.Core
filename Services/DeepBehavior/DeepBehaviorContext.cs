using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DeepBehavior;

public sealed class DeepBehaviorContext
{
    public MethodDefinition Method { get; set; } = null!;
    public MethodSignals Signals { get; set; } = null!;
    public IReadOnlyList<ScanFinding> MethodFindings { get; set; } = Array.Empty<ScanFinding>();
    public IReadOnlyList<ScanFinding> TypeFindings { get; set; } = Array.Empty<ScanFinding>();
    public IReadOnlyList<ScanFinding> NamespaceFindings { get; set; } = Array.Empty<ScanFinding>();

    public Mono.Collections.Generic.Collection<Instruction> Instructions => Method.Body!.Instructions;

    public IEnumerable<string> RuleIds => MethodFindings
        .Where(finding => !string.IsNullOrEmpty(finding.RuleId))
        .Select(finding => finding.RuleId!);

    public IEnumerable<ScanFinding> ScopedFindings => MethodFindings.Concat(TypeFindings).Concat(NamespaceFindings);

    public bool HasRule(string ruleId)
    {
        return ScopedFindings.Any(finding => string.Equals(finding.RuleId, ruleId, StringComparison.Ordinal));
    }

    public bool HasAnyRule(IEnumerable<string> ruleIds)
    {
        var lookup = new HashSet<string>(ruleIds, StringComparer.Ordinal);
        return ScopedFindings.Any(finding => finding.RuleId != null && lookup.Contains(finding.RuleId));
    }

    public int? FirstOffset()
    {
        return Instructions.Count == 0 ? null : Instructions[0].Offset;
    }

    public int? FirstOffsetForRule(string ruleId)
    {
        var finding = MethodFindings.FirstOrDefault(item => string.Equals(item.RuleId, ruleId, StringComparison.Ordinal));
        if (finding == null)
        {
            return null;
        }

        return TryParseOffset(finding.Location);
    }

    public static int? TryParseOffset(string location)
    {
        if (string.IsNullOrWhiteSpace(location))
        {
            return null;
        }

        var parts = location.Split(':');
        if (parts.Length < 2)
        {
            return null;
        }

        return int.TryParse(parts[^1], out var parsed) ? parsed : null;
    }
}
