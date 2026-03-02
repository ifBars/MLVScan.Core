using MLVScan.Models;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DeepBehavior;

public abstract class DeepBehaviorAnalyzer
{
    protected DeepBehaviorAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
    {
        Config = config;
        SnippetBuilder = snippetBuilder;
    }

    protected DeepBehaviorAnalysisConfig Config { get; }
    protected CodeSnippetBuilder SnippetBuilder { get; }

    public abstract IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context);

    protected ScanFinding CreateFinding(
        DeepBehaviorContext context,
        string ruleId,
        string description,
        Severity severity,
        int? offset = null)
    {
        var snippet = BuildSnippet(context.Instructions, offset);
        var location = offset.HasValue
            ? $"{context.Method.DeclaringType?.FullName}.{context.Method.Name}:{offset.Value}"
            : $"{context.Method.DeclaringType?.FullName}.{context.Method.Name}";

        return new ScanFinding(location, description, severity, snippet) { RuleId = ruleId };
    }

    protected string BuildSnippet(Mono.Collections.Generic.Collection<Instruction> instructions, int? offset = null)
    {
        var index = 0;
        if (offset.HasValue)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].Offset == offset.Value)
                {
                    index = i;
                    break;
                }
            }
        }

        return SnippetBuilder.BuildSnippet(instructions, index, 3);
    }
}
