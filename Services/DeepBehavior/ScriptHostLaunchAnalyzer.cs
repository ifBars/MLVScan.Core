using MLVScan.Models;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DeepBehavior;

public sealed class ScriptHostLaunchAnalyzer : DeepBehaviorAnalyzer
{
    private static readonly string[] ScriptHosts =
    [
        "powershell",
        "cmd.exe",
        "mshta",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32"
    ];

    public ScriptHostLaunchAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableScriptHostLaunchAnalysis || !context.HasRule("ProcessStartRule"))
        {
            return Enumerable.Empty<ScanFinding>();
        }

        for (var i = 0; i < context.Instructions.Count; i++)
        {
            var instruction = context.Instructions[i];
            if (instruction.OpCode != OpCodes.Ldstr || instruction.Operand is not string str)
            {
                continue;
            }

            if (!ContainsScriptHost(str))
            {
                continue;
            }

            var hasEncodedIndicator = HasEncodedIndicatorNear(context.Instructions, i);
            var severity = hasEncodedIndicator ? Severity.Critical : Severity.High;
            var description = hasEncodedIndicator
                ? "Deep correlation: script host launch with encoded/hidden argument indicators."
                : "Deep correlation: script host launch chain detected.";

            return
            [
                CreateFinding(
                    context,
                    ruleId: "DeepScriptHostLaunchRule",
                    description: description,
                    severity: severity,
                    offset: instruction.Offset)
            ];
        }

        return Enumerable.Empty<ScanFinding>();
    }

    private static bool ContainsScriptHost(string value)
    {
        return ScriptHosts.Any(host => value.Contains(host, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasEncodedIndicatorNear(Mono.Collections.Generic.Collection<Instruction> instructions, int index)
    {
        var start = Math.Max(0, index - 10);
        var end = Math.Min(instructions.Count - 1, index + 10);

        for (var i = start; i <= end; i++)
        {
            if (instructions[i].OpCode != OpCodes.Ldstr || instructions[i].Operand is not string str)
            {
                continue;
            }

            if (str.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                str.Contains("frombase64string", StringComparison.OrdinalIgnoreCase) ||
                str.Contains("/c", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
