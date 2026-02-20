using MLVScan.Models;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DeepBehavior;

public sealed class ResourcePayloadAnalyzer : DeepBehaviorAnalyzer
{
    public ResourcePayloadAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableResourcePayloadAnalysis)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var hasResourceRead = false;
        var hasDecompression = false;
        var hasAssemblyLoad = context.HasRule("AssemblyDynamicLoadRule");
        var hasFileWrite = context.Signals.HasFileWrite;
        var hasExecution = context.HasRule("ProcessStartRule") || context.HasRule("Shell32Rule");

        int? resourceOffset = null;
        int? sinkOffset = context.FirstOffsetForRule("AssemblyDynamicLoadRule") ?? context.FirstOffsetForRule("ProcessStartRule");

        for (var i = 0; i < context.Instructions.Count; i++)
        {
            var instruction = context.Instructions[i];
            if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                instruction.Operand is not Mono.Cecil.MethodReference called)
            {
                continue;
            }

            var typeName = called.DeclaringType?.FullName ?? string.Empty;
            var methodName = called.Name;

            if (typeName == "System.Reflection.Assembly" && methodName == "GetManifestResourceStream")
            {
                hasResourceRead = true;
                resourceOffset ??= instruction.Offset;
                continue;
            }

            if ((typeName == "System.IO.Compression.GZipStream" || typeName == "System.IO.Compression.DeflateStream") &&
                methodName == ".ctor")
            {
                hasDecompression = true;
                continue;
            }

            if (typeName == "System.Reflection.Assembly" && (methodName == "Load" || methodName == "LoadFrom"))
            {
                hasAssemblyLoad = true;
                sinkOffset ??= instruction.Offset;
                continue;
            }

            if (typeName == "System.IO.File" && (methodName == "WriteAllBytes" || methodName == "WriteAllText"))
            {
                hasFileWrite = true;
                sinkOffset ??= instruction.Offset;
            }
        }

        var hasResourceExecutionChain = hasResourceRead && (hasAssemblyLoad || (hasFileWrite && hasExecution));
        if (!hasResourceExecutionChain)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var description = hasDecompression
            ? "Deep correlation: embedded resource payload with decompression reaches load/execute behavior."
            : "Deep correlation: embedded resource payload reaches load/execute behavior.";

        var finding = CreateFinding(
            context,
            ruleId: "DeepResourcePayloadRule",
            description: description,
            severity: Severity.High,
            offset: sinkOffset ?? resourceOffset ?? context.FirstOffset());

        return [finding];
    }
}
