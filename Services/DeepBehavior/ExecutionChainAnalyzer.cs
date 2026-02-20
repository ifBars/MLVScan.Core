using MLVScan.Models;

namespace MLVScan.Services.DeepBehavior;

public sealed class ExecutionChainAnalyzer : DeepBehaviorAnalyzer
{
    public ExecutionChainAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableExecutionChainAnalysis)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var signals = context.Signals;
        if (signals == null)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var isDownloadDecodeExecute = signals.HasNetworkCall && signals.HasFileWrite &&
                                      (signals.HasProcessLikeCall || context.HasRule("AssemblyDynamicLoadRule"));

        var isDecodeReflectInvoke = signals.HasEncodedStrings && signals.HasSuspiciousReflection &&
                                    (context.HasRule("AssemblyDynamicLoadRule") || signals.HasProcessLikeCall);

        var isStagerLike = signals.HasFileWrite &&
                           (context.HasRule("AssemblyDynamicLoadRule") || context.HasRule("ProcessStartRule") || context.HasRule("Shell32Rule"));

        if (!isDownloadDecodeExecute && !isDecodeReflectInvoke && !isStagerLike)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var severity = isDownloadDecodeExecute ? Severity.Critical : Severity.High;
        var offset = context.FirstOffsetForRule("ProcessStartRule")
                     ?? context.FirstOffsetForRule("AssemblyDynamicLoadRule")
                     ?? context.FirstOffset();

        var finding = CreateFinding(
            context,
            ruleId: "DeepExecutionChainRule",
            description: "Deep correlation: staged payload execution chain detected (decode/load/write/execute).",
            severity: severity,
            offset: offset);

        return [finding];
    }
}
