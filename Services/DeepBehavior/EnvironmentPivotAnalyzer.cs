using MLVScan.Models;

namespace MLVScan.Services.DeepBehavior;

public sealed class EnvironmentPivotAnalyzer : DeepBehaviorAnalyzer
{
    public EnvironmentPivotAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableEnvironmentPivotCorrelation)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        if (!context.HasRule("EnvironmentPathRule"))
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var hasFollowupSink = context.Signals.HasFileWrite ||
                              context.HasRule("ProcessStartRule") ||
                              context.HasRule("AssemblyDynamicLoadRule") ||
                              context.HasRule("PersistenceRule");

        if (!hasFollowupSink)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var severity = context.HasRule("ProcessStartRule") || context.HasRule("PersistenceRule")
            ? Severity.High
            : Severity.Medium;

        var offset = context.FirstOffsetForRule("EnvironmentPathRule") ?? context.FirstOffset();

        var finding = CreateFinding(
            context,
            ruleId: "DeepEnvironmentPivotRule",
            description: "Deep correlation: sensitive environment path access is chained with write/load/execute behavior.",
            severity: severity,
            offset: offset);

        return [finding];
    }
}
