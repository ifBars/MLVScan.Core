using MLVScan.Models;

namespace MLVScan.Services.DeepBehavior;

public sealed class NativeInteropCorrelationAnalyzer : DeepBehaviorAnalyzer
{
    public NativeInteropCorrelationAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableNativeInteropCorrelation)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        if (!context.HasRule("DllImportRule"))
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var hasExecution = context.HasRule("ProcessStartRule") || context.HasRule("Shell32Rule");
        var hasDynamicLoad = context.HasRule("AssemblyDynamicLoadRule");
        var hasPersistence = context.HasRule("PersistenceRule");

        if (!hasExecution && !hasDynamicLoad && !hasPersistence)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var severity = hasExecution ? Severity.Critical : Severity.High;
        var offset = context.FirstOffsetForRule("DllImportRule")
                     ?? context.FirstOffsetForRule("ProcessStartRule")
                     ?? context.FirstOffset();

        var finding = CreateFinding(
            context,
            ruleId: "DeepNativeInteropCorrelationRule",
            description: "Deep correlation: native interop is paired with dynamic execution/persistence behavior.",
            severity: severity,
            offset: offset);

        return [finding];
    }
}
