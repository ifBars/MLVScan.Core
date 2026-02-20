using MLVScan.Models;

namespace MLVScan.Services.DeepBehavior;

public sealed class DynamicLoadCorrelationAnalyzer : DeepBehaviorAnalyzer
{
    public DynamicLoadCorrelationAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableDynamicLoadCorrelation)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        if (!context.HasRule("AssemblyDynamicLoadRule"))
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var hasReflectiveInvoke = context.HasRule("ReflectionRule");
        var hasEncoded = context.HasAnyRule(DeepBehaviorRuleSets.EncodedRuleIds);
        var hasExecutionSink = context.HasRule("ProcessStartRule") || context.HasRule("Shell32Rule");

        if (!hasReflectiveInvoke && !hasEncoded && !hasExecutionSink)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var severity = hasReflectiveInvoke && hasExecutionSink ? Severity.Critical : Severity.High;
        var offset = context.FirstOffsetForRule("AssemblyDynamicLoadRule") ?? context.FirstOffset();

        var finding = CreateFinding(
            context,
            ruleId: "DeepDynamicLoadCorrelationRule",
            description: "Deep correlation: dynamic load is combined with reflection/encoding/execution behavior.",
            severity: severity,
            offset: offset);

        return [finding];
    }
}
