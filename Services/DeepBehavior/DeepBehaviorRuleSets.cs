namespace MLVScan.Services.DeepBehavior;

internal static class DeepBehaviorRuleSets
{
    public static readonly HashSet<string> SeedRuleIds = new(StringComparer.Ordinal)
    {
        "DllImportRule",
        "ProcessStartRule",
        "Shell32Rule",
        "AssemblyDynamicLoadRule",
        "ReflectionRule",
        "EnvironmentPathRule",
        "Base64Rule",
        "HexStringRule",
        "EncodedStringLiteralRule",
        "EncodedStringPipelineRule",
        "EncodedBlobSplittingRule",
        "ByteArrayManipulationRule",
        "PersistenceRule",
        "DataExfiltrationRule",
        "DataInfiltrationRule"
    };

    public static readonly HashSet<string> EncodedRuleIds = new(StringComparer.Ordinal)
    {
        "Base64Rule",
        "HexStringRule",
        "EncodedStringLiteralRule",
        "EncodedStringPipelineRule",
        "EncodedBlobSplittingRule",
        "ByteArrayManipulationRule"
    };

    public static readonly HashSet<string> RiskySinkRuleIds = new(StringComparer.Ordinal)
    {
        "ProcessStartRule",
        "Shell32Rule",
        "DllImportRule",
        "ReflectionRule",
        "AssemblyDynamicLoadRule",
        "DataExfiltrationRule",
        "DataInfiltrationRule",
        "PersistenceRule"
    };
}
