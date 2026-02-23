namespace MLVScan.Models
{
    /// <summary>
    /// Core scanning configuration for MLVScan.Core library.
    /// Contains platform-agnostic settings for the static analysis engine.
    /// </summary>
    public class ScanConfig
    {
        // Enable multi-signal heuristics (combination pattern detection)
        public bool EnableMultiSignalDetection { get; set; } = true;

        // Enable analysis of exception handlers
        public bool AnalyzeExceptionHandlers { get; set; } = true;

        // Enable analysis of local variable types as signals
        public bool AnalyzeLocalVariables { get; set; } = true;

        // Enable analysis of property/event accessors
        public bool AnalyzePropertyAccessors { get; set; } = true;

        // Enable scanning of assembly metadata attributes for hidden payloads
        public bool DetectAssemblyMetadata { get; set; } = true;

        // Enable cross-method data flow analysis (traces data across method boundaries)
        public bool EnableCrossMethodAnalysis { get; set; } = true;

        // Maximum depth for cross-method call chain analysis (higher = more thorough but slower)
        public int MaxCallChainDepth { get; set; } = 5;

        // Enable return value data flow tracking (callee returns data → caller uses it)
        public bool EnableReturnValueTracking { get; set; } = true;

        // Enable recursive scanning of embedded resources loaded as assemblies
        public bool EnableRecursiveResourceScanning { get; set; } = true;

        // Maximum size (in MB) of embedded resources to attempt recursive scanning on
        public int MaxRecursiveResourceSizeMB { get; set; } = 10;

        // Minimum number of numeric segments to consider as encoded string
        public int MinimumEncodedStringLength { get; set; } = 10;

        // Developer mode: Show remediation guidance for mod developers
        public bool DeveloperMode { get; set; } = false;

        // Deep behavior analysis configuration for practical Unity-mod threat detection
        public DeepBehaviorAnalysisConfig DeepAnalysis { get; set; } = new DeepBehaviorAnalysisConfig();
    }
}
