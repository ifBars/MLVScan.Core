namespace MLVScan.Models
{
    /// <summary>
    /// Core scanning configuration for MLVScan.Core.
    /// Contains platform-agnostic settings for the static analysis engine.
    /// </summary>
    public class ScanConfig
    {
        /// <summary>
        /// Enables multi-signal correlation so the scanner can combine related primitive findings.
        /// </summary>
        public bool EnableMultiSignalDetection { get; set; } = true;

        /// <summary>
        /// Enables inspection of exception handlers for suspicious control-flow patterns.
        /// </summary>
        public bool AnalyzeExceptionHandlers { get; set; } = true;

        /// <summary>
        /// Enables analysis of local variables as part of signal extraction.
        /// </summary>
        public bool AnalyzeLocalVariables { get; set; } = true;

        /// <summary>
        /// Enables scanning of property and event accessors in addition to ordinary methods.
        /// </summary>
        public bool AnalyzePropertyAccessors { get; set; } = true;

        /// <summary>
        /// Enables scanning of assembly-level metadata for hidden or encoded payloads.
        /// </summary>
        public bool DetectAssemblyMetadata { get; set; } = true;

        /// <summary>
        /// Enables cross-method analysis so call chains and data flows can cross method boundaries.
        /// </summary>
        public bool EnableCrossMethodAnalysis { get; set; } = true;

        /// <summary>
        /// Maximum call depth to explore during cross-method call-chain analysis.
        /// </summary>
        public int MaxCallChainDepth { get; set; } = 5;

        /// <summary>
        /// Enables return-value tracking so data returned by one method can be followed into its caller.
        /// </summary>
        public bool EnableReturnValueTracking { get; set; } = true;

        /// <summary>
        /// Enables recursive scanning of embedded resources that appear to contain managed assemblies.
        /// </summary>
        public bool EnableRecursiveResourceScanning { get; set; } = true;

        /// <summary>
        /// Maximum size, in megabytes, of embedded resources that will be recursively scanned.
        /// </summary>
        public int MaxRecursiveResourceSizeMB { get; set; } = 10;

        /// <summary>
        /// Minimum number of numeric segments required before a string is treated as an encoded value.
        /// </summary>
        public int MinimumEncodedStringLength { get; set; } = 10;

        /// <summary>
        /// Enables developer guidance and remediation details in generated scan results.
        /// </summary>
        public bool DeveloperMode { get; set; } = false;

        /// <summary>
        /// Configuration for the optional deep behavior pipeline.
        /// </summary>
        public DeepBehaviorAnalysisConfig DeepAnalysis { get; set; } = new DeepBehaviorAnalysisConfig();
    }
}
