namespace MLVScan.Models
{
    /// <summary>
    /// Core scanning configuration for MLVScan.Core.
    /// Contains platform-agnostic settings for the static analysis engine.
    /// </summary>
    public class ScanConfig
    {
        /// <summary>
        /// Creates an opt-in scan configuration with larger, still finite data-flow and process-value budgets.
        /// A scan that exhausts these budgets must continue to report incomplete analysis.
        /// </summary>
        public static ScanConfig CreateDeepAnalysis(ScanConfig? baseline = null)
        {
            var deep = baseline is null ? new ScanConfig() : (ScanConfig)baseline.MemberwiseClone();
            deep.DeepScanMode = DeepScanMode.Disabled;
            deep.MaxCallChainDepth = Math.Max(deep.MaxCallChainDepth, 8);
            deep.MaxDataFlowOperationsPerMethod = Math.Max(deep.MaxDataFlowOperationsPerMethod, 8192);
            deep.MaxDataFlowChainsPerMethod = Math.Max(deep.MaxDataFlowChainsPerMethod, 1024);
            deep.MaxCrossMethodCallEdges = Math.Max(deep.MaxCrossMethodCallEdges, 1000000);
            deep.MaxDeepCallChainEdges = Math.Max(deep.MaxDeepCallChainEdges, 100000);
            deep.MaxCrossMethodChains = Math.Max(deep.MaxCrossMethodChains, 4096);
            deep.MaxValueResolutionWork = Math.Max(deep.MaxValueResolutionWork, 65536);
            deep.MaxValueResolutionDepth = Math.Max(deep.MaxValueResolutionDepth, 64);
            deep.MaxValueResolutionAlternatives = Math.Max(deep.MaxValueResolutionAlternatives, 128);
            return deep;
        }

        /// <summary>Controls whether deep analysis is disabled, retried on bounded work, or always used.</summary>
        public DeepScanMode DeepScanMode { get; set; } = DeepScanMode.Disabled;

        /// <summary>Maximum work units per process target or argument resolution.</summary>
        public int MaxValueResolutionWork { get; set; } = 4096;

        /// <summary>Maximum recursion depth for process value reconstruction.</summary>
        public int MaxValueResolutionDepth { get; set; } = 32;

        /// <summary>Maximum alternatives retained by each process value merge.</summary>
        public int MaxValueResolutionAlternatives { get; set; } = 32;

        /// <summary>
        /// Enables multi-signal correlation so the scanner can combine related primitive findings.
        /// </summary>
        public bool EnableMultiSignalDetection { get; set; } = true;

        /// <summary>
        /// Enables inspection of exception handlers for suspicious control-flow patterns.
        /// </summary>
        public bool AnalyzeExceptionHandlers { get; set; } = true;

        /// <summary>Maximum number of exception handlers inspected in one method.</summary>
        public int MaxExceptionHandlersPerMethod { get; set; } = 128;

        /// <summary>Maximum cumulative handler instructions inspected in one method.</summary>
        public int MaxExceptionHandlerInstructionsPerMethod { get; set; } = 16384;

        /// <summary>Maximum findings retained from exception-handler analysis in one method.</summary>
        public int MaxExceptionHandlerFindingsPerMethod { get; set; } = 256;

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
        /// Maximum number of interesting data-flow operations retained for one method.
        /// Reaching this limit marks the analysis as incomplete and requires manual review.
        /// </summary>
        public int MaxDataFlowOperationsPerMethod { get; set; } = 2048;

        /// <summary>
        /// Maximum number of data-flow chains retained for one method.
        /// </summary>
        public int MaxDataFlowChainsPerMethod { get; set; } = 256;

        /// <summary>
        /// Maximum number of call-graph edges evaluated during one cross-method analysis pass.
        /// </summary>
        public int MaxCrossMethodCallEdges { get; set; } = 100000;

        /// <summary>
        /// Maximum number of recursively expanded edges during deep call-chain analysis.
        /// </summary>
        public int MaxDeepCallChainEdges { get; set; } = 10000;

        /// <summary>
        /// Maximum number of cross-method chains retained during one scan.
        /// </summary>
        public int MaxCrossMethodChains { get; set; } = 512;

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

    }
}
