namespace MLVScan.Models
{
    /// <summary>
    /// Configuration for deep behavior-focused analysis tuned for Unity mod malware patterns.
    /// Deep analysis is opt-in and budget bounded.
    /// </summary>
    public class DeepBehaviorAnalysisConfig
    {
        /// <summary>
        /// Enables the deep behavior pipeline.
        /// </summary>
        public bool EnableDeepAnalysis { get; set; } = false;

        /// <summary>
        /// Limits deep analysis to methods already flagged by the quick scan pipeline.
        /// </summary>
        public bool DeepScanOnlyFlaggedMethods { get; set; } = true;

        /// <summary>
        /// Enables string decode flow analysis.
        /// </summary>
        public bool EnableStringDecodeFlow { get; set; } = true;

        /// <summary>
        /// Enables execution chain analysis.
        /// </summary>
        public bool EnableExecutionChainAnalysis { get; set; } = true;

        /// <summary>
        /// Enables embedded resource payload analysis.
        /// </summary>
        public bool EnableResourcePayloadAnalysis { get; set; } = true;

        /// <summary>
        /// Enables dynamic assembly-load correlation analysis.
        /// </summary>
        public bool EnableDynamicLoadCorrelation { get; set; } = true;

        /// <summary>
        /// Enables native interop correlation analysis.
        /// </summary>
        public bool EnableNativeInteropCorrelation { get; set; } = true;

        /// <summary>
        /// Enables script host launch analysis.
        /// </summary>
        public bool EnableScriptHostLaunchAnalysis { get; set; } = true;

        /// <summary>
        /// Enables environment pivot correlation analysis.
        /// </summary>
        public bool EnableEnvironmentPivotCorrelation { get; set; } = true;

        /// <summary>
        /// Enables network-to-execution correlation analysis.
        /// </summary>
        public bool EnableNetworkToExecutionCorrelation { get; set; } = true;

        /// <summary>
        /// Maximum number of instructions to inspect within a single method during deep analysis.
        /// </summary>
        public int MaxInstructionsPerMethod { get; set; } = 20000;

        /// <summary>
        /// Maximum time budget, in milliseconds, for deep analysis of a single method.
        /// </summary>
        public int MaxAnalysisTimeMsPerMethod { get; set; } = 120;

        /// <summary>
        /// Maximum number of methods that may be deep scanned in one assembly.
        /// </summary>
        public int MaxDeepMethodsPerAssembly { get; set; } = 300;

        /// <summary>
        /// Maximum number of tracked data-flow edges permitted per method during deep analysis.
        /// </summary>
        public int MaxTrackedDataFlowEdgesPerMethod { get; set; } = 5000;

        /// <summary>
        /// Emits deep-analysis findings as diagnostics in the scan result.
        /// </summary>
        public bool EmitDiagnosticFindings { get; set; } = false;

        /// <summary>
        /// Requires a correlated base finding before emitting deep diagnostic findings.
        /// </summary>
        public bool RequireCorrelatedBaseFinding { get; set; } = true;

        /// <summary>
        /// Returns true when at least one deep-analysis subsystem is enabled.
        /// </summary>
        public bool IsAnyDeepAnalysisEnabled()
        {
            return EnableStringDecodeFlow ||
                   EnableExecutionChainAnalysis ||
                   EnableResourcePayloadAnalysis ||
                   EnableDynamicLoadCorrelation ||
                   EnableNativeInteropCorrelation ||
                   EnableScriptHostLaunchAnalysis ||
                   EnableEnvironmentPivotCorrelation ||
                   EnableNetworkToExecutionCorrelation;
        }
    }
}
