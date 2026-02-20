namespace MLVScan.Models
{
    /// <summary>
    /// Configuration for deep behavior-focused analysis tuned for Unity mod malware patterns.
    /// Deep analysis is opt-in and budget bounded.
    /// </summary>
    public class DeepBehaviorAnalysisConfig
    {
        public bool EnableDeepAnalysis { get; set; } = false;
        public bool DeepScanOnlyFlaggedMethods { get; set; } = true;

        public bool EnableStringDecodeFlow { get; set; } = true;
        public bool EnableExecutionChainAnalysis { get; set; } = true;
        public bool EnableResourcePayloadAnalysis { get; set; } = true;
        public bool EnableDynamicLoadCorrelation { get; set; } = true;
        public bool EnableNativeInteropCorrelation { get; set; } = true;
        public bool EnableScriptHostLaunchAnalysis { get; set; } = true;
        public bool EnableEnvironmentPivotCorrelation { get; set; } = true;
        public bool EnableNetworkToExecutionCorrelation { get; set; } = true;

        public int MaxInstructionsPerMethod { get; set; } = 20000;
        public int MaxAnalysisTimeMsPerMethod { get; set; } = 120;
        public int MaxDeepMethodsPerAssembly { get; set; } = 300;
        public int MaxTrackedDataFlowEdgesPerMethod { get; set; } = 5000;

        // Diagnostic emission controls
        public bool EmitDiagnosticFindings { get; set; } = false;
        public bool RequireCorrelatedBaseFinding { get; set; } = true;

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
