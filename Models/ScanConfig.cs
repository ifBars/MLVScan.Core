namespace MLVScan.Models
{
    public class ScanConfig
    {
        // Enable/disable automatic scanning at startup
        public bool EnableAutoScan { get; set; } = true;

        // Enable/disable automatic disabling of suspicious mods
        public bool EnableAutoDisable { get; set; } = true;

        // Minimum severity level to trigger disabling
        public Severity MinSeverityForDisable { get; set; } = Severity.Medium;

        // Where to scan for mods
        public string[] ScanDirectories { get; set; } = ["Mods", "Plugins"];

        // How many suspicious findings before disabling a mod
        public int SuspiciousThreshold { get; set; } = 1;

        // Mods to whitelist (will be skipped during scanning)
        public string[] WhitelistedHashes { get; set; } = [];

        // Save a full IL dump of each scanned mod to the reports directory
        public bool DumpFullIlReports { get; set; } = false;

        // Minimum number of numeric segments to consider as encoded string
        public int MinimumEncodedStringLength { get; set; } = 10;

        // Enable scanning of assembly metadata attributes for hidden payloads
        public bool DetectAssemblyMetadata { get; set; } = true;

        // Enable multi-signal heuristics (combination pattern detection)
        public bool EnableMultiSignalDetection { get; set; } = true;

        // Enable analysis of exception handlers
        public bool AnalyzeExceptionHandlers { get; set; } = true;

        // Enable analysis of local variable types as signals
        public bool AnalyzeLocalVariables { get; set; } = true;

        // Enable analysis of property/event accessors
        public bool AnalyzePropertyAccessors { get; set; } = true;

        // Developer mode: Show remediation guidance for mod developers
        public bool DeveloperMode { get; set; } = false;
    }
}
