namespace MLVScan.Models
{
    public class ScanFinding(string location, string description, Severity severity = Severity.Low, string? codeSnippet = null)
    {
        public string Location { get; set; } = location;
        public string Description { get; set; } = description;
        public Severity Severity { get; set; } = severity;
        public string? CodeSnippet { get; set; } = codeSnippet;

        /// <summary>
        /// The rule ID that generated this finding (e.g., "Base64Rule", "PersistenceRule").
        /// Populated during scanning to track which rule triggered.
        /// </summary>
        public string? RuleId { get; set; }

        /// <summary>
        /// Developer-facing guidance for fixing false positives.
        /// Only populated in developer mode when the rule provides guidance.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance { get; set; }

        /// <summary>
        /// The call chain showing how malicious code is reached.
        /// When present, this finding represents a consolidated view of an attack pattern
        /// (e.g., entry point -> wrapper method -> P/Invoke declaration).
        /// </summary>
        public CallChain? CallChain { get; set; }

        /// <summary>
        /// Indicates whether this finding has call chain information.
        /// </summary>
        public bool HasCallChain => CallChain != null && CallChain.Nodes.Count > 0;

        public override string ToString()
        {
            var logMessage = $"[{Severity}] {Description} at {Location}";
            if (!string.IsNullOrEmpty(CodeSnippet))
            {
                logMessage += $"\n   Snippet: {CodeSnippet}";
            }
            return logMessage;
        }
    }
}
