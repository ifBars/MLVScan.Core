using MLVScan.Abstractions;

namespace MLVScan.Models
{
    /// <summary>
    /// Represents a single scan finding emitted by a rule or analysis pass.
    /// </summary>
    public class ScanFinding(
        string location,
        string description,
        Severity severity = Severity.Low,
        string? codeSnippet = null)
    {
        /// <summary>
        /// Gets or sets the location associated with the finding.
        /// </summary>
        public string Location { get; set; } = location;

        /// <summary>
        /// Gets or sets the human-readable finding description.
        /// </summary>
        public string Description { get; set; } = description;

        /// <summary>
        /// Gets or sets the severity assigned by the detecting rule.
        /// </summary>
        public Severity Severity { get; set; } = severity;

        /// <summary>
        /// Gets or sets the optional source snippet captured with the finding.
        /// </summary>
        public string? CodeSnippet { get; set; } = codeSnippet;

        /// <summary>
        /// Gets or sets the rule identifier that generated the finding.
        /// </summary>
        public string? RuleId { get; set; }

        /// <summary>
        /// Gets or sets developer-facing guidance when the rule can suggest a safer alternative.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance { get; set; }

        /// <summary>
        /// Gets or sets the call chain associated with the finding.
        /// </summary>
        public CallChain? CallChain { get; set; }

        /// <summary>
        /// Gets a value indicating whether call-chain data is attached.
        /// </summary>
        public bool HasCallChain => CallChain != null && CallChain.Nodes.Count > 0;

        /// <summary>
        /// Gets or sets the data flow chain associated with the finding.
        /// </summary>
        public DataFlowChain? DataFlowChain { get; set; }

        /// <summary>
        /// Gets a value indicating whether data-flow data is attached.
        /// </summary>
        public bool HasDataFlow => DataFlowChain != null && DataFlowChain.Nodes.Count > 0;

        /// <summary>
        /// Gets or sets whether this finding bypasses the companion-finding requirement.
        /// </summary>
        public bool BypassCompanionCheck { get; set; } = false;

        /// <summary>
        /// Gets or sets the optional numeric risk score computed by a rule.
        /// Severity still comes from the rule; this value is for transparency or ranking only.
        /// </summary>
        public int? RiskScore { get; set; }

        /// <summary>
        /// Returns a human-readable description of the finding.
        /// </summary>
        /// <returns>A formatted string containing severity, description, location, and snippet details.</returns>
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
