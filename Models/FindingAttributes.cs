namespace MLVScan.Models
{
    /// <summary>
    /// Structured values a rule resolved while producing a finding.
    /// </summary>
    /// <remarks>
    /// The finding description stays the human-readable source of truth. Attributes expose the same
    /// resolved values in a stable shape so consumers can group, filter, and display findings without
    /// parsing description text. Every member is optional because most rules resolve only some values.
    /// </remarks>
    public sealed class FindingAttributes
    {
        /// <summary>
        /// Gets or sets the resolved target the call acts on, such as a launched program or URL.
        /// </summary>
        /// <remarks>
        /// Unresolved targets keep the scanner's placeholder text, for example <c>&lt;unknown/non-literal&gt;</c>.
        /// </remarks>
        public string? Target { get; set; }

        /// <summary>
        /// Gets or sets the neutral category of <see cref="Target"/>.
        /// </summary>
        public FindingTargetKind? TargetKind { get; set; }

        /// <summary>
        /// Gets or sets concrete values the scanner considered possible for an ambiguous target.
        /// </summary>
        /// <remarks>
        /// Populated only when <see cref="Target"/> could resolve to several values. Placeholder values
        /// such as null or budget-exhausted markers are excluded.
        /// </remarks>
        public List<string> TargetCandidates { get; set; } = new();

        /// <summary>
        /// Gets or sets the resolved arguments passed with <see cref="Target"/>, when present.
        /// </summary>
        public string? Arguments { get; set; }

        /// <summary>
        /// Gets or sets machine-readable indicators observed at the call site, such as <c>WindowStyle=Hidden</c>.
        /// </summary>
        public List<string> Indicators { get; set; } = new();

        /// <summary>
        /// Gets or sets the short reason the rule used to choose the finding severity.
        /// </summary>
        public string? RiskReason { get; set; }
    }

    /// <summary>
    /// Neutral categories for a finding target.
    /// </summary>
    public enum FindingTargetKind
    {
        /// <summary>
        /// A program or binary path.
        /// </summary>
        Executable,

        /// <summary>
        /// A script file or a shell/script interpreter.
        /// </summary>
        Script,

        /// <summary>
        /// A URL, URI, or bare web domain.
        /// </summary>
        Url,

        /// <summary>
        /// A file or folder path that is not itself a program or script.
        /// </summary>
        Path,

        /// <summary>
        /// A value built at runtime that static analysis could not resolve.
        /// </summary>
        Unresolved
    }
}
