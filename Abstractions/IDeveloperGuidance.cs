namespace MLVScan.Abstractions
{
    /// <summary>
    /// Developer-facing guidance for interpreting or remediating a finding.
    /// </summary>
    public interface IDeveloperGuidance
    {
        /// <summary>
        /// Human-readable remediation advice for the flagged pattern.
        /// </summary>
        string Remediation { get; }

        /// <summary>
        /// Optional URL to documentation that explains the recommended approach.
        /// </summary>
        string? DocumentationUrl { get; }

        /// <summary>
        /// Optional list of safer APIs or workflows that can be used instead.
        /// </summary>
        string[]? AlternativeApis { get; }

        /// <summary>
        /// Indicates whether a practical safe alternative exists for the flagged pattern.
        /// </summary>
        bool IsRemediable { get; }
    }
}
