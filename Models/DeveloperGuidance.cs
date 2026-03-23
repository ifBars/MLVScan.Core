using MLVScan.Abstractions;

namespace MLVScan.Models
{
    /// <summary>
    /// Concrete implementation of developer guidance for scan findings.
    /// </summary>
    public class DeveloperGuidance : IDeveloperGuidance
    {
        /// <summary>
        /// Gets the remediation guidance shown to consumers.
        /// </summary>
        public string Remediation { get; }

        /// <summary>
        /// Gets an optional link to supporting documentation.
        /// </summary>
        public string? DocumentationUrl { get; }

        /// <summary>
        /// Gets the optional APIs or patterns that should be used instead.
        /// </summary>
        public string[]? AlternativeApis { get; }

        /// <summary>
        /// Gets whether a practical safe alternative exists for the flagged pattern.
        /// </summary>
        public bool IsRemediable { get; }

        /// <summary>
        /// Creates a new developer guidance payload.
        /// </summary>
        /// <param name="remediation">Human-readable remediation guidance.</param>
        /// <param name="documentationUrl">Optional documentation URL for the recommended approach.</param>
        /// <param name="alternativeApis">Optional safe APIs or workflows that can be used instead.</param>
        /// <param name="isRemediable">Whether the issue has a practical safe alternative.</param>
        public DeveloperGuidance(
            string remediation,
            string? documentationUrl = null,
            string[]? alternativeApis = null,
            bool isRemediable = true)
        {
            Remediation = remediation ?? throw new ArgumentNullException(nameof(remediation));
            DocumentationUrl = documentationUrl;
            AlternativeApis = alternativeApis;
            IsRemediable = isRemediable;
        }
    }
}
