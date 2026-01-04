namespace MLVScan.Models
{
    /// <summary>
    /// Concrete implementation of developer guidance for scan findings.
    /// Use this to provide actionable remediation hints to mod developers.
    /// </summary>
    public class DeveloperGuidance : IDeveloperGuidance
    {
        public string Remediation { get; }
        public string? DocumentationUrl { get; }
        public string[]? AlternativeApis { get; }
        public bool IsRemediable { get; }

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
