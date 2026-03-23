namespace MLVScan.Models
{
    /// <summary>
    /// Severity levels used by scan findings and call/data-flow summaries.
    /// </summary>
    public enum Severity : int
    {
        /// <summary>
        /// Low-confidence or informational finding.
        /// </summary>
        Low = 1,

        /// <summary>
        /// Suspicious behavior that merits review.
        /// </summary>
        Medium = 2,

        /// <summary>
        /// High-risk behavior that is likely malicious or strongly suspicious.
        /// </summary>
        High = 3,

        /// <summary>
        /// Critical behavior that is strongly associated with malicious activity.
        /// </summary>
        Critical = 4
    }
}
