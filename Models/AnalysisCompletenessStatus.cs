namespace MLVScan.Models;

/// <summary>
/// Describes how much of the requested static analysis completed.
/// </summary>
public enum AnalysisCompletenessStatus
{
    /// <summary>
    /// No completeness-limiting scanner warnings were retained.
    /// </summary>
    Complete,

    /// <summary>
    /// Some analysis failed, but other findings were retained.
    /// </summary>
    Partial,

    /// <summary>
    /// Analysis could not inspect enough of the input to support a clean verdict.
    /// </summary>
    Incomplete
}
