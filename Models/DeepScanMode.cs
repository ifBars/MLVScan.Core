namespace MLVScan.Models;

/// <summary>Controls when the scanner uses larger, still finite analysis budgets.</summary>
public enum DeepScanMode
{
    /// <summary>Use the configured standard budgets for a single pass.</summary>
    Disabled,

    /// <summary>Retry once with deep budgets when the standard pass exhausts a data-flow limit.</summary>
    RetryOnIncomplete,

    /// <summary>Use deep budgets from the start for every assembly.</summary>
    Always
}
