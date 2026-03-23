namespace MLVScan.Models.CrossAssembly;

/// <summary>
/// Controls how far quarantine recommendations should propagate across related assemblies.
/// </summary>
public enum QuarantinePolicy
{
    /// <summary>
    /// Quarantine only the assembly that directly triggered the recommendation.
    /// </summary>
    CallerOnly = 0,

    /// <summary>
    /// Quarantine both the triggering assembly and the directly related callee.
    /// </summary>
    CallerAndCallee = 1,

    /// <summary>
    /// Quarantine the broader connected dependency cluster.
    /// </summary>
    DependencyCluster = 2
}
