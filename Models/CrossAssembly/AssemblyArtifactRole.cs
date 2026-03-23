namespace MLVScan.Models.CrossAssembly;

/// <summary>
/// Classifies the role an assembly plays inside a scanned dependency graph.
/// </summary>
public enum AssemblyArtifactRole
{
    /// <summary>
    /// The assembly could not be classified.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// A primary mod assembly supplied by the end user.
    /// </summary>
    Mod = 1,

    /// <summary>
    /// A plugin assembly loaded by a host framework.
    /// </summary>
    Plugin = 2,

    /// <summary>
    /// A supporting user library referenced by a mod or plugin.
    /// </summary>
    UserLib = 3,

    /// <summary>
    /// An assembly that patches or rewrites other assemblies during load.
    /// </summary>
    Patcher = 4,

    /// <summary>
    /// A referenced assembly outside the primary scan target set.
    /// </summary>
    ExternalReference = 5
}
