namespace MLVScan.Models.CrossAssembly;

/// <summary>
/// Describes a single assembly in a cross-assembly dependency graph.
/// </summary>
public sealed class AssemblyGraphNode
{
    /// <summary>
    /// Gets or sets the resolved path used as the node identifier.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the simple assembly name.
    /// </summary>
    public string AssemblyName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the optional content hash for the assembly.
    /// </summary>
    public string? Hash { get; set; }

    /// <summary>
    /// Gets or sets the classified role of the assembly in the scanned ecosystem.
    /// </summary>
    public AssemblyArtifactRole Role { get; set; } = AssemblyArtifactRole.Unknown;
}
