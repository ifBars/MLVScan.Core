namespace MLVScan.Models.CrossAssembly;

/// <summary>
/// Describes the reason two assemblies are connected in a dependency graph.
/// </summary>
public enum AssemblyEdgeType
{
    /// <summary>
    /// The source assembly references the target assembly through normal metadata.
    /// </summary>
    Reference = 0,

    /// <summary>
    /// The source assembly appears to call into or otherwise execute code from the target assembly.
    /// </summary>
    CallEvidence = 1,

    /// <summary>
    /// The source assembly appears to load the target assembly from an embedded or external resource.
    /// </summary>
    ResourceLoad = 2
}

/// <summary>
/// Represents a directed relationship between two assemblies in a dependency graph.
/// </summary>
public sealed class AssemblyGraphEdge
{
    /// <summary>
    /// Gets or sets the path of the source assembly.
    /// </summary>
    public string SourcePath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the path of the target assembly.
    /// </summary>
    public string TargetPath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the relationship type represented by the edge.
    /// </summary>
    public AssemblyEdgeType EdgeType { get; set; } = AssemblyEdgeType.Reference;

    /// <summary>
    /// Gets or sets optional human-readable evidence describing why the edge exists.
    /// </summary>
    public string? Evidence { get; set; }
}
