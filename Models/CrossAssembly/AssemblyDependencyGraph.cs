namespace MLVScan.Models.CrossAssembly;

/// <summary>
/// Represents the dependency graph built for a set of scanned assemblies.
/// </summary>
public sealed class AssemblyDependencyGraph
{
    /// <summary>
    /// Gets or sets the assemblies present in the graph.
    /// </summary>
    public IReadOnlyList<AssemblyGraphNode> Nodes { get; set; } = [];

    /// <summary>
    /// Gets or sets the directed relationships between graph nodes.
    /// </summary>
    public IReadOnlyList<AssemblyGraphEdge> Edges { get; set; } = [];

    /// <summary>
    /// Gets the outgoing edges grouped by source assembly path.
    /// </summary>
    public IReadOnlyDictionary<string, List<AssemblyGraphEdge>> OutgoingBySource
    {
        get
        {
            return Edges
                .GroupBy(edge => edge.SourcePath)
                .ToDictionary(group => group.Key, group => group.ToList());
        }
    }

    /// <summary>
    /// Gets the incoming edges grouped by target assembly path.
    /// </summary>
    public IReadOnlyDictionary<string, List<AssemblyGraphEdge>> IncomingByTarget
    {
        get
        {
            return Edges
                .GroupBy(edge => edge.TargetPath)
                .ToDictionary(group => group.Key, group => group.ToList());
        }
    }
}
