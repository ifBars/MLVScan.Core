namespace MLVScan.Models.CrossAssembly;

public sealed class AssemblyDependencyGraph
{
    public IReadOnlyList<AssemblyGraphNode> Nodes { get; set; } = [];
    public IReadOnlyList<AssemblyGraphEdge> Edges { get; set; } = [];

    public IReadOnlyDictionary<string, List<AssemblyGraphEdge>> OutgoingBySource
    {
        get
        {
            return Edges
                .GroupBy(edge => edge.SourcePath)
                .ToDictionary(group => group.Key, group => group.ToList());
        }
    }

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
