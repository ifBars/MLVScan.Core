namespace MLVScan.Models.CrossAssembly;

public enum AssemblyEdgeType
{
    Reference = 0,
    CallEvidence = 1,
    ResourceLoad = 2
}

public sealed class AssemblyGraphEdge
{
    public string SourcePath { get; set; } = string.Empty;
    public string TargetPath { get; set; } = string.Empty;
    public AssemblyEdgeType EdgeType { get; set; } = AssemblyEdgeType.Reference;
    public string? Evidence { get; set; }
}
