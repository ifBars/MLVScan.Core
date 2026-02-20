namespace MLVScan.Models.CrossAssembly;

public sealed class AssemblyGraphNode
{
    public string Path { get; set; } = string.Empty;
    public string AssemblyName { get; set; } = string.Empty;
    public string? Hash { get; set; }
    public AssemblyArtifactRole Role { get; set; } = AssemblyArtifactRole.Unknown;
}
