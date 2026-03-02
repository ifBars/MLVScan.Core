using MLVScan.Models.CrossAssembly;
using Mono.Cecil;

namespace MLVScan.Services.CrossAssembly;

/// <summary>
/// Builds a dependency graph for already scoped target assemblies.
/// Caller is responsible for providing only target assemblies (mods/plugins/userlibs/patchers).
/// </summary>
public sealed class CrossAssemblyGraphBuilder
{
    public AssemblyDependencyGraph Build(
        IEnumerable<(string path, AssemblyDefinition assembly, AssemblyArtifactRole role)> targets)
    {
        var targetList = targets.ToList();
        var nodes = new List<AssemblyGraphNode>(targetList.Count);
        var edges = new List<AssemblyGraphEdge>();

        var pathByAssemblyName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (path, assembly, role) in targetList)
        {
            var fullPath = Normalize(path);
            var simpleName = assembly.Name?.Name ?? Path.GetFileNameWithoutExtension(fullPath);

            nodes.Add(new AssemblyGraphNode { Path = fullPath, AssemblyName = simpleName, Role = role });

            if (!pathByAssemblyName.ContainsKey(simpleName))
            {
                pathByAssemblyName[simpleName] = fullPath;
            }
        }

        foreach (var (sourcePath, assembly, _) in targetList)
        {
            var normalizedSource = Normalize(sourcePath);
            foreach (var reference in assembly.MainModule.AssemblyReferences)
            {
                if (!pathByAssemblyName.TryGetValue(reference.Name, out var targetPath))
                {
                    continue;
                }

                if (string.Equals(normalizedSource, targetPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                edges.Add(new AssemblyGraphEdge
                {
                    SourcePath = normalizedSource,
                    TargetPath = targetPath,
                    EdgeType = AssemblyEdgeType.Reference,
                    Evidence = reference.FullName
                });
            }
        }

        return new AssemblyDependencyGraph { Nodes = nodes, Edges = DeduplicateEdges(edges) };
    }

    private static string Normalize(string path)
    {
        return Path.GetFullPath(path);
    }

    private static IReadOnlyList<AssemblyGraphEdge> DeduplicateEdges(IEnumerable<AssemblyGraphEdge> edges)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unique = new List<AssemblyGraphEdge>();

        foreach (var edge in edges)
        {
            var key = $"{edge.SourcePath}|{edge.TargetPath}|{(int)edge.EdgeType}";
            if (!seen.Add(key))
            {
                continue;
            }

            unique.Add(edge);
        }

        return unique;
    }
}
