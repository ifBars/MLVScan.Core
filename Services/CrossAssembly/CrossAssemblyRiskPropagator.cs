using MLVScan.Models;
using MLVScan.Models.CrossAssembly;

namespace MLVScan.Services.CrossAssembly;

/// <summary>
/// Correlates findings across assembly dependencies to detect wrapper/sidecar attack chains.
/// </summary>
public sealed class CrossAssemblyRiskPropagator
{
    public IEnumerable<ScanFinding> BuildCorrelatedFindings(
        AssemblyDependencyGraph graph,
        IReadOnlyDictionary<string, List<ScanFinding>> findingsByAssemblyPath,
        QuarantinePolicy policy = QuarantinePolicy.CallerAndCallee)
    {
        if (graph.Nodes.Count == 0 || graph.Edges.Count == 0)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var suspiciousTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, findings) in findingsByAssemblyPath)
        {
            if (findings.Any(finding => finding.Severity >= Severity.High))
            {
                suspiciousTargets.Add(Path.GetFullPath(path));
            }
        }

        if (suspiciousTargets.Count == 0)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var pathCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string NormalizePath(string path)
        {
            if (!pathCache.TryGetValue(path, out var normalized))
            {
                normalized = Path.GetFullPath(path);
                pathCache[path] = normalized;
            }
            return normalized;
        }

        var correlated = new List<ScanFinding>();
        foreach (var suspiciousPath in suspiciousTargets)
        {
            var callers = graph.Edges
                .Where(edge => string.Equals(NormalizePath(edge.TargetPath), suspiciousPath, StringComparison.OrdinalIgnoreCase))
                .Select(edge => edge.SourcePath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var caller in callers)
            {
                correlated.Add(new ScanFinding(
                    location: caller,
                    description: "Cross-assembly correlation: assembly calls into a high-risk sidecar dependency.",
                    severity: Severity.High,
                    codeSnippet: null)
                {
                    RuleId = "CrossAssemblyDependency"
                });
            }

            if (policy == QuarantinePolicy.CallerAndCallee || policy == QuarantinePolicy.DependencyCluster)
            {
                correlated.Add(new ScanFinding(
                    location: suspiciousPath,
                    description: "Cross-assembly correlation: high-risk dependency is actively referenced by local assemblies.",
                    severity: Severity.High,
                    codeSnippet: null)
                {
                    RuleId = "CrossAssemblyDependency"
                });
            }

            if (policy == QuarantinePolicy.DependencyCluster)
            {
                correlated.AddRange(BuildClusterFindings(graph, suspiciousPath, NormalizePath));
            }
        }

        return correlated
            .GroupBy(finding => $"{finding.Location}|{finding.Description}")
            .Select(group => group.First())
            .ToList();
    }

    private static IEnumerable<ScanFinding> BuildClusterFindings(
        AssemblyDependencyGraph graph,
        string seedPath,
        Func<string, string> normalizePath)
    {
        var findings = new List<ScanFinding>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { normalizePath(seedPath) };
        var queue = new Queue<string>();
        queue.Enqueue(normalizePath(seedPath));

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            foreach (var edge in graph.Edges.Where(edge =>
                         string.Equals(normalizePath(edge.SourcePath), current, StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(normalizePath(edge.TargetPath), current, StringComparison.OrdinalIgnoreCase)))
            {
                var neighbor = string.Equals(normalizePath(edge.SourcePath), current, StringComparison.OrdinalIgnoreCase)
                    ? normalizePath(edge.TargetPath)
                    : normalizePath(edge.SourcePath);

                if (!visited.Add(neighbor))
                {
                    continue;
                }

                queue.Enqueue(neighbor);
                findings.Add(new ScanFinding(
                    location: neighbor,
                    description: "Cross-assembly correlation: assembly belongs to a suspicious dependency cluster.",
                    severity: Severity.Medium,
                    codeSnippet: null)
                {
                    RuleId = "CrossAssemblyDependency"
                });
            }
        }

        return findings;
    }
}
