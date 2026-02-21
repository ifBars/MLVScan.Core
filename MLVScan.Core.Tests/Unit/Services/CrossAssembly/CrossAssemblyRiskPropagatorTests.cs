using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.CrossAssembly;
using MLVScan.Services.CrossAssembly;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.CrossAssembly;

/// <summary>
/// Tests for CrossAssemblyRiskPropagator - correlates findings across assembly dependencies.
/// </summary>
public class CrossAssemblyRiskPropagatorTests
{
    private readonly CrossAssemblyRiskPropagator _propagator = new();

    #region BuildCorrelatedFindings - Empty/Edge Cases

    [Fact]
    public void BuildCorrelatedFindings_WithEmptyGraph_ReturnsEmpty()
    {
        var graph = new AssemblyDependencyGraph { Nodes = [], Edges = [] };
        var findings = new Dictionary<string, List<ScanFinding>>();

        var result = _propagator.BuildCorrelatedFindings(graph, findings);

        result.Should().BeEmpty();
    }

    [Fact]
    public void BuildCorrelatedFindings_WithNoEdges_ReturnsEmpty()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [new AssemblyGraphNode { Path = @"C:\a.dll", AssemblyName = "A" }],
            Edges = []
        };
        var findings = new Dictionary<string, List<ScanFinding>>();

        var result = _propagator.BuildCorrelatedFindings(graph, findings);

        result.Should().BeEmpty();
    }

    [Fact]
    public void BuildCorrelatedFindings_WithNoHighSeverityFindings_ReturnsEmpty()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "low risk", Severity.Low)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings);

        result.Should().BeEmpty();
    }

    [Fact]
    public void BuildCorrelatedFindings_WithEmptyFindingsByAssembly_ReturnsEmpty()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>();

        var result = _propagator.BuildCorrelatedFindings(graph, findings);

        result.Should().BeEmpty();
    }

    #endregion

    #region BuildCorrelatedFindings - CallerOnly Policy

    [Fact]
    public void BuildCorrelatedFindings_CallerOnly_WithHighSeverityTarget_CreatesCallerFinding()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "critical", Severity.Critical)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerOnly).ToList();

        result.Should().HaveCount(1);
        result[0].Location.Should().Be(@"C:\source.dll");
        result[0].Severity.Should().Be(Severity.High);
        result[0].RuleId.Should().Be("CrossAssemblyDependency");
    }

    [Fact]
    public void BuildCorrelatedFindings_CallerOnly_WithMultipleCallers_CreatesFindingPerCaller()
    {
        var graph = CreateGraphWithMultipleCallers();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerOnly).ToList();

        result.Should().HaveCount(2);
        result.Should().Contain(f => f.Location == @"C:\caller1.dll");
        result.Should().Contain(f => f.Location == @"C:\caller2.dll");
    }

    [Fact]
    public void BuildCorrelatedFindings_CallerOnly_DoesNotIncludeCallee()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "critical", Severity.Critical)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerOnly);

        result.Should().NotContain(f => f.Location == @"C:\target.dll");
    }

    #endregion

    #region BuildCorrelatedFindings - CallerAndCallee Policy

    [Fact]
    public void BuildCorrelatedFindings_CallerAndCallee_WithHighSeverity_CreatesCallerAndCalleeFindings()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerAndCallee).ToList();

        result.Should().HaveCount(2);
        result.Should().Contain(f => f.Location == @"C:\source.dll" && f.Severity == Severity.High);
        result.Should().Contain(f => f.Location == @"C:\target.dll" && f.Severity == Severity.High);
    }

    [Fact]
    public void BuildCorrelatedFindings_CallerAndCallee_DescriptionIsCorrect()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "critical", Severity.Critical)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerAndCallee).ToList();

        var callerFinding = result.First(f => f.Location == @"C:\source.dll");
        var calleeFinding = result.First(f => f.Location == @"C:\target.dll");

        callerFinding.Description.Should().Contain("calls into");
        calleeFinding.Description.Should().Contain("actively referenced");
    }

    #endregion

    #region BuildCorrelatedFindings - DependencyCluster Policy

    [Fact]
    public void BuildCorrelatedFindings_DependencyCluster_CreatesCallerCalleeAndClusterFindings()
    {
        var graph = CreateChainGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\B.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.DependencyCluster).ToList();

        // Should have: caller finding (A), callee finding (B), cluster findings (C and D reachable from B)
        result.Should().Contain(f => f.Location == @"C:\A.dll" && f.Severity == Severity.High);
        result.Should().Contain(f => f.Location == @"C:\B.dll" && f.Severity == Severity.High);
        result.Should().Contain(f => f.Location == @"C:\C.dll" && f.Severity == Severity.Medium);
        result.Should().Contain(f => f.Location == @"C:\D.dll" && f.Severity == Severity.Medium);
    }

    [Fact]
    public void BuildCorrelatedFindings_DependencyCluster_TraversesBidirectionally()
    {
        // A <-> B (bidirectional)
        var graph = new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\A.dll", AssemblyName = "A" },
                new AssemblyGraphNode { Path = @"C:\B.dll", AssemblyName = "B" }
            ],
            Edges =
            [
                new AssemblyGraphEdge { SourcePath = @"C:\A.dll", TargetPath = @"C:\B.dll" },
                new AssemblyGraphEdge { SourcePath = @"C:\B.dll", TargetPath = @"C:\A.dll" }
            ]
        };
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\A.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.DependencyCluster).ToList();

        // Both A and B should be in cluster findings (as Medium severity)
        var clusterFindings = result.Where(f => f.Severity == Severity.Medium).ToList();
        clusterFindings.Should().Contain(f => f.Location == @"C:\B.dll");
    }

    [Fact]
    public void BuildCorrelatedFindings_DependencyCluster_ClusterFindingDescriptionIsCorrect()
    {
        var graph = CreateChainGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\B.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.DependencyCluster).ToList();

        var clusterFinding = result.First(f => f.Location == @"C:\C.dll");
        clusterFinding.Description.Should().Contain("suspicious dependency cluster");
        clusterFinding.RuleId.Should().Be("CrossAssemblyDependency");
    }

    #endregion

    #region BuildCorrelatedFindings - Multiple Suspicious Targets

    [Fact]
    public void BuildCorrelatedFindings_WithMultipleSuspiciousTargets_CreatesFindingsForAll()
    {
        var graph = CreateGraphWithMultipleSuspiciousTargets();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target1.dll"] = [new ScanFinding("loc", "high", Severity.High)],
            [@"C:\target2.dll"] = [new ScanFinding("loc", "critical", Severity.Critical)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerAndCallee).ToList();

        // Caller of target1 + caller of target2 + both targets
        result.Should().Contain(f => f.Location == @"C:\caller1.dll");
        result.Should().Contain(f => f.Location == @"C:\caller2.dll");
        result.Should().Contain(f => f.Location == @"C:\target1.dll");
        result.Should().Contain(f => f.Location == @"C:\target2.dll");
    }

    [Fact]
    public void BuildCorrelatedFindings_DuplicateFindings_Deduplicates()
    {
        var graph = CreateGraphWithSharedCaller();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target1.dll"] = [new ScanFinding("loc", "high", Severity.High)],
            [@"C:\target2.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings, QuarantinePolicy.CallerOnly).ToList();

        // Shared caller should only appear once despite calling both suspicious targets
        var callerFindings = result.Where(f => f.Location == @"C:\shared.dll").ToList();
        callerFindings.Should().HaveCount(1);
    }

    #endregion

    #region BuildCorrelatedFindings - Severity Threshold

    [Theory]
    [InlineData(Severity.Critical, true)]
    [InlineData(Severity.High, true)]
    [InlineData(Severity.Medium, false)]
    [InlineData(Severity.Low, false)]
    public void BuildCorrelatedFindings_OnlyHighSeverityOrAboveTriggersPropagation(Severity severity, bool shouldTrigger)
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] = [new ScanFinding("loc", "test", severity)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings).ToList();

        if (shouldTrigger)
        {
            result.Should().NotBeEmpty();
        }
        else
        {
            result.Should().BeEmpty();
        }
    }

    [Fact]
    public void BuildCorrelatedFindings_WithMixedSeverity_OnlyHighSeverityConsidered()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [@"C:\target.dll"] =
            [
                new ScanFinding("loc1", "low", Severity.Low),
                new ScanFinding("loc2", "medium", Severity.Medium),
                new ScanFinding("loc3", "high", Severity.High)
            ]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings);

        result.Should().NotBeEmpty();
    }

    #endregion

    #region BuildCorrelatedFindings - Path Handling

    [Fact]
    public void BuildCorrelatedFindings_PathsAreCaseInsensitive()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\SOURCE.dll", AssemblyName = "Source" },
                new AssemblyGraphNode { Path = @"C:\TARGET.dll", AssemblyName = "Target" }
            ],
            Edges =
            [
                new AssemblyGraphEdge { SourcePath = @"C:\SOURCE.dll", TargetPath = @"C:\TARGET.dll" }
            ]
        };
        var findings = new Dictionary<string, List<ScanFinding>>(StringComparer.OrdinalIgnoreCase)
        {
            [@"c:\target.dll"] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings).ToList();

        result.Should().Contain(f => f.Location.EndsWith("SOURCE.dll", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildCorrelatedFindings_FindsByNormalizedPath()
    {
        var graph = CreateSimpleGraph();
        var findings = new Dictionary<string, List<ScanFinding>>
        {
            [Path.GetFullPath(@"C:\target.dll")] = [new ScanFinding("loc", "high", Severity.High)]
        };

        var result = _propagator.BuildCorrelatedFindings(graph, findings);

        result.Should().NotBeEmpty();
    }

    #endregion

    #region Helper Methods - Graph Creation

    private static AssemblyDependencyGraph CreateSimpleGraph()
    {
        return new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\source.dll", AssemblyName = "Source" },
                new AssemblyGraphNode { Path = @"C:\target.dll", AssemblyName = "Target" }
            ],
            Edges =
            [
                new AssemblyGraphEdge
                {
                    SourcePath = @"C:\source.dll",
                    TargetPath = @"C:\target.dll",
                    EdgeType = AssemblyEdgeType.Reference
                }
            ]
        };
    }

    private static AssemblyDependencyGraph CreateGraphWithMultipleCallers()
    {
        return new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\caller1.dll", AssemblyName = "Caller1" },
                new AssemblyGraphNode { Path = @"C:\caller2.dll", AssemblyName = "Caller2" },
                new AssemblyGraphNode { Path = @"C:\target.dll", AssemblyName = "Target" }
            ],
            Edges =
            [
                new AssemblyGraphEdge { SourcePath = @"C:\caller1.dll", TargetPath = @"C:\target.dll" },
                new AssemblyGraphEdge { SourcePath = @"C:\caller2.dll", TargetPath = @"C:\target.dll" }
            ]
        };
    }

    private static AssemblyDependencyGraph CreateChainGraph()
    {
        // A -> B -> C -> D
        return new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\A.dll", AssemblyName = "A" },
                new AssemblyGraphNode { Path = @"C:\B.dll", AssemblyName = "B" },
                new AssemblyGraphNode { Path = @"C:\C.dll", AssemblyName = "C" },
                new AssemblyGraphNode { Path = @"C:\D.dll", AssemblyName = "D" }
            ],
            Edges =
            [
                new AssemblyGraphEdge { SourcePath = @"C:\A.dll", TargetPath = @"C:\B.dll" },
                new AssemblyGraphEdge { SourcePath = @"C:\B.dll", TargetPath = @"C:\C.dll" },
                new AssemblyGraphEdge { SourcePath = @"C:\C.dll", TargetPath = @"C:\D.dll" }
            ]
        };
    }

    private static AssemblyDependencyGraph CreateGraphWithMultipleSuspiciousTargets()
    {
        return new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\caller1.dll", AssemblyName = "Caller1" },
                new AssemblyGraphNode { Path = @"C:\caller2.dll", AssemblyName = "Caller2" },
                new AssemblyGraphNode { Path = @"C:\target1.dll", AssemblyName = "Target1" },
                new AssemblyGraphNode { Path = @"C:\target2.dll", AssemblyName = "Target2" }
            ],
            Edges =
            [
                new AssemblyGraphEdge { SourcePath = @"C:\caller1.dll", TargetPath = @"C:\target1.dll" },
                new AssemblyGraphEdge { SourcePath = @"C:\caller2.dll", TargetPath = @"C:\target2.dll" }
            ]
        };
    }

    private static AssemblyDependencyGraph CreateGraphWithSharedCaller()
    {
        return new AssemblyDependencyGraph
        {
            Nodes =
            [
                new AssemblyGraphNode { Path = @"C:\shared.dll", AssemblyName = "Shared" },
                new AssemblyGraphNode { Path = @"C:\target1.dll", AssemblyName = "Target1" },
                new AssemblyGraphNode { Path = @"C:\target2.dll", AssemblyName = "Target2" }
            ],
            Edges =
            [
                new AssemblyGraphEdge { SourcePath = @"C:\shared.dll", TargetPath = @"C:\target1.dll" },
                new AssemblyGraphEdge { SourcePath = @"C:\shared.dll", TargetPath = @"C:\target2.dll" }
            ]
        };
    }

    #endregion
}
