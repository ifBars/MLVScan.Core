using FluentAssertions;
using MLVScan.Models.CrossAssembly;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models.CrossAssembly;

/// <summary>
/// Tests for AssemblyDependencyGraph - dependency graph model and its indexed views.
/// </summary>
public class AssemblyDependencyGraphTests
{
    #region Default State

    [Fact]
    public void Constructor_SetsEmptyCollections()
    {
        var graph = new AssemblyDependencyGraph();

        graph.Nodes.Should().BeEmpty();
        graph.Edges.Should().BeEmpty();
    }

    [Fact]
    public void DefaultState_OutgoingBySource_IsEmpty()
    {
        var graph = new AssemblyDependencyGraph();

        graph.OutgoingBySource.Should().BeEmpty();
    }

    [Fact]
    public void DefaultState_IncomingByTarget_IsEmpty()
    {
        var graph = new AssemblyDependencyGraph();

        graph.IncomingByTarget.Should().BeEmpty();
    }

    #endregion

    #region Nodes Collection

    [Fact]
    public void Nodes_SetAndGet_ReturnsCorrectValues()
    {
        var graph = new AssemblyDependencyGraph();
        var nodes = new List<AssemblyGraphNode>
        {
            new() { Path = @"C:\mods\ModA.dll", AssemblyName = "ModA", Role = AssemblyArtifactRole.Mod },
            new() { Path = @"C:\mods\ModB.dll", AssemblyName = "ModB", Role = AssemblyArtifactRole.Plugin }
        };

        graph.Nodes = nodes;

        graph.Nodes.Should().HaveCount(2);
        graph.Nodes[0].AssemblyName.Should().Be("ModA");
        graph.Nodes[1].AssemblyName.Should().Be("ModB");
    }

    [Fact]
    public void Nodes_WithEmptyList_ReturnsEmpty()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = new List<AssemblyGraphNode>()
        };

        graph.Nodes.Should().BeEmpty();
    }

    #endregion

    #region Edges Collection

    [Fact]
    public void Edges_SetAndGet_ReturnsCorrectValues()
    {
        var graph = new AssemblyDependencyGraph();
        var edges = new List<AssemblyGraphEdge>
        {
            new() { SourcePath = @"C:\mods\Source.dll", TargetPath = @"C:\mods\Target.dll", EdgeType = AssemblyEdgeType.Reference },
            new() { SourcePath = @"C:\mods\A.dll", TargetPath = @"C:\mods\B.dll", EdgeType = AssemblyEdgeType.CallEvidence }
        };

        graph.Edges = edges;

        graph.Edges.Should().HaveCount(2);
        graph.Edges[0].SourcePath.Should().Be(@"C:\mods\Source.dll");
        graph.Edges[1].EdgeType.Should().Be(AssemblyEdgeType.CallEvidence);
    }

    [Fact]
    public void Edges_WithEmptyList_ReturnsEmpty()
    {
        var graph = new AssemblyDependencyGraph
        {
            Edges = new List<AssemblyGraphEdge>()
        };

        graph.Edges.Should().BeEmpty();
    }

    #endregion

    #region OutgoingBySource - Indexing

    [Fact]
    public void OutgoingBySource_SingleEdge_ReturnsCorrectGrouping()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"C:\mods\Source.dll", TargetPath = @"C:\mods\Target.dll", EdgeType = AssemblyEdgeType.Reference }
            ]
        };

        var outgoing = graph.OutgoingBySource;

        outgoing.Should().HaveCount(1);
        outgoing.Should().ContainKey(@"C:\mods\Source.dll");
        outgoing[@"C:\mods\Source.dll"].Should().HaveCount(1);
        outgoing[@"C:\mods\Source.dll"][0].TargetPath.Should().Be(@"C:\mods\Target.dll");
    }

    [Fact]
    public void OutgoingBySource_MultipleEdgesSameSource_GroupsTogether()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"C:\mods\Source.dll", TargetPath = @"C:\mods\TargetA.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C:\mods\Source.dll", TargetPath = @"C:\mods\TargetB.dll", EdgeType = AssemblyEdgeType.CallEvidence },
                new() { SourcePath = @"C:\mods\Source.dll", TargetPath = @"C:\mods\TargetC.dll", EdgeType = AssemblyEdgeType.ResourceLoad }
            ]
        };

        var outgoing = graph.OutgoingBySource;

        outgoing.Should().HaveCount(1);
        outgoing[@"C:\mods\Source.dll"].Should().HaveCount(3);
        outgoing[@"C:\mods\Source.dll"].Select(e => e.TargetPath).Should().ContainInOrder(
            @"C:\mods\TargetA.dll",
            @"C:\mods\TargetB.dll",
            @"C:\mods\TargetC.dll"
        );
    }

    [Fact]
    public void OutgoingBySource_MultipleSources_SeparateGroups()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"C:\mods\SourceA.dll", TargetPath = @"C:\mods\Common.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C:\mods\SourceB.dll", TargetPath = @"C:\mods\Common.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C:\mods\SourceC.dll", TargetPath = @"C:\mods\Other.dll", EdgeType = AssemblyEdgeType.CallEvidence }
            ]
        };

        var outgoing = graph.OutgoingBySource;

        outgoing.Should().HaveCount(3);
        outgoing.Should().ContainKey(@"C:\mods\SourceA.dll");
        outgoing.Should().ContainKey(@"C:\mods\SourceB.dll");
        outgoing.Should().ContainKey(@"C:\mods\SourceC.dll");
        outgoing[@"C:\mods\SourceA.dll"].Should().HaveCount(1);
        outgoing[@"C:\mods\SourceB.dll"].Should().HaveCount(1);
        outgoing[@"C:\mods\SourceC.dll"].Should().HaveCount(1);
    }

    [Fact]
    public void OutgoingBySource_EmptyEdges_ReturnsEmptyDictionary()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges = []
        };

        graph.OutgoingBySource.Should().BeEmpty();
    }

    #endregion

    #region IncomingByTarget - Indexing

    [Fact]
    public void IncomingByTarget_SingleEdge_ReturnsCorrectGrouping()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"C:\mods\Source.dll", TargetPath = @"C:\mods\Target.dll", EdgeType = AssemblyEdgeType.Reference }
            ]
        };

        var incoming = graph.IncomingByTarget;

        incoming.Should().HaveCount(1);
        incoming.Should().ContainKey(@"C:\mods\Target.dll");
        incoming[@"C:\mods\Target.dll"].Should().HaveCount(1);
        incoming[@"C:\mods\Target.dll"][0].SourcePath.Should().Be(@"C:\mods\Source.dll");
    }

    [Fact]
    public void IncomingByTarget_MultipleEdgesSameTarget_GroupsTogether()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"C:\mods\SourceA.dll", TargetPath = @"C:\mods\Target.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C:\mods\SourceB.dll", TargetPath = @"C:\mods\Target.dll", EdgeType = AssemblyEdgeType.CallEvidence },
                new() { SourcePath = @"C:\mods\SourceC.dll", TargetPath = @"C:\mods\Target.dll", EdgeType = AssemblyEdgeType.ResourceLoad }
            ]
        };

        var incoming = graph.IncomingByTarget;

        incoming.Should().HaveCount(1);
        incoming[@"C:\mods\Target.dll"].Should().HaveCount(3);
        incoming[@"C:\mods\Target.dll"].Select(e => e.SourcePath).Should().ContainInOrder(
            @"C:\mods\SourceA.dll",
            @"C:\mods\SourceB.dll",
            @"C:\mods\SourceC.dll"
        );
    }

    [Fact]
    public void IncomingByTarget_MultipleTargets_SeparateGroups()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"C:\mods\Common.dll", TargetPath = @"C:\mods\TargetA.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C:\mods\Common.dll", TargetPath = @"C:\mods\TargetB.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C:\mods\Other.dll", TargetPath = @"C:\mods\TargetC.dll", EdgeType = AssemblyEdgeType.CallEvidence }
            ]
        };

        var incoming = graph.IncomingByTarget;

        incoming.Should().HaveCount(3);
        incoming.Should().ContainKey(@"C:\mods\TargetA.dll");
        incoming.Should().ContainKey(@"C:\mods\TargetB.dll");
        incoming.Should().ContainKey(@"C:\mods\TargetC.dll");
        incoming[@"C:\mods\TargetA.dll"].Should().HaveCount(1);
        incoming[@"C:\mods\TargetB.dll"].Should().HaveCount(1);
        incoming[@"C:\mods\TargetC.dll"].Should().HaveCount(1);
    }

    [Fact]
    public void IncomingByTarget_EmptyEdges_ReturnsEmptyDictionary()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges = []
        };

        graph.IncomingByTarget.Should().BeEmpty();
    }

    #endregion

    #region Combined Scenarios

    [Fact]
    public void DiamondDependency_BothIndexesCorrect()
    {
        // A -> B, A -> C, B -> D, C -> D
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"A.dll", TargetPath = @"B.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"A.dll", TargetPath = @"C.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"B.dll", TargetPath = @"D.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C.dll", TargetPath = @"D.dll", EdgeType = AssemblyEdgeType.Reference }
            ]
        };

        var outgoing = graph.OutgoingBySource;
        var incoming = graph.IncomingByTarget;

        // Verify outgoing
        outgoing.Should().HaveCount(3);
        outgoing["A.dll"].Should().HaveCount(2);
        outgoing["B.dll"].Should().HaveCount(1);
        outgoing["C.dll"].Should().HaveCount(1);

        // Verify incoming
        incoming.Should().HaveCount(3);
        incoming["B.dll"].Should().HaveCount(1);
        incoming["C.dll"].Should().HaveCount(1);
        incoming["D.dll"].Should().HaveCount(2);
    }

    [Fact]
    public void ChainDependency_BothIndexesCorrect()
    {
        // A -> B -> C -> D
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"A.dll", TargetPath = @"B.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"B.dll", TargetPath = @"C.dll", EdgeType = AssemblyEdgeType.Reference },
                new() { SourcePath = @"C.dll", TargetPath = @"D.dll", EdgeType = AssemblyEdgeType.Reference }
            ]
        };

        var outgoing = graph.OutgoingBySource;
        var incoming = graph.IncomingByTarget;

        // Verify outgoing - each node except D has one outgoing
        outgoing.Should().HaveCount(3);
        outgoing["A.dll"].Should().HaveCount(1);
        outgoing["B.dll"].Should().HaveCount(1);
        outgoing["C.dll"].Should().HaveCount(1);
        outgoing.Should().NotContainKey("D.dll");

        // Verify incoming - each node except A has one incoming
        incoming.Should().HaveCount(3);
        incoming["B.dll"].Should().HaveCount(1);
        incoming["C.dll"].Should().HaveCount(1);
        incoming["D.dll"].Should().HaveCount(1);
        incoming.Should().NotContainKey("A.dll");
    }

    [Fact]
    public void SelfLoop_HandledCorrectly()
    {
        // A -> A (self-reference)
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"A.dll", TargetPath = @"A.dll", EdgeType = AssemblyEdgeType.Reference }
            ]
        };

        var outgoing = graph.OutgoingBySource;
        var incoming = graph.IncomingByTarget;

        outgoing.Should().HaveCount(1);
        outgoing["A.dll"].Should().HaveCount(1);

        incoming.Should().HaveCount(1);
        incoming["A.dll"].Should().HaveCount(1);

        // Verify it's the same edge
        outgoing["A.dll"][0].Should().Be(incoming["A.dll"][0]);
    }

    [Fact]
    public void MultipleEdgeTypes_MixedCorrectly()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"A.dll", TargetPath = @"B.dll", EdgeType = AssemblyEdgeType.Reference, Evidence = "Reference" },
                new() { SourcePath = @"A.dll", TargetPath = @"B.dll", EdgeType = AssemblyEdgeType.CallEvidence, Evidence = "Call" },
                new() { SourcePath = @"A.dll", TargetPath = @"C.dll", EdgeType = AssemblyEdgeType.ResourceLoad, Evidence = "Resource" }
            ]
        };

        var outgoing = graph.OutgoingBySource;
        var incoming = graph.IncomingByTarget;

        // Outgoing: A has 3, B and C have 0
        outgoing["A.dll"].Should().HaveCount(3);
        outgoing.Should().NotContainKey("B.dll");
        outgoing.Should().NotContainKey("C.dll");

        // Incoming: A has 0, B has 2, C has 1
        incoming.Should().NotContainKey("A.dll");
        incoming["B.dll"].Should().HaveCount(2);
        incoming["C.dll"].Should().HaveCount(1);

        // Verify edge types
        var edgeTypes = outgoing["A.dll"].Select(e => e.EdgeType).ToList();
        edgeTypes.Should().Contain(AssemblyEdgeType.Reference);
        edgeTypes.Should().Contain(AssemblyEdgeType.CallEvidence);
        edgeTypes.Should().Contain(AssemblyEdgeType.ResourceLoad);
    }

    #endregion

    #region Edge Property Preservation

    [Fact]
    public void Indexes_PreserveAllEdgeProperties()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new()
                {
                    SourcePath = @"C:\mods\Source.dll",
                    TargetPath = @"C:\mods\Target.dll",
                    EdgeType = AssemblyEdgeType.CallEvidence,
                    Evidence = "MethodCall:LoadLibrary"
                }
            ]
        };

        var outgoing = graph.OutgoingBySource;
        var incoming = graph.IncomingByTarget;

        var edge = outgoing[@"C:\mods\Source.dll"][0];
        edge.SourcePath.Should().Be(@"C:\mods\Source.dll");
        edge.TargetPath.Should().Be(@"C:\mods\Target.dll");
        edge.EdgeType.Should().Be(AssemblyEdgeType.CallEvidence);
        edge.Evidence.Should().Be("MethodCall:LoadLibrary");

        // Same edge from incoming index
        incoming[@"C:\mods\Target.dll"][0].Should().BeEquivalentTo(edge);
    }

    #endregion

    #region Index Recomputation

    [Fact]
    public void Indexes_RecomputeWhenEdgesChange()
    {
        var graph = new AssemblyDependencyGraph
        {
            Nodes = [],
            Edges =
            [
                new() { SourcePath = @"A.dll", TargetPath = @"B.dll", EdgeType = AssemblyEdgeType.Reference }
            ]
        };

        // First access
        var outgoing1 = graph.OutgoingBySource;
        outgoing1.Should().HaveCount(1);

        // Modify edges
        graph.Edges = new List<AssemblyGraphEdge>
        {
            new() { SourcePath = @"X.dll", TargetPath = @"Y.dll", EdgeType = AssemblyEdgeType.CallEvidence },
            new() { SourcePath = @"X.dll", TargetPath = @"Z.dll", EdgeType = AssemblyEdgeType.CallEvidence }
        };

        // Second access - should reflect new edges
        var outgoing2 = graph.OutgoingBySource;
        outgoing2.Should().HaveCount(1);
        outgoing2.Should().ContainKey("X.dll");
        outgoing2.Should().NotContainKey("A.dll");
        outgoing2["X.dll"].Should().HaveCount(2);
    }

    #endregion
}
