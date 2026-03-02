using System.IO;
using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.CrossAssembly;
using MLVScan.Services.CrossAssembly;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.CrossAssembly;

/// <summary>
/// Tests for CrossAssemblyGraphBuilder - builds dependency graphs between target assemblies.
/// </summary>
public class CrossAssemblyGraphBuilderTests
{
    private readonly CrossAssemblyGraphBuilder _builder = new();

    #region Build - Basic Functionality

    [Fact]
    public void Build_WithEmptyTargets_ReturnsEmptyGraph()
    {
        var targets = new List<(string path, AssemblyDefinition assembly, AssemblyArtifactRole role)>();

        var graph = _builder.Build(targets);

        graph.Nodes.Should().BeEmpty();
        graph.Edges.Should().BeEmpty();
    }

    [Fact]
    public void Build_WithSingleAssembly_CreatesSingleNode()
    {
        var assembly = TestAssemblyBuilder.Create("SingleAssembly").Build();
        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\SingleAssembly.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Nodes.Should().HaveCount(1);
        graph.Nodes[0].AssemblyName.Should().Be("SingleAssembly");
        graph.Nodes[0].Role.Should().Be(AssemblyArtifactRole.Mod);
        graph.Edges.Should().BeEmpty();
    }

    [Fact]
    public void Build_WithMultipleAssemblies_CreatesNodesForEach()
    {
        var assembly1 = TestAssemblyBuilder.Create("AssemblyOne").Build();
        var assembly2 = TestAssemblyBuilder.Create("AssemblyTwo").Build();
        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\AssemblyOne.dll", assembly1, AssemblyArtifactRole.Mod),
            (@"C:\mods\AssemblyTwo.dll", assembly2, AssemblyArtifactRole.Plugin)
        };

        var graph = _builder.Build(targets);

        graph.Nodes.Should().HaveCount(2);
        graph.Nodes.Should().Contain(n => n.AssemblyName == "AssemblyOne" && n.Role == AssemblyArtifactRole.Mod);
        graph.Nodes.Should().Contain(n => n.AssemblyName == "AssemblyTwo" && n.Role == AssemblyArtifactRole.Plugin);
    }

    #endregion

    #region Build - Reference Detection

    [Fact]
    public void Build_WithAssemblyReference_CreatesEdge()
    {
        var targetAssembly = TestAssemblyBuilder.Create("TargetAssembly").Build();
        var referencingAssembly = TestAssemblyBuilder.Create("ReferencingAssembly").Build();

        referencingAssembly.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("TargetAssembly", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\TargetAssembly.dll", targetAssembly, AssemblyArtifactRole.Mod),
            (@"C:\mods\ReferencingAssembly.dll", referencingAssembly, AssemblyArtifactRole.Plugin)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(1);
        var edge = graph.Edges[0];
        edge.SourcePath.Should().EndWith("ReferencingAssembly.dll");
        edge.TargetPath.Should().EndWith("TargetAssembly.dll");
        edge.EdgeType.Should().Be(AssemblyEdgeType.Reference);
        edge.Evidence.Should().Be("TargetAssembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
    }

    [Fact]
    public void Build_WithBidirectionalReferences_CreatesBothEdges()
    {
        var assemblyA = TestAssemblyBuilder.Create("AssemblyA").Build();
        var assemblyB = TestAssemblyBuilder.Create("AssemblyB").Build();

        assemblyA.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("AssemblyB", new Version(1, 0, 0, 0)));
        assemblyB.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("AssemblyA", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\AssemblyA.dll", assemblyA, AssemblyArtifactRole.Mod),
            (@"C:\mods\AssemblyB.dll", assemblyB, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(2);
        graph.Edges.Should().Contain(e => e.SourcePath.Contains("AssemblyA") && e.TargetPath.Contains("AssemblyB"));
        graph.Edges.Should().Contain(e => e.SourcePath.Contains("AssemblyB") && e.TargetPath.Contains("AssemblyA"));
    }

    [Fact]
    public void Build_WithExternalReference_NotInTargets_NoEdgeCreated()
    {
        var assembly = TestAssemblyBuilder.Create("LocalAssembly").Build();
        assembly.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("ExternalAssembly", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\LocalAssembly.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Nodes.Should().HaveCount(1);
        graph.Edges.Should().BeEmpty();
    }

    [Fact]
    public void Build_WithSelfReference_NoEdgeCreated()
    {
        var assembly = TestAssemblyBuilder.Create("SelfReferencingAssembly").Build();
        assembly.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("SelfReferencingAssembly", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\SelfReferencingAssembly.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Nodes.Should().HaveCount(1);
        graph.Edges.Should().BeEmpty();
    }

    #endregion

    #region Build - Edge Deduplication

    [Fact]
    public void Build_WithDuplicateReferences_DeduplicatesEdges()
    {
        var targetAssembly = TestAssemblyBuilder.Create("Target").Build();
        var sourceAssembly = TestAssemblyBuilder.Create("Source").Build();

        // Add same reference twice (can happen in complex scenarios)
        sourceAssembly.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Target", new Version(1, 0, 0, 0)));
        sourceAssembly.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Target", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\Target.dll", targetAssembly, AssemblyArtifactRole.Mod),
            (@"C:\mods\Source.dll", sourceAssembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(1);
    }

    [Fact]
    public void Build_WithMultipleReferencesToSameTarget_SingleEdgeCreated()
    {
        var target = TestAssemblyBuilder.Create("CommonTarget").Build();
        var source1 = TestAssemblyBuilder.Create("Source1").Build();
        var source2 = TestAssemblyBuilder.Create("Source2").Build();

        source1.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("CommonTarget", new Version(1, 0, 0, 0)));
        source2.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("CommonTarget", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\CommonTarget.dll", target, AssemblyArtifactRole.Mod),
            (@"C:\mods\Source1.dll", source1, AssemblyArtifactRole.Plugin),
            (@"C:\mods\Source2.dll", source2, AssemblyArtifactRole.Plugin)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(2);
        // The key is the normalized full path, not just the filename
        var targetKey = graph.IncomingByTarget.Keys.First(k => k.EndsWith("CommonTarget.dll", StringComparison.OrdinalIgnoreCase));
        graph.IncomingByTarget[targetKey].Should().HaveCount(2);
    }

    #endregion

    #region Build - Path Normalization

    [Fact]
    public void Build_WithRelativePaths_NormalizesToFullPaths()
    {
        var assembly = TestAssemblyBuilder.Create("PathTest").Build();
        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            ("mods/PathTest.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Nodes[0].Path.Should().Contain(System.IO.Path.DirectorySeparatorChar.ToString());
        System.IO.Path.IsPathFullyQualified(graph.Nodes[0].Path).Should().BeTrue();
    }

    [Fact]
    public void Build_PreservesPathCaseForDisplay()
    {
        var assembly = TestAssemblyBuilder.Create("CaseTest").Build();
        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\Mods\CaseTest.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        // Path should be normalized but case should be preserved on Windows
        graph.Nodes[0].Path.Should().EndWith("CaseTest.dll");
    }

    #endregion

    #region Build - Assembly Name Handling

    [Fact]
    public void Build_UsesAssemblyNameFromDefinition()
    {
        var assembly = TestAssemblyBuilder.Create("MyCustomAssembly").Build();
        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\renamed.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Nodes[0].AssemblyName.Should().Be("MyCustomAssembly");
    }

    [Fact]
    public void Build_WithNullAssemblyName_UsesFileName()
    {
        var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();

        // Simulate null assembly name by setting it to null using reflection
        var nameProperty = typeof(AssemblyDefinition).GetProperty("Name");
        nameProperty!.SetValue(assembly, null);

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"mods/FallbackName.dll", assembly, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Nodes[0].AssemblyName.Should().Be("FallbackName");
    }

    [Fact]
    public void Build_WithAssemblyNameCaseMismatch_MatchesCaseInsensitively()
    {
        var target = TestAssemblyBuilder.Create("MyTarget").Build();
        var source = TestAssemblyBuilder.Create("Source").Build();

        // Reference uses different case
        source.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("mytarget", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\MyTarget.dll", target, AssemblyArtifactRole.Mod),
            (@"C:\mods\Source.dll", source, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(1);
    }

    #endregion

    #region Build - Complex Scenarios

    [Fact]
    public void Build_WithChainOfDependencies_CreatesAllEdges()
    {
        var assemblyA = TestAssemblyBuilder.Create("A").Build();
        var assemblyB = TestAssemblyBuilder.Create("B").Build();
        var assemblyC = TestAssemblyBuilder.Create("C").Build();

        // A -> B -> C
        assemblyA.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("B", new Version(1, 0, 0, 0)));
        assemblyB.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("C", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\A.dll", assemblyA, AssemblyArtifactRole.Mod),
            (@"C:\mods\B.dll", assemblyB, AssemblyArtifactRole.Mod),
            (@"C:\mods\C.dll", assemblyC, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(2);
        graph.OutgoingBySource.Keys.Should().Contain(path => path.EndsWith("A.dll"));
        graph.OutgoingBySource.Keys.Should().Contain(path => path.EndsWith("B.dll"));
    }

    [Fact]
    public void Build_WithDiamondDependency_CreatesAllEdges()
    {
        var top = TestAssemblyBuilder.Create("Top").Build();
        var left = TestAssemblyBuilder.Create("Left").Build();
        var right = TestAssemblyBuilder.Create("Right").Build();
        var bottom = TestAssemblyBuilder.Create("Bottom").Build();

        //    Top
        //   /   \
        // Left  Right
        //   \   /
        //   Bottom
        top.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Left", new Version(1, 0, 0, 0)));
        top.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Right", new Version(1, 0, 0, 0)));
        left.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Bottom", new Version(1, 0, 0, 0)));
        right.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Bottom", new Version(1, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\Top.dll", top, AssemblyArtifactRole.Mod),
            (@"C:\mods\Left.dll", left, AssemblyArtifactRole.Mod),
            (@"C:\mods\Right.dll", right, AssemblyArtifactRole.Mod),
            (@"C:\mods\Bottom.dll", bottom, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Edges.Should().HaveCount(4);
        var bottomKey = graph.IncomingByTarget.Keys.First(path => path.EndsWith("Bottom.dll"));
        graph.IncomingByTarget[bottomKey].Should().HaveCount(2);
    }

    [Fact]
    public void Build_WithMultipleAssemblyReferences_SingleEdgePerTarget()
    {
        var target = TestAssemblyBuilder.Create("Target").Build();
        var source = TestAssemblyBuilder.Create("Source").Build();

        // Different versions of same assembly (should match by name only)
        source.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Target", new Version(1, 0, 0, 0)));
        source.MainModule.AssemblyReferences.Add(
            new AssemblyNameReference("Target", new Version(2, 0, 0, 0)));

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\Target.dll", target, AssemblyArtifactRole.Mod),
            (@"C:\mods\Source.dll", source, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        // Should deduplicate edges even with different versions
        graph.Edges.Should().HaveCount(1);
    }

    #endregion

    #region Build - Edge Properties

    [Fact]
    public void Build_EdgeHasCorrectEvidence()
    {
        var target = TestAssemblyBuilder.Create("TargetEvidence").Build();
        var source = TestAssemblyBuilder.Create("SourceEvidence").Build();

        var reference = new AssemblyNameReference("TargetEvidence", new Version(2, 5, 1, 0))
        {
            Culture = "en-US",
            PublicKeyToken = new byte[] { 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93 }
        };
        source.MainModule.AssemblyReferences.Add(reference);

        var targets = new List<(string, AssemblyDefinition, AssemblyArtifactRole)>
        {
            (@"C:\mods\TargetEvidence.dll", target, AssemblyArtifactRole.Mod),
            (@"C:\mods\SourceEvidence.dll", source, AssemblyArtifactRole.Mod)
        };

        var graph = _builder.Build(targets);

        graph.Edges[0].Evidence.Should().Contain("TargetEvidence");
        graph.Edges[0].Evidence.Should().Contain("Version=2.5.1.0");
        graph.Edges[0].Evidence.Should().Contain("Culture=en-US");
    }

    #endregion
}
