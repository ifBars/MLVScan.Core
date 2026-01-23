using FluentAssertions;
using MLVScan.Models;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models
{
    public class DataFlowChainTests
    {
        public class DataFlowNodeTests
        {
            [Fact]
            public void Constructor_ShouldSetAllProperties()
            {
                var node = new DataFlowNode(
                    "Namespace.Type.Method:12",
                    "Base64.Decode",
                    DataFlowNodeType.Transform,
                    "byte[] payload",
                    12,
                    "code snippet",
                    "Method.Key"
                );

                node.Location.Should().Be("Namespace.Type.Method:12");
                node.Operation.Should().Be("Base64.Decode");
                node.NodeType.Should().Be(DataFlowNodeType.Transform);
                node.DataDescription.Should().Be("byte[] payload");
                node.InstructionOffset.Should().Be(12);
                node.CodeSnippet.Should().Be("code snippet");
                node.MethodKey.Should().Be("Method.Key");
                node.IsMethodBoundary.Should().BeFalse();
                node.TargetMethodKey.Should().BeNull();
            }

            [Fact]
            public void Constructor_ShouldAcceptOptionalParameters()
            {
                var node = new DataFlowNode(
                    "Loc:10",
                    "Operation",
                    DataFlowNodeType.Source,
                    "Data",
                    10
                );

                node.CodeSnippet.Should().BeNull();
                node.MethodKey.Should().BeNull();
            }

            [Theory]
            [InlineData(DataFlowNodeType.Source, "[SOURCE]")]
            [InlineData(DataFlowNodeType.Transform, "[TRANSFORM]")]
            [InlineData(DataFlowNodeType.Sink, "[SINK]")]
            [InlineData(DataFlowNodeType.Intermediate, "[PASS]")]
            public void ToString_ShouldReturnCorrectPrefix(DataFlowNodeType nodeType, string expectedPrefix)
            {
                var node = new DataFlowNode(
                    "Loc:10",
                    "Op",
                    nodeType,
                    "Desc",
                    10
                );

                var result = node.ToString();

                result.Should().StartWith(expectedPrefix);
                result.Should().Contain("Op");
                result.Should().Contain("→ Desc");
            }

            [Fact]
            public void ToString_WithMethodBoundary_ShouldIncludeTargetMethod()
            {
                var node = new DataFlowNode("Loc:10", "Op", DataFlowNodeType.Intermediate, "Desc", 10)
                {
                    IsMethodBoundary = true,
                    TargetMethodKey = "Target.Method"
                };

                var result = node.ToString();

                result.Should().Contain("→ calls Target.Method");
            }

            [Fact]
            public void ToString_WithoutMethodBoundary_ShouldNotIncludeTarget()
            {
                var node = new DataFlowNode("Loc:10", "Op", DataFlowNodeType.Intermediate, "Desc", 10);

                var result = node.ToString();

                result.Should().NotContain("calls");
            }
        }

        public class DataFlowChainTests_Class
        {
            [Fact]
            public void Constructor_ShouldSetAllProperties()
            {
                var chain = new DataFlowChain(
                    "chain-123",
                    DataFlowPattern.DownloadAndExecute,
                    Severity.High,
                    0.85,
                    "Test summary",
                    "Namespace.Type.Method"
                );

                chain.ChainId.Should().Be("chain-123");
                chain.Pattern.Should().Be(DataFlowPattern.DownloadAndExecute);
                chain.Severity.Should().Be(Severity.High);
                chain.Confidence.Should().Be(0.85);
                chain.Summary.Should().Be("Test summary");
                chain.MethodLocation.Should().Be("Namespace.Type.Method");
                chain.SourceVariable.Should().BeNull();
                chain.Nodes.Should().BeEmpty();
                chain.InvolvedMethods.Should().BeEmpty();
                chain.IsCrossMethod.Should().BeFalse();
            }

            [Fact]
            public void IsSuspicious_LegitimatePattern_ReturnsFalse()
            {
                var chain = new DataFlowChain(
                    "chain-1",
                    DataFlowPattern.Legitimate,
                    Severity.Low,
                    1.0,
                    "Summary",
                    "Method"
                );

                chain.IsSuspicious.Should().BeFalse();
            }

            [Fact]
            public void IsSuspicious_UnknownPattern_ReturnsFalse()
            {
                var chain = new DataFlowChain(
                    "chain-1",
                    DataFlowPattern.Unknown,
                    Severity.Low,
                    1.0,
                    "Summary",
                    "Method"
                );

                chain.IsSuspicious.Should().BeFalse();
            }

            [Theory]
            [InlineData(DataFlowPattern.DownloadAndExecute)]
            [InlineData(DataFlowPattern.DataExfiltration)]
            [InlineData(DataFlowPattern.DynamicCodeLoading)]
            [InlineData(DataFlowPattern.CredentialTheft)]
            [InlineData(DataFlowPattern.RemoteConfigLoad)]
            [InlineData(DataFlowPattern.ObfuscatedPersistence)]
            public void IsSuspicious_SuspiciousPatterns_ReturnsTrue(DataFlowPattern pattern)
            {
                var chain = new DataFlowChain(
                    "chain-1",
                    pattern,
                    Severity.High,
                    1.0,
                    "Summary",
                    "Method"
                );

                chain.IsSuspicious.Should().BeTrue();
            }

            [Fact]
            public void CallDepth_SingleMethod_ReturnsOne()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");

                chain.CallDepth.Should().Be(1);
            }

            [Fact]
            public void CallDepth_MultipleMethods_ReturnsCount()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                chain.InvolvedMethods.Add("Method1");
                chain.InvolvedMethods.Add("Method2");
                chain.InvolvedMethods.Add("Method3");

                chain.CallDepth.Should().Be(3);
            }

            [Fact]
            public void AppendNode_ShouldAddToEnd()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                var node1 = new DataFlowNode("Loc1", "Op1", DataFlowNodeType.Source, "Data1", 10);
                var node2 = new DataFlowNode("Loc2", "Op2", DataFlowNodeType.Transform, "Data2", 20);

                chain.AppendNode(node1);
                chain.AppendNode(node2);

                chain.Nodes.Should().HaveCount(2);
                chain.Nodes[0].Should().Be(node1);
                chain.Nodes[1].Should().Be(node2);
            }

            [Fact]
            public void PrependNode_ShouldAddToBeginning()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                var node1 = new DataFlowNode("Loc1", "Op1", DataFlowNodeType.Source, "Data1", 10);
                var node2 = new DataFlowNode("Loc2", "Op2", DataFlowNodeType.Transform, "Data2", 20);

                chain.AppendNode(node1);
                chain.PrependNode(node2);

                chain.Nodes.Should().HaveCount(2);
                chain.Nodes[0].Should().Be(node2);
                chain.Nodes[1].Should().Be(node1);
            }

            [Fact]
            public void ToDetailedDescription_WithNoNodes_ShouldReturnSummary()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 0.75, "Test summary", "Method");

                var result = chain.ToDetailedDescription();

                result.Should().Be("Test summary");
            }

            [Fact]
            public void ToDetailedDescription_WithNodes_ShouldFormatCorrectly()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 0.75, "Attack pattern", "Method");
                var node1 = new DataFlowNode("Loc1", "Download", DataFlowNodeType.Source, "bytes", 10);
                var node2 = new DataFlowNode("Loc2", "Decode", DataFlowNodeType.Transform, "payload", 20);
                var node3 = new DataFlowNode("Loc3", "Execute", DataFlowNodeType.Sink, "process", 30);

                chain.AppendNode(node1);
                chain.AppendNode(node2);
                chain.AppendNode(node3);

                var result = chain.ToDetailedDescription();

                result.Should().Contain("Attack pattern");
                result.Should().Contain("Data Flow Chain (Confidence: 75%):");
                result.Should().Contain("[SOURCE] Download → bytes");
                result.Should().Contain("[TRANSFORM] Decode → payload");
                result.Should().Contain("[SINK] Execute → process");
            }

            [Fact]
            public void ToDetailedDescription_ShouldIncludeLocations()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 0.5, "Summary", "Method");
                chain.AppendNode(new DataFlowNode("Method1:10", "Op1", DataFlowNodeType.Source, "Data", 10));
                chain.AppendNode(new DataFlowNode("Method2:20", "Op2", DataFlowNodeType.Sink, "Data", 20));

                var result = chain.ToDetailedDescription();

                result.Should().Contain("Location: Method1:10");
                result.Should().Contain("Location: Method2:20");
            }

            [Fact]
            public void ToCombinedCodeSnippet_WithNoNodes_ShouldReturnNull()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");

                var result = chain.ToCombinedCodeSnippet();

                result.Should().BeNull();
            }

            [Fact]
            public void ToCombinedCodeSnippet_WithNodesNoCode_ShouldReturnNull()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                chain.AppendNode(new DataFlowNode("Loc1", "Op1", DataFlowNodeType.Source, "Data", 10));
                chain.AppendNode(new DataFlowNode("Loc2", "Op2", DataFlowNodeType.Sink, "Data", 20));

                var result = chain.ToCombinedCodeSnippet();

                result.Should().BeNull();
            }

            [Fact]
            public void ToCombinedCodeSnippet_WithCode_ShouldCombineWithSeparation()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                chain.AppendNode(new DataFlowNode("Loc1", "Op1", DataFlowNodeType.Source, "Data", 10, "code1"));
                chain.AppendNode(new DataFlowNode("Loc2", "Op2", DataFlowNodeType.Sink, "Data", 20, "code2"));

                var result = chain.ToCombinedCodeSnippet();

                result.Should().NotBeNull();
                result.Should().Contain("// Loc1 - Op1");
                result.Should().Contain("code1");
                result.Should().Contain("// Loc2 - Op2");
                result.Should().Contain("code2");
            }

            [Fact]
            public void GetSource_WithSourceNode_ShouldReturnSource()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                var source = new DataFlowNode("Loc1", "Read", DataFlowNodeType.Source, "Data", 10);
                chain.AppendNode(source);
                chain.AppendNode(new DataFlowNode("Loc2", "Process", DataFlowNodeType.Sink, "Data", 20));

                var result = chain.GetSource();

                result.Should().NotBeNull();
                result.Should().Be(source);
            }

            [Fact]
            public void GetSource_WithoutSourceNode_ShouldReturnNull()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                chain.AppendNode(new DataFlowNode("Loc1", "Pass", DataFlowNodeType.Intermediate, "Data", 10));
                chain.AppendNode(new DataFlowNode("Loc2", "Process", DataFlowNodeType.Sink, "Data", 20));

                var result = chain.GetSource();

                result.Should().BeNull();
            }

            [Fact]
            public void GetSinks_WithMultipleSinks_ShouldReturnAll()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                var sink1 = new DataFlowNode("Loc1", "Write", DataFlowNodeType.Sink, "Data", 10);
                var sink2 = new DataFlowNode("Loc2", "Send", DataFlowNodeType.Sink, "Data", 20);
                chain.AppendNode(new DataFlowNode("Loc0", "Read", DataFlowNodeType.Source, "Data", 5));
                chain.AppendNode(sink1);
                chain.AppendNode(sink2);

                var result = chain.GetSinks();

                result.Should().HaveCount(2);
                result.Should().Contain(sink1);
                result.Should().Contain(sink2);
            }

            [Fact]
            public void GetSinks_WithNoSinks_ShouldReturnEmpty()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                chain.AppendNode(new DataFlowNode("Loc1", "Read", DataFlowNodeType.Source, "Data", 10));

                var result = chain.GetSinks();

                result.Should().BeEmpty();
            }

            [Fact]
            public void GetTransforms_WithMultipleTransforms_ShouldReturnAll()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                var transform1 = new DataFlowNode("Loc1", "Decode", DataFlowNodeType.Transform, "Data", 10);
                var transform2 = new DataFlowNode("Loc2", "Decrypt", DataFlowNodeType.Transform, "Data", 20);
                chain.AppendNode(transform1);
                chain.AppendNode(transform2);

                var result = chain.GetTransforms();

                result.Should().HaveCount(2);
                result.Should().Contain(transform1);
                result.Should().Contain(transform2);
            }

            [Fact]
            public void GetTransforms_WithNoTransforms_ShouldReturnEmpty()
            {
                var chain = new DataFlowChain("chain-1", DataFlowPattern.Unknown, Severity.Low, 1.0, "Summary", "Method");
                chain.AppendNode(new DataFlowNode("Loc1", "Read", DataFlowNodeType.Source, "Data", 10));

                var result = chain.GetTransforms();

                result.Should().BeEmpty();
            }
        }
    }
}