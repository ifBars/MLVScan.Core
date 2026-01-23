using FluentAssertions;
using MLVScan.Models;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models
{
    public class CallChainTests
    {
        public class CallChainNodeTests
        {
            [Fact]
            public void Constructor_ShouldSetAllProperties()
            {
                var node = new CallChainNode(
                    "Namespace.Type.Method:12",
                    "Test description",
                    CallChainNodeType.IntermediateCall,
                    "test snippet"
                );

                node.Location.Should().Be("Namespace.Type.Method:12");
                node.Description.Should().Be("Test description");
                node.NodeType.Should().Be(CallChainNodeType.IntermediateCall);
                node.CodeSnippet.Should().Be("test snippet");
            }

            [Fact]
            public void Constructor_ShouldAcceptNullCodeSnippet()
            {
                var node = new CallChainNode(
                    "Namespace.Type.Method:12",
                    "Test description",
                    CallChainNodeType.IntermediateCall
                );

                node.CodeSnippet.Should().BeNull();
            }

            [Theory]
            [InlineData(CallChainNodeType.EntryPoint, "[ENTRY]")]
            [InlineData(CallChainNodeType.IntermediateCall, "[CALL]")]
            [InlineData(CallChainNodeType.SuspiciousDeclaration, "[DECL]")]
            public void ToString_ShouldReturnCorrectPrefix(CallChainNodeType nodeType, string expectedPrefix)
            {
                var node = new CallChainNode(
                    "Namespace.Type.Method:12",
                    "Test description",
                    nodeType
                );

                var result = node.ToString();

                result.Should().StartWith(expectedPrefix);
                result.Should().Contain("Namespace.Type.Method:12");
                result.Should().Contain("Test description");
            }
        }

        public class CallChainTests_Class
        {
            [Fact]
            public void Constructor_ShouldSetAllProperties()
            {
                var chain = new CallChain(
                    "chain-123",
                    "TestRule",
                    Severity.High,
                    "Test summary"
                );

                chain.ChainId.Should().Be("chain-123");
                chain.RuleId.Should().Be("TestRule");
                chain.Severity.Should().Be(Severity.High);
                chain.Summary.Should().Be("Test summary");
                chain.Nodes.Should().NotBeNull();
                chain.Nodes.Should().BeEmpty();
            }

            [Fact]
            public void AppendNode_ShouldAddToEnd()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");
                var node1 = new CallChainNode("Loc1", "Desc1", CallChainNodeType.EntryPoint);
                var node2 = new CallChainNode("Loc2", "Desc2", CallChainNodeType.IntermediateCall);

                chain.AppendNode(node1);
                chain.AppendNode(node2);

                chain.Nodes.Should().HaveCount(2);
                chain.Nodes[0].Should().Be(node1);
                chain.Nodes[1].Should().Be(node2);
            }

            [Fact]
            public void PrependNode_ShouldAddToBeginning()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");
                var node1 = new CallChainNode("Loc1", "Desc1", CallChainNodeType.EntryPoint);
                var node2 = new CallChainNode("Loc2", "Desc2", CallChainNodeType.IntermediateCall);

                chain.AppendNode(node1);
                chain.PrependNode(node2);

                chain.Nodes.Should().HaveCount(2);
                chain.Nodes[0].Should().Be(node2);
                chain.Nodes[1].Should().Be(node1);
            }

            [Fact]
            public void ToDetailedDescription_WithNoNodes_ShouldReturnSummary()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Test summary");

                var result = chain.ToDetailedDescription();

                result.Should().Be("Test summary");
            }

            [Fact]
            public void ToDetailedDescription_WithNodes_ShouldFormatCorrectly()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Attack pattern");
                var node1 = new CallChainNode("Entry.Method:10", "Entry point", CallChainNodeType.EntryPoint);
                var node2 = new CallChainNode("Mid.Method:20", "Intermediate", CallChainNodeType.IntermediateCall);
                var node3 = new CallChainNode("Decl.Method:30", "Suspicious", CallChainNodeType.SuspiciousDeclaration);

                chain.AppendNode(node1);
                chain.AppendNode(node2);
                chain.AppendNode(node3);

                var result = chain.ToDetailedDescription();

                result.Should().Contain("Attack pattern");
                result.Should().Contain("Call chain:");
                result.Should().Contain("[ENTRY] Entry.Method:10: Entry point");
                result.Should().Contain("[CALL] Mid.Method:20: Intermediate");
                result.Should().Contain("[DECL] Decl.Method:30: Suspicious");
            }

            [Fact]
            public void ToDetailedDescription_ShouldReturnFormattedOutput()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");
                chain.AppendNode(new CallChainNode("L1", "D1", CallChainNodeType.EntryPoint));
                chain.AppendNode(new CallChainNode("L2", "D2", CallChainNodeType.IntermediateCall));
                chain.AppendNode(new CallChainNode("L3", "D3", CallChainNodeType.SuspiciousDeclaration));

                var result = chain.ToDetailedDescription();

                result.Should().NotBeNullOrEmpty();
                result.Should().Contain("Summary");
                result.Should().Contain("Call chain:");
                result.Should().Contain("[ENTRY]");
                result.Should().Contain("[CALL]");
                result.Should().Contain("[DECL]");
            }

            [Fact]
            public void ToCombinedCodeSnippet_WithNoNodes_ShouldReturnNull()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");

                var result = chain.ToCombinedCodeSnippet();

                result.Should().BeNull();
            }

            [Fact]
            public void ToCombinedCodeSnippet_WithNodesNoCode_ShouldReturnNull()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");
                chain.AppendNode(new CallChainNode("L1", "D1", CallChainNodeType.EntryPoint));
                chain.AppendNode(new CallChainNode("L2", "D2", CallChainNodeType.IntermediateCall));

                var result = chain.ToCombinedCodeSnippet();

                result.Should().BeNull();
            }

            [Fact]
            public void ToCombinedCodeSnippet_WithCode_ShouldCombineWithSeparation()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");
                chain.AppendNode(new CallChainNode("L1", "D1", CallChainNodeType.EntryPoint, "code1"));
                chain.AppendNode(new CallChainNode("L2", "D2", CallChainNodeType.SuspiciousDeclaration, "code2"));

                var result = chain.ToCombinedCodeSnippet();

                result.Should().NotBeNull();
                result.Should().Contain("// L1");
                result.Should().Contain("code1");
                result.Should().Contain("// L2");
                result.Should().Contain("code2");
            }

            [Fact]
            public void ToCombinedCodeSnippet_ShouldSeparateWithDoubleNewline()
            {
                var chain = new CallChain("chain-1", "Rule1", Severity.High, "Summary");
                chain.AppendNode(new CallChainNode("L1", "D1", CallChainNodeType.EntryPoint, "code1"));
                chain.AppendNode(new CallChainNode("L2", "D2", CallChainNodeType.SuspiciousDeclaration, "code2"));

        var result = chain.ToCombinedCodeSnippet();

        result.Should().Contain("code1");
        result.Should().Contain("code2");
        result.Should().Contain("\n\n");
            }
        }
    }
}