using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.DataFlow;
using MLVScan.Services.DataFlow;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DataFlowPatternEvaluatorTests
{
    [Fact]
    public void RecognizePattern_WithLinkedFileWriteAndProcessTarget_ReturnsEmbeddedDropper()
    {
        var operations = CreateEmbeddedResourceOperations("method::local:4", "method::local:4");

        new DataFlowPatternEvaluator().RecognizePattern(operations)
            .Should().Be(DataFlowPattern.EmbeddedResourceDropAndExecute);
    }

    [Fact]
    public void RecognizePattern_WithUnrelatedFileWriteAndProcessTarget_DoesNotReturnEmbeddedDropper()
    {
        var operations = CreateEmbeddedResourceOperations("method::local:4", "method::local:7");

        new DataFlowPatternEvaluator().RecognizePattern(operations)
            .Should().Be(DataFlowPattern.Unknown,
                "nearby resource handling and process execution are not a linked payload flow");
    }

    [Fact]
    public void RecognizePattern_WithExecutionBeforeMatchingWrite_DoesNotReturnEmbeddedDropper()
    {
        var operations = CreateEmbeddedResourceOperations("method::local:4", "method::local:4");
        (operations[1], operations[2]) = (operations[2], operations[1]);

        new DataFlowPatternEvaluator().RecognizePattern(operations)
            .Should().Be(DataFlowPattern.Unknown,
                "a payload written only after execution was not dropped and executed");
    }

    [Fact]
    public void CreateFinding_WithEmbeddedExecutableDropperWithoutScriptMarkers_PreservesSeverity()
    {
        var chain = new DataFlowChain(
            "df-embedded-executable",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Extracts and launches an embedded executable",
            "Malware.Loader.Run");
        chain.AppendNode(new DataFlowNode(
            "Malware.Loader.Run:12",
            "GetManifestResourceStream",
            DataFlowNodeType.Source,
            "embedded executable",
            12));
        chain.AppendNode(new DataFlowNode(
            "Malware.Loader.Run:24",
            "File.Create",
            DataFlowNodeType.Sink,
            "C:/AppData/Vendor/updater.exe",
            24));
        chain.AppendNode(new DataFlowNode(
            "Malware.Loader.Run:36",
            "Process.Start",
            DataFlowNodeType.Sink,
            "launch updater executable",
            36));

        var finding = new DataFlowPatternEvaluator().CreateFinding(chain);

        finding.Severity.Should().Be(Severity.Critical);
    }

    private static List<DataFlowInterestingOperation> CreateEmbeddedResourceOperations(
        string writtenPath,
        string executedPath)
    {
        return new List<DataFlowInterestingOperation>
        {
            new()
            {
                NodeType = DataFlowNodeType.Source,
                Operation = "Assembly.GetManifestResourceStream",
                DataDescription = "embedded resource"
            },
            new()
            {
                NodeType = DataFlowNodeType.Sink,
                Operation = "File.Create",
                DataDescription = "Writes to file",
                PayloadPathIdentities = new HashSet<string>(StringComparer.Ordinal) { writtenPath }
            },
            new()
            {
                NodeType = DataFlowNodeType.Sink,
                Operation = "Process.Start",
                DataDescription = "Executes process",
                PayloadPathIdentities = new HashSet<string>(StringComparer.Ordinal) { executedPath }
            }
        };
    }
}
