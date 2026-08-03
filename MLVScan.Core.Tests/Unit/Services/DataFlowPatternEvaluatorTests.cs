using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.DataFlow;
using MLVScan.Services.DataFlow;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DataFlowPatternEvaluatorTests
{
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
}
