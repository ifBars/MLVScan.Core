using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ThreatDispositionClassifierTests
{
    [Fact]
    public void Classify_WithFamilyMatch_ReturnsKnownThreat()
    {
        var classifier = new ThreatDispositionClassifier();
        var finding = new ScanFinding("Malware.Loader.Init", "Known malware behavior", Severity.Critical)
        {
            RuleId = "ProcessStartRule"
        };
        var threatFamilies = new[]
        {
            new ThreatFamilyMatch
            {
                FamilyId = "family-known",
                VariantId = "variant-a",
                DisplayName = "Known Family",
                Summary = "Known malware family",
                MatchKind = ThreatMatchKind.BehaviorVariant,
                Confidence = 0.8,
                MatchedRules = { "ProcessStartRule" },
                Evidence =
                {
                    new ThreatFamilyEvidence
                    {
                        Kind = "rule",
                        Value = "Process start",
                        RuleId = "ProcessStartRule",
                        Location = "Malware.Loader.Init"
                    }
                }
            }
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies);

        result.Classification.Should().Be(ThreatDispositionClassification.KnownThreat);
        result.PrimaryThreatFamilyId.Should().Be("family-known");
        result.RelatedFindings.Should().ContainSingle().Which.Should().BeSameAs(finding);
    }

    [Fact]
    public void Classify_WithExactHashAndBehaviorVariant_PrefersExactHashMatch()
    {
        var classifier = new ThreatDispositionClassifier();
        var threatFamilies = new[]
        {
            new ThreatFamilyMatch
            {
                FamilyId = "family-behavior",
                VariantId = "variant-a",
                DisplayName = "Behavior Variant",
                MatchKind = ThreatMatchKind.BehaviorVariant,
                Confidence = 0.99
            },
            new ThreatFamilyMatch
            {
                FamilyId = "family-exact",
                VariantId = "variant-b",
                DisplayName = "Exact Sample",
                MatchKind = ThreatMatchKind.ExactSampleHash,
                Confidence = 0.5,
                ExactHashMatch = true
            }
        };

        var result = classifier.Classify(Array.Empty<ScanFinding>(), threatFamilies);

        result.Classification.Should().Be(ThreatDispositionClassification.KnownThreat);
        result.PrimaryThreatFamilyId.Should().Be("family-exact");
    }

    [Fact]
    public void Classify_WithSuspiciousDataFlow_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var dataFlow = new DataFlowChain(
            "df-download-exec",
            DataFlowPattern.DownloadAndExecute,
            Severity.High,
            "Downloads and executes a staged payload",
            "Suspicious.Mod.Loader");
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:12",
            "DownloadFile",
            DataFlowNodeType.Source,
            "Remote payload",
            12));
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:27",
            "Process.Start",
            DataFlowNodeType.Sink,
            "Execute payload",
            27));

        var finding = new ScanFinding("Suspicious.Mod.Loader", "Suspicious staged payload execution detected", Severity.High)
        {
            RuleId = "DataFlowAnalysis",
            DataFlowChain = dataFlow
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().ContainSingle().Which.Should().BeSameAs(finding);
    }

    [Fact]
    public void Classify_WithEmbeddedResourceTempCmdDropperDataFlow_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var dataFlow = new DataFlowChain(
            "df-resource-cmd",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Embedded resource extracted to %TEMP%/payload.cmd and executed via ShellExecuteEx",
            "Suspicious.Mod.Loader");
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:12",
            "GetManifestResourceStream",
            DataFlowNodeType.Source,
            "embedded payload",
            12));
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:27",
            "PInvoke.ShellExecuteEx",
            DataFlowNodeType.Sink,
            "%TEMP%/payload.cmd",
            27));

        var finding = new ScanFinding(
            "Suspicious.Mod.Loader",
            "Embedded resource dropper launches %TEMP%/payload.cmd through ShellExecuteEx with nShow=0",
            Severity.Critical)
        {
            RuleId = "DataFlowAnalysis",
            DataFlowChain = dataFlow
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().ContainSingle().Which.Should().BeSameAs(finding);
    }

    [Fact]
    public void Classify_WithEmbeddedUpdaterExeDataFlowAndNoDropperMarkers_ReturnsClean()
    {
        var classifier = new ThreatDispositionClassifier();
        var dataFlow = new DataFlowChain(
            "df-local-updater",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Extracts embedded updater executable and launches it from a local data directory",
            "Benign.Updater.Run");
        dataFlow.AppendNode(new DataFlowNode(
            "Benign.Updater.Run:12",
            "GetManifestResourceStream",
            DataFlowNodeType.Source,
            "embedded updater resource",
            12));
        dataFlow.AppendNode(new DataFlowNode(
            "Benign.Updater.Run:24",
            "File.Create",
            DataFlowNodeType.Sink,
            "C:/AppData/Vendor/updater.exe",
            24));
        dataFlow.AppendNode(new DataFlowNode(
            "Benign.Updater.Run:36",
            "Process.Start",
            DataFlowNodeType.Sink,
            "run local updater executable",
            36));

        var finding = new ScanFinding(
            "Benign.Updater.Run",
            "Embedded updater executable extracted and launched with Process.Start",
            Severity.Critical)
        {
            RuleId = "DataFlowAnalysis",
            DataFlowChain = dataFlow
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Clean);
        result.RelatedFindings.Should().BeEmpty();
        result.BlockingRecommended.Should().BeFalse();
    }

    [Fact]
    public void Classify_WithStandalonePrimitiveFinding_ReturnsClean()
    {
        var classifier = new ThreatDispositionClassifier();
        var finding = new ScanFinding("Legit.Mod.Start", "Reads local config and opens a folder", Severity.High)
        {
            RuleId = "DataExfiltrationRule"
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Clean);
        result.RelatedFindings.Should().BeEmpty();
        result.BlockingRecommended.Should().BeFalse();
    }

    [Fact]
    public void Classify_WithSingleHighSeverityCallChainFinding_ReturnsClean()
    {
        var classifier = new ThreatDispositionClassifier();
        var callChain = new CallChain("cc-native-socket", "DllImportRule", Severity.High, "Native socket receive path");
        callChain.AppendNode(new CallChainNode("Net.Socket.RecvFrom", "Calls recvfrom", CallChainNodeType.IntermediateCall));
        callChain.AppendNode(new CallChainNode("Net.Socket.Native.recvfrom", "P/Invoke declaration", CallChainNodeType.SuspiciousDeclaration));

        var finding = new ScanFinding("Net.Socket.RecvFrom", "Native socket receive interop", Severity.High)
        {
            RuleId = "DllImportRule",
            CallChain = callChain
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Clean);
        result.RelatedFindings.Should().BeEmpty();
    }
}
