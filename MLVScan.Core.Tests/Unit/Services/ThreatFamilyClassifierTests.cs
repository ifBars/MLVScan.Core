using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ThreatFamilyClassifierTests
{
    [Fact]
    public void Classify_WithExactKnownHash_ReturnsExactHashMatch()
    {
        var classifier = new ThreatFamilyClassifier();

        var findings = new List<ScanFinding>();

        var matches = classifier.Classify(findings, "6c15802426e22e8a0376af1be8bb5caebb5b2e2f4f06a8e7944c80c647a548e6");

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-powershell-iwr-dlbat-v1");
        matches[0].MatchKind.Should().Be(ThreatMatchKind.ExactSampleHash);
        matches[0].ExactHashMatch.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithPowerShellDownloaderBehavior_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Test.Mod.Init:52",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: iwr ... dl.bat ... Start-Sleep ... Remove-Item [Evasion: UseShellExecute=true, WindowStyle=Hidden]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-powershell-iwr-dlbat-v1");
        matches[0].MatchKind.Should().Be(ThreatMatchKind.BehaviorVariant);
        matches[0].MatchedRules.Should().Contain("ProcessStartRule");
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "rule" &&
            e.RuleId == "ProcessStartRule" &&
            e.Location == "Test.Mod.Init:52");
    }

    [Fact]
    public void Classify_WithEmbeddedResourceDataFlowAndShellCallChain_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var callChain = new CallChain(
            "cc-resource-shell32",
            "DllImportRule",
            Severity.Critical,
            "Native shell execution path")
        {
            Nodes =
            {
                new CallChainNode("Malware.Loader.Init", "Entry point calls ExtractPayload", CallChainNodeType.EntryPoint),
                new CallChainNode("Malware.Loader.ExtractPayload", "P/Invoke declaration for shell32.dll ShellExecuteEx", CallChainNodeType.SuspiciousDeclaration)
            }
        };

        var dataFlow = new DataFlowChain(
            "df-resource-shell32",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Embedded resource extracted to %TEMP%/payload.cmd and executed",
            "Malware.Loader.ExtractPayload")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.ExtractPayload:14", "GetManifestResourceStream", DataFlowNodeType.Source, "embedded resource payload", 14),
                new DataFlowNode("Malware.Loader.ExtractPayload:28", "File.WriteAllBytes", DataFlowNodeType.Sink, "%TEMP%/payload.cmd", 28),
                new DataFlowNode("Malware.Loader.ExtractPayload:41", "PInvoke.ShellExecuteEx", DataFlowNodeType.Sink, "execute temp cmd", 41)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.ExtractPayload", "Native shell execution detected", Severity.Critical)
            {
                RuleId = "DllImportRule",
                CallChain = callChain,
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, new[] { callChain }, new[] { dataFlow }, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-resource-shell32-tempcmd-v2");
        matches[0].MatchedRules.Should().Contain(new[] { "DataFlowAnalysis", "DllImportRule" });
        matches[0].Evidence.Should().Contain(e => e.Kind == "pattern" && e.Value == DataFlowPattern.EmbeddedResourceDropAndExecute.ToString());
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "call-chain" &&
            e.CallChainId == "cc-resource-shell32");
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "data-flow-chain" &&
            e.DataFlowChainId == "df-resource-shell32" &&
            e.Pattern == DataFlowPattern.EmbeddedResourceDropAndExecute.ToString());
    }

    [Fact]
    public void Classify_WithEmbeddedUpdaterProcessStartAndNoCmdOrShellExecute_ReturnsNoMatches()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-updater-process-start",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Extracts embedded updater and starts it from an application data folder",
            "Benign.Updater.Run")
        {
            Nodes =
            {
                new DataFlowNode("Benign.Updater.Run:12", "GetManifestResourceStream", DataFlowNodeType.Source, "embedded updater resource", 12),
                new DataFlowNode("Benign.Updater.Run:24", "File.Create", DataFlowNodeType.Sink, "C:/AppData/Vendor/updater.exe", 24),
                new DataFlowNode("Benign.Updater.Run:36", "Process.Start", DataFlowNodeType.Sink, "run local updater executable", 36)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Benign.Updater.Run", "Embedded updater executable extracted and launched with Process.Start", Severity.Critical)
            {
                RuleId = "DataFlowAnalysis",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().BeEmpty();
    }

    [Fact]
    public void Classify_WithEmbeddedTempCmdAndProcessStart_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-resource-process-start",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Embedded resource extracted to %TEMP%/payload.cmd and executed with Process.Start",
            "Malware.Loader.Run")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Run:12", "GetManifestResourceStream", DataFlowNodeType.Source, "embedded resource payload", 12),
                new DataFlowNode("Malware.Loader.Run:24", "File.WriteAllBytes", DataFlowNodeType.Sink, "%TEMP%/payload.cmd", 24),
                new DataFlowNode("Malware.Loader.Run:36", "Process.Start", DataFlowNodeType.Sink, "execute temp cmd", 36)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Run", "Embedded resource temp cmd execution chain", Severity.Critical)
            {
                RuleId = "DataFlowAnalysis",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Run:36", "Detected Process.Start call which could execute arbitrary programs. Target: " +
                "\"cmd.exe\". Arguments: /c %TEMP%\\payload.cmd [Evasion: CreateNoWindow=true] [Process with evasion and temp path execution]", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-resource-shell32-tempcmd-v2");
        matches[0].VariantId.Should().Be("resource-shell32-tempcmd-process-start");
        matches[0].MatchedRules.Should().Contain(new[] { "DataFlowAnalysis", "ProcessStartRule" });
    }

    [Fact]
    public void Classify_WithWebClientDownloadExecuteDataFlow_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-webclient-stage",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads payload with WebClient and executes it from TEMP",
            "Malware.Loader.Stage")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Stage:12", "DownloadFileTaskAsync", DataFlowNodeType.Source, "remote payload", 12),
                new DataFlowNode("Malware.Loader.Stage:24", "File.WriteAllBytes", DataFlowNodeType.Sink, "%TEMP%/d.bat", 24),
                new DataFlowNode("Malware.Loader.Stage:36", "Process.Start", DataFlowNodeType.Sink, "execute staged payload", 36)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Stage", "Network staging activity", Severity.Critical)
            {
                RuleId = "DataInfiltrationRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage", "Launches staged payload from TEMP", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webclient-stage-exec-v1");
        matches[0].MatchedRules.Should().Contain(new[] { "DataFlowAnalysis", "DataInfiltrationRule", "ProcessStartRule" });
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "source" &&
            e.DataFlowChainId == "df-webclient-stage" &&
            e.MethodLocation == "Malware.Loader.Stage");
    }

    [Fact]
    public void Classify_WithMetadataLoaderSignalsAndChains_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var callChain = new CallChain(
            "cc-metadata-loader",
            "ReflectionRule",
            Severity.High,
            "Metadata-backed reflective loader")
        {
            Nodes =
            {
                new CallChainNode("Malware.Loader.Init", "Entry point calls metadata reader", CallChainNodeType.EntryPoint),
                new CallChainNode("Malware.Loader.Metadata", "Reads AssemblyMetadataAttribute values to reconstruct loader strings", CallChainNodeType.SuspiciousDeclaration)
            }
        };

        var dataFlow = new DataFlowChain(
            "df-metadata-loader",
            DataFlowPattern.DynamicCodeLoading,
            Severity.Critical,
            "Decoded metadata-backed payload is loaded dynamically",
            "Malware.Loader.Metadata")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Metadata:10", "NumericStringDecode", DataFlowNodeType.Transform, "numeric decode pipeline", 10),
                new DataFlowNode("Malware.Loader.Metadata:32", "Assembly.Load", DataFlowNodeType.Sink, "dynamic payload load", 32)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Metadata", "Hidden ProcessStartInfo launcher recovered from numeric strings", Severity.High)
            {
                RuleId = "EncodedStringLiteralRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Metadata", "Numeric string decode pipeline detected", Severity.High)
            {
                RuleId = "EncodedStringPipelineRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Metadata", "Reflection over AssemblyMetadataAttribute values", Severity.High)
            {
                RuleId = "ReflectionRule",
                CallChain = callChain,
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, new[] { callChain }, new[] { dataFlow }, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-obfuscated-metadata-loader-v1");
        matches[0].MatchedRules.Should().Contain(new[]
        {
            "DataFlowAnalysis",
            "EncodedStringLiteralRule",
            "EncodedStringPipelineRule",
            "ReflectionRule"
        });
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "call-chain" &&
            e.CallChainId == "cc-metadata-loader");
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "data-flow-pattern" &&
            e.DataFlowChainId == "df-metadata-loader" &&
            e.Pattern == DataFlowPattern.DynamicCodeLoading.ToString());
    }

    [Fact]
    public void Classify_WithNoKnownSignals_ReturnsNoMatches()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Legit.Mod.Start", "Opens explorer for a local folder.", Severity.Low)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().BeEmpty();
    }
}
