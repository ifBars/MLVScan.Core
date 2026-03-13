using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ScanResultMapperTests
{
    private readonly byte[] _testAssemblyBytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00 }; // MZ header

    [Fact]
    public void ToDto_WithBasicFindings_CreatesDtoWithMetadata()
    {
        var findings = new List<ScanFinding>
        {
            new ScanFinding("Test.Method1", "Test finding", Severity.High, "code snippet")
        };
        var options = new ScanResultOptions
        {
            Platform = "test",
            CoreVersion = "1.0.0",
            PlatformVersion = "2.0.0"
        };

        var result = ScanResultMapper.ToDto(findings, "TestAssembly.dll", _testAssemblyBytes, options);

        result.Should().NotBeNull();
        result.SchemaVersion.Should().NotBeEmpty();
        result.Metadata.CoreVersion.Should().Be("1.0.0");
        result.Metadata.PlatformVersion.Should().Be("2.0.0");
        result.Metadata.Platform.Should().Be("test");
        result.Input.FileName.Should().Be("TestAssembly.dll");
        result.Input.SizeBytes.Should().Be(_testAssemblyBytes.Length);
        result.Input.Sha256Hash.Should().NotBeEmpty();
    }

    [Fact]
    public void ToDto_WithMultipleFindings_CountsCorrectly()
    {
        var findings = new List<ScanFinding>
        {
            new ScanFinding("Test.Method1", "Finding 1", Severity.High, "code 1"),
            new ScanFinding("Test.Method2", "Finding 2", Severity.Medium, "code 2"),
            new ScanFinding("Test.Method3", "Finding 3", Severity.Critical, "code 3")
        };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.Summary.TotalFindings.Should().Be(3);
        result.Findings.Should().HaveCount(3);
    }

    [Fact]
    public void ToDto_GroupsBySeverityCorrectly()
    {
        var findings = new List<ScanFinding>
        {
            new ScanFinding("Test.M1", "F1", Severity.High, "c1"),
            new ScanFinding("Test.M2", "F2", Severity.High, "c2"),
            new ScanFinding("Test.M3", "F3", Severity.Medium, "c3"),
            new ScanFinding("Test.M4", "F4", Severity.Critical, "c4")
        };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.Summary.CountBySeverity["High"].Should().Be(2);
        result.Summary.CountBySeverity["Medium"].Should().Be(1);
        result.Summary.CountBySeverity["Critical"].Should().Be(1);
    }

    [Fact]
    public void ToDto_WithRuleIds_CollectsTriggeredRules()
    {
        var finding1 = new ScanFinding("Test.M1", "F1", Severity.High, "c1");
        finding1.RuleId = "Rule1";
        var finding2 = new ScanFinding("Test.M2", "F2", Severity.High, "c2");
        finding2.RuleId = "Rule2";
        var finding3 = new ScanFinding("Test.M3", "F3", Severity.Medium, "c3");
        finding3.RuleId = "Rule1"; // Duplicate

        var findings = new List<ScanFinding> { finding1, finding2, finding3 };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.Summary.TriggeredRules.Should().HaveCount(2);
        result.Summary.TriggeredRules.Should().Contain("Rule1");
        result.Summary.TriggeredRules.Should().Contain("Rule2");
    }

    [Fact]
    public void ToDto_WithCallChain_IncludesCallChainInFinding()
    {
        var callChain = new CallChain("test-chain", "TestRule", Severity.High, "Test chain");
        callChain.AppendNode(new CallChainNode("Location1", "Desc1", CallChainNodeType.EntryPoint, "snippet1"));

        var finding = new ScanFinding("Test.Method", "Test", Severity.High, "code");
        finding.CallChain = callChain;

        var findings = new List<ScanFinding> { finding };
        var options = new ScanResultOptions { IncludeCallChains = true };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.Findings[0].CallChain.Should().NotBeNull();
        result.Findings[0].CallChainId.Should().Be("test-chain");
        result.Findings[0].CallChain!.Id.Should().Be("test-chain");
        result.CallChains.Should().NotBeNull();
        result.CallChains!.Should().HaveCount(1);
    }

    [Fact]
    public void ToDto_WithCallChainsDisabled_DoesNotIncludeCallChains()
    {
        var callChain = new CallChain("test-chain", "TestRule", Severity.High, "Test chain");
        var finding = new ScanFinding("Test.Method", "Test", Severity.High, "code");
        finding.CallChain = callChain;

        var findings = new List<ScanFinding> { finding };
        var options = new ScanResultOptions { IncludeCallChains = false };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.CallChains.Should().BeNull();
    }

    [Fact]
    public void ToDto_WithDataFlow_IncludesDataFlowInFinding()
    {
        var dataFlow = new DataFlowChain("df-chain", DataFlowPattern.DynamicCodeLoading, Severity.High, "Flow", "method");
        dataFlow.IsCrossMethod = true;
        dataFlow.InvolvedMethods = new List<string> { "method1", "method2" };
        dataFlow.AppendNode(new DataFlowNode("Location1", "Load", DataFlowNodeType.Source, "Data", 0, "snippet1", "method1"));

        var finding = new ScanFinding("Test.Method", "Test", Severity.High, "code");
        finding.DataFlowChain = dataFlow;

        var findings = new List<ScanFinding> { finding };
        var options = new ScanResultOptions { IncludeDataFlows = true };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.Findings[0].DataFlowChain.Should().NotBeNull();
        result.Findings[0].DataFlowChainId.Should().Be("df-chain");
        result.Findings[0].DataFlowChain!.IsSuspicious.Should().BeTrue();
        result.Findings[0].DataFlowChain!.CallDepth.Should().Be(2);
        result.DataFlows.Should().NotBeNull();
        result.DataFlows!.Should().HaveCount(1);
        result.DataFlows[0].IsSuspicious.Should().BeTrue();
        result.DataFlows[0].CallDepth.Should().Be(2);
    }

    [Fact]
    public void ToDto_WithDeveloperGuidance_IncludesGuidance()
    {
        var guidance = new DeveloperGuidance("Fix this", "http://docs.example.com", new[] { "Alt1", "Alt2" }, true);
        var finding = new ScanFinding("Test.Method", "Test", Severity.High, "code");
        finding.RuleId = "TestRule";
        finding.DeveloperGuidance = guidance;

        var findings = new List<ScanFinding> { finding };
        var options = new ScanResultOptions { IncludeDeveloperGuidance = true };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.DeveloperGuidance.Should().NotBeNull();
        result.DeveloperGuidance!.Should().HaveCount(1);
        result.DeveloperGuidance[0].RuleId.Should().Be("TestRule");
        result.DeveloperGuidance[0].RuleIds.Should().Equal("TestRule");
        result.DeveloperGuidance![0].Remediation.Should().Be("Fix this");
        result.Findings[0].DeveloperGuidance.Should().NotBeNull();
        result.Findings[0].DeveloperGuidance!.RuleIds.Should().Equal("TestRule");
    }

    [Fact]
    public void ToDto_WithDeveloperGuidanceDisabled_DoesNotIncludeGuidance()
    {
        var guidance = new DeveloperGuidance("Fix this", null, null, false);
        var finding = new ScanFinding("Test.Method", "Test", Severity.High, "code");
        finding.DeveloperGuidance = guidance;

        var findings = new List<ScanFinding> { finding };
        var options = new ScanResultOptions { IncludeDeveloperGuidance = false };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.DeveloperGuidance.Should().BeNull();
        result.Findings[0].DeveloperGuidance.Should().BeNull();
    }

    [Fact]
    public void ToDto_WithRiskScore_IncludesRiskScore()
    {
        var finding = new ScanFinding("Test.Method", "Test", Severity.High, "code")
        {
            RiskScore = 82
        };

        var result = ScanResultMapper.ToDto(new[] { finding }, "test.dll", _testAssemblyBytes, false);

        result.Findings[0].RiskScore.Should().Be(82);
    }

    [Fact]
    public void ToDto_DefaultOverload_UsesDeveloperModeCorrectly()
    {
        var findings = new List<ScanFinding>
        {
            new ScanFinding("Test.Method", "Test", Severity.High, "code")
        };

        var resultNoDev = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);
        var resultWithDev = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, true);

        resultNoDev.Metadata.ScanMode.Should().Be("detailed");
        resultWithDev.Metadata.ScanMode.Should().Be("developer");
    }

    [Fact]
    public void ToDto_ComputesSha256HashCorrectly()
    {
        var findings = new List<ScanFinding>();
        var knownBytes = new byte[] { 0x00, 0x01, 0x02, 0x03 };

        var result = ScanResultMapper.ToDto(findings, "test.dll", knownBytes, false);

        result.Input.Sha256Hash.Should().NotBeEmpty();
        result.Input.Sha256Hash.Should().HaveLength(64); // SHA256 hash is 64 hex characters
    }

    [Fact]
    public void ToDto_GeneratesUniqueIdForEachFinding()
    {
        var findings = new List<ScanFinding>
        {
            new ScanFinding("Test.M1", "F1", Severity.High, "c1"),
            new ScanFinding("Test.M2", "F2", Severity.High, "c2")
        };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.Findings[0].Id.Should().NotBeNullOrEmpty();
        result.Findings[1].Id.Should().NotBeNullOrEmpty();
        result.Findings[0].Id.Should().NotBe(result.Findings[1].Id);
    }

    [Fact]
    public void ToDto_SetsTimestamp()
    {
        var findings = new List<ScanFinding>();

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.Metadata.Timestamp.Should().NotBeNullOrEmpty();
        DateTime.TryParse(result.Metadata.Timestamp, out _).Should().BeTrue();
    }

    [Fact]
    public void ScanResultOptions_ForWasm_SetsCorrectPlatform()
    {
        var options = ScanResultOptions.ForWasm();

        options.Platform.Should().Be("wasm");
        options.ScanMode.Should().Be("detailed");
        options.IncludeDeveloperGuidance.Should().BeFalse();
    }

    [Fact]
    public void ScanResultOptions_ForWasmDeveloper_EnablesGuidance()
    {
        var options = ScanResultOptions.ForWasm(true);

        options.Platform.Should().Be("wasm");
        options.ScanMode.Should().Be("developer");
        options.IncludeDeveloperGuidance.Should().BeTrue();
    }

    [Fact]
    public void ScanResultOptions_ForCli_SetsCorrectPlatform()
    {
        var options = ScanResultOptions.ForCli();

        options.Platform.Should().Be("cli");
    }

    [Fact]
    public void ScanResultOptions_ForServer_SetsCorrectPlatform()
    {
        var options = ScanResultOptions.ForServer();

        options.Platform.Should().Be("server");
    }

    [Fact]
    public void ScanResultOptions_ForDesktop_SetsCorrectPlatform()
    {
        var options = ScanResultOptions.ForDesktop();

        options.Platform.Should().Be("desktop");
    }

    [Fact]
    public void ToDto_WithDuplicateDataFlows_DeduplicatesCorrectly()
    {
        var dataFlow = new DataFlowChain("df-1", DataFlowPattern.DynamicCodeLoading, Severity.High, "Flow", "method");
        dataFlow.AppendNode(new DataFlowNode("Location1", "Load", DataFlowNodeType.Source, "Data", 0)); // Add a node so HasDataFlow returns true

        var finding1 = new ScanFinding("Test.M1", "F1", Severity.High, "c1");
        finding1.DataFlowChain = dataFlow;

        var finding2 = new ScanFinding("Test.M2", "F2", Severity.High, "c2");
        finding2.DataFlowChain = dataFlow; // Same instance

        var findings = new List<ScanFinding> { finding1, finding2 };
        var options = new ScanResultOptions { IncludeDataFlows = true };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.DataFlows.Should().NotBeNull();
        result.DataFlows!.Should().HaveCount(1); // Deduplicated
    }

    [Fact]
    public void ToDto_WithDuplicateDeveloperGuidance_DeduplicatesByRemediation()
    {
        var guidance1 = new DeveloperGuidance("Same fix", "url1", null, true);
        var guidance2 = new DeveloperGuidance("Same fix", "url2", null, true);

        var finding1 = new ScanFinding("Test.M1", "F1", Severity.High, "c1");
        finding1.RuleId = "Rule1";
        finding1.DeveloperGuidance = guidance1;

        var finding2 = new ScanFinding("Test.M2", "F2", Severity.High, "c2");
        finding2.RuleId = "Rule2";
        finding2.DeveloperGuidance = guidance2;

        var findings = new List<ScanFinding> { finding1, finding2 };
        var options = new ScanResultOptions { IncludeDeveloperGuidance = true };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, options);

        result.DeveloperGuidance.Should().HaveCount(1); // Deduplicated by Remediation
        result.DeveloperGuidance![0].RuleId.Should().BeNull();
        result.DeveloperGuidance[0].RuleIds.Should().BeEquivalentTo(new[] { "Rule1", "Rule2" });
    }

    [Fact]
    public void ToDto_WithKnownThreatFamily_IncludesThreatFamilies()
    {
        var findings = new List<ScanFinding>
        {
            new("Test.Mod.Init:52",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: iwr ... dl.bat ... Start-Sleep ... Remove-Item [Evasion: UseShellExecute=true, WindowStyle=Hidden]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.ThreatFamilies.Should().NotBeNull();
        result.ThreatFamilies!.Should().ContainSingle();
        result.ThreatFamilies[0].FamilyId.Should().Be("family-powershell-iwr-dlbat-v1");
        result.ThreatFamilies[0].MatchKind.Should().Be("BehaviorVariant");
        result.ThreatFamilies[0].Evidence.Should().Contain(e =>
            e.Kind == "rule" &&
            e.RuleId == "ProcessStartRule" &&
            e.Location == "Test.Mod.Init:52");
    }

    [Fact]
    public void ToDto_WithThreatFamilyStructuredEvidence_MapsEvidenceContextFields()
    {
        var callChain = new CallChain("cc-resource-shell32", "DllImportRule", Severity.Critical, "ShellExecute chain");
        callChain.AppendNode(new CallChainNode("Malware.Loader.Init", "Entry point", CallChainNodeType.EntryPoint));
        callChain.AppendNode(new CallChainNode(
            "Malware.Loader.ExtractPayload",
            "P/Invoke declaration for shell32.dll ShellExecuteEx",
            CallChainNodeType.SuspiciousDeclaration));

        var dataFlow = new DataFlowChain(
            "df-resource-shell32",
            DataFlowPattern.EmbeddedResourceDropAndExecute,
            Severity.Critical,
            "Embedded resource extracted to temp cmd and executed",
            "Malware.Loader.ExtractPayload");
        dataFlow.AppendNode(new DataFlowNode(
            "Malware.Loader.ExtractPayload:41",
            "PInvoke.ShellExecuteEx",
            DataFlowNodeType.Sink,
            "execute temp cmd",
            41));

        var finding = new ScanFinding("Malware.Loader.ExtractPayload", "Native shell execution detected", Severity.Critical)
        {
            RuleId = "DllImportRule",
            CallChain = callChain,
            DataFlowChain = dataFlow
        };

        var result = ScanResultMapper.ToDto(new[] { finding }, "test.dll", _testAssemblyBytes, false);

        result.ThreatFamilies.Should().NotBeNullOrEmpty();
        var family = result.ThreatFamilies!.First(match => match.FamilyId == "family-resource-shell32-tempcmd-v1");
        family.Evidence.Should().Contain(e =>
            e.Kind == "call-chain" &&
            e.CallChainId == "cc-resource-shell32");
        family.Evidence.Should().Contain(e =>
            e.Kind == "data-flow-chain" &&
            e.DataFlowChainId == "df-resource-shell32" &&
            e.Pattern == "EmbeddedResourceDropAndExecute" &&
            e.MethodLocation == "Malware.Loader.ExtractPayload");
    }

    [Fact]
    public void ToDto_WithNoKnownThreatFamily_LeavesThreatFamiliesNull()
    {
        var findings = new List<ScanFinding>
        {
            new("Test.Mod.Init", "Opens a local folder for the user.", Severity.Low)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var result = ScanResultMapper.ToDto(findings, "test.dll", _testAssemblyBytes, false);

        result.ThreatFamilies.Should().BeNull();
    }
}
