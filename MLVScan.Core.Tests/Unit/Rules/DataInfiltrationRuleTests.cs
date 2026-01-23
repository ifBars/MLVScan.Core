using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class DataInfiltrationRuleTests
{
    private readonly DataInfiltrationRule _rule = new();

    [Fact]
    public void RuleId_ReturnsDataInfiltrationRule()
    {
        _rule.RuleId.Should().Be("DataInfiltrationRule");
    }

    [Fact]
    public void Severity_ReturnsHigh()
    {
        _rule.Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsTrue()
    {
        _rule.RequiresCompanionFinding.Should().BeTrue();
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrWhiteSpace();
        _rule.Description.Should().Contain("infiltration");
    }

    [Fact]
    public void DeveloperGuidance_IsNotNull()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().Contain("GitHub");
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeContextualPattern_NullMethod_ReturnsNoFindings()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(null!, instructions, 0, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NullDeclaringType_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.CreateWithNullType("GetAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 0, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NonNetworkCall_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.Create("System.IO.File", "ReadAllText");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "test.txt"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_PostAsyncCall_ReturnsNoFindings()
    {
        // POST operations should be ignored by DataInfiltrationRule (handled by DataExfiltrationRule)
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/abc123"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NetworkCallWithNoLiterals_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Nop));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_GetStringAsyncWithRawPastebin_ReturnsHighSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/malware123"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Read-only operation to suspicious endpoint");
        findings[0].Description.Should().Contain("payload download");
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsyncWithHastebin_ReturnsHighSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://hastebin.com/raw/test456"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_DownloadStringWithBareIp_ReturnsHighSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadString");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "http://192.168.1.50/payload.dll"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_GetByteArrayAsyncWithNgrok_ReturnsHighSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetByteArrayAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://abc123.ngrok.io/malware.bin"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_DownloadDataWithTelegram_ReturnsHighSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadData");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.telegram.org/file/bot123/payload"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_DownloadFileWithBareIp_ReturnsHighSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadFile");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://10.0.0.1:443/file.exe"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_GitHubReleases_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://github.com/user/repo/releases/latest"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("GitHub");
        findings[0].Description.Should().Contain("likely legitimate");
    }

    [Fact]
    public void AnalyzeContextualPattern_GitHubApi_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.github.com/repos/user/repo/releases"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_RawGitHubUserContent_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://raw.githubusercontent.com/user/repo/main/version.txt"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_GitHubPages_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadString");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://user.github.io/project/config.json"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_Modrinth_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.modrinth.com/v2/project/mymod/version"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("mod hosting site");
    }

    [Fact]
    public void AnalyzeContextualPattern_Curseforge_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.curseforge.com/v1/mods/12345"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_Nexusmods_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadData");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.nexusmods.com/v1/games/skyrim/mods/12345"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_JsDelivrCdn_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetByteArrayAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://cdn.jsdelivr.net/npm/package@1.0.0/dist/bundle.js"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("CDN");
    }

    [Fact]
    public void AnalyzeContextualPattern_UnpkgCdn_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://unpkg.com/package@1.0.0/index.js"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_CdnjsCloudflare_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadString");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_GoogleStatic_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://fonts.gstatic.com/s/roboto/v30/font.woff2"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_GoogleApis_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://storage.googleapis.com/bucket/file.json"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void AnalyzeContextualPattern_MultipleUrlsInLiterals_IncludesAllInDescription()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/abc123"));
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "backup: https://pastebin.com/raw/def456"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 2, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("URL(s):");
    }

    [Fact]
    public void AnalyzeContextualPattern_SystemNetNamespace_DetectedAsNetworkCall()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebRequest", "GetResponse");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "http://192.168.1.1"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeContextualPattern_UnityWebRequest_DetectedAsNetworkCall()
    {
        var methodRef = MethodReferenceFactory.Create("UnityEngine.Networking.UnityWebRequest", "Get");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://ngrok.io/payload"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeContextualPattern_EmptyStringLiterals_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, ""));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_IncludesCodeSnippet()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Nop));
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/test"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        instructions.Add(Instruction.Create(OpCodes.Nop));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 2, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].CodeSnippet.Should().NotBeNullOrWhiteSpace();
        findings[0].CodeSnippet.Should().Contain(">>>");
    }

    [Fact]
    public void AnalyzeContextualPattern_IncludesLocationWithOffset()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        var ldstrInstr = Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/test");
        var callInstr = Instruction.Create(OpCodes.Call, methodRef);
        callInstr.Offset = 99;
        instructions.Add(ldstrInstr);
        instructions.Add(callInstr);
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Location.Should().Contain(":99");
    }

    [Fact]
    public void AnalyzeContextualPattern_LiteralsOutsideWindow_NotIncluded()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        // Add string far before the call (outside 10-instruction window)
        for (int i = 0; i < 15; i++)
        {
            instructions.Add(Instruction.Create(OpCodes.Nop));
        }
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/faraway"));
        for (int i = 0; i < 15; i++)
        {
            instructions.Add(Instruction.Create(OpCodes.Nop));
        }
        int callIndex = instructions.Count;
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));

        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, callIndex, methodSignals).ToList();

        findings.Should().BeEmpty();
    }
}
