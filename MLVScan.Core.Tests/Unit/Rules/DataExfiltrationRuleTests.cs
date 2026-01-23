using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class DataExfiltrationRuleTests
{
    private readonly DataExfiltrationRule _rule = new();

    [Fact]
    public void AnalyzeContextualPattern_NullMethod_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var type = assembly.MainModule.Types.First();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(null!, instructions, 0, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NullDeclaringType_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.CreateWithNullType("PostAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 0, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NonNetworkCall_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.Create("System.Console", "WriteLine");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "Hello"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NetworkCallWithNoLiterals_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Nop));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        instructions.Add(Instruction.Create(OpCodes.Nop));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsyncCall_ReturnsNoFindings()
    {
        // GET operations should be ignored by DataExfiltrationRule (handled by DataInfiltrationRule)
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/123/abc"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_DiscordWebhookPost_ReturnsCriticalFinding()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/123456/abcdef"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        instructions.Add(Instruction.Create(OpCodes.Nop));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Discord webhook");
        findings[0].Description.Should().Contain("exfiltration");
    }

    [Fact]
    public void AnalyzeContextualPattern_RawPastebinPost_ReturnsCriticalFinding()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "UploadString");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/abc123"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Data-sending operation");
        findings[0].Description.Should().Contain("suspicious endpoint");
    }

    [Fact]
    public void AnalyzeContextualPattern_BareIpUrlPost_ReturnsCriticalFinding()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "http://192.168.1.100:8080/data"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Data-sending operation");
    }

    [Fact]
    public void AnalyzeContextualPattern_NgrokPost_ReturnsCriticalFinding()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "SendAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://abc123.ngrok.io/collect"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_TelegramPost_ReturnsCriticalFinding()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebClient", "UploadData");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.telegram.org/bot123/sendMessage"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_UnknownOperationWithSuspiciousUrl_ReturnsMediumSeverity()
    {
        // Unknown operation type (not GET/POST/PUT/etc.) should return Medium severity
        var methodRef = MethodReferenceFactory.Create("System.Net.Sockets.TcpClient", "Connect");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "http://10.0.0.1:9999"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Medium);
        findings[0].Description.Should().Contain("Potential payload download");
    }

    [Fact]
    public void AnalyzeContextualPattern_GitHubPost_ReturnsLowSeverity()
    {
        // Posting to GitHub (API interaction) should be Low severity
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.github.com/repos/user/repo/issues"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("Data-sending operation to GitHub");
    }

    [Fact]
    public void AnalyzeContextualPattern_ModrinthPost_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PutAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://api.modrinth.com/v2/project"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("mod hosting site");
    }

    [Fact]
    public void AnalyzeContextualPattern_CDNPost_ReturnsLowSeverity()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://cdn.jsdelivr.net/upload"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("CDN");
    }

    [Fact]
    public void AnalyzeContextualPattern_MultipleUrlsInLiterals_IncludesAllInDescription()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/123/abc"));
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "backup: https://discord.com/api/webhooks/456/def"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 2, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("URL(s):");
    }

    [Fact]
    public void AnalyzeContextualPattern_SystemNetNamespace_DetectedAsNetworkCall()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.WebRequest", "Create");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/test/test"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_UnityWebRequest_DetectedAsNetworkCall()
    {
        var methodRef = MethodReferenceFactory.Create("UnityEngine.Networking.UnityWebRequest", "Post");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "http://192.168.1.1"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeContextualPattern_SocketsNamespace_DetectedAsNetworkCall()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Sockets.Socket", "Send");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/test"));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public void AnalyzeContextualPattern_LiteralsOutsideWindow_NotIncluded()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        // Add string far before the call (outside 10-instruction window)
        for (int i = 0; i < 15; i++)
        {
            instructions.Add(Instruction.Create(OpCodes.Nop));
        }
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/far/away"));
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

    [Fact]
    public void AnalyzeContextualPattern_EmptyStringLiterals_ReturnsNoFindings()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Ldstr, ""));
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "   "));
        instructions.Add(Instruction.Create(OpCodes.Call, methodRef));
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 2, methodSignals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_IncludesCodeSnippet()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        instructions.Add(Instruction.Create(OpCodes.Nop));
        instructions.Add(Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/123/abc"));
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
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var assembly = TestAssemblyBuilder.Create("TestMod").Build();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();
        var ldstrInstr = Instruction.Create(OpCodes.Ldstr, "https://discord.com/api/webhooks/123/abc");
        var callInstr = Instruction.Create(OpCodes.Call, methodRef);
        callInstr.Offset = 42; // Set a specific offset
        instructions.Add(ldstrInstr);
        instructions.Add(callInstr);
        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, methodSignals).ToList();

        findings.Should().HaveCount(1);
        findings[0].Location.Should().Contain(":42");
    }
}
