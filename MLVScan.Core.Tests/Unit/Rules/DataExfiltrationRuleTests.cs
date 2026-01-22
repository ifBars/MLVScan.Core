using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class DataExfiltrationRuleTests
{
    private readonly DataExfiltrationRule _rule = new();

    [Fact]
    public void RuleId_ReturnsDataExfiltrationRule()
    {
        _rule.RuleId.Should().Be("DataExfiltrationRule");
    }

    [Fact]
    public void Severity_ReturnsCritical()
    {
        _rule.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeContextualPattern_DiscordWebhook_ReturnsCriticalFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://discord.com/api/webhooks/123456/abcdef")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Discord webhook");
    }

    [Fact]
    public void AnalyzeContextualPattern_PastebinRaw_WithPostAsync_ReturnsCriticalFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://pastebin.com/raw/abc123")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Data-sending operation");
    }

    [Fact]
    public void AnalyzeContextualPattern_BareIpUrl_WithPostAsync_ReturnsCriticalFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("http://192.168.1.100:8080/endpoint")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_NgrokUrl_WithPostAsync_ReturnsCriticalFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://abc123.ngrok.io/data")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithSuspiciousUrl_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://pastebin.com/raw/abc123")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_GitHubUrl_WithPostAsync_ReturnsLowSeverity()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://api.github.com/repos/user/repo/issues")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("GitHub");
    }

    [Fact]
    public void AnalyzeContextualPattern_ModrinthUrl_WithPostAsync_ReturnsLowSeverity()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://api.modrinth.com/v2/project")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("mod hosting site");
    }

    [Fact]
    public void AnalyzeContextualPattern_CDNUrl_WithPostAsync_ReturnsLowSeverity()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://cdn.jsdelivr.net/npm/package")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("CDN");
    }

    [Fact]
    public void AnalyzeContextualPattern_NoLiteralsNearby_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 0, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NonNetworkCall_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://discord.com/api/webhooks/123/abc")
            .EmitCall("System.Console", "WriteLine")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var consoleWriteLine = MethodReferenceFactory.Create("System.Console", "WriteLine");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(consoleWriteLine, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NullMethod_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("test")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(null!, instructions, 0, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_UnknownOperation_WithSuspiciousUrl_ReturnsMediumSeverity()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://pastebin.com/raw/abc123")
            .EmitCall("System.Net.Http.HttpClient", "SendAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientSendAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "SendAsync");
        var instructions = method.Body.Instructions;

        // SendAsync is not explicitly categorized, so it should trigger the unknown operation case
        var findings = _rule.AnalyzeContextualPattern(httpClientSendAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_WebClient_UploadString_WithDiscord_ReturnsCriticalFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://discord.com/api/webhooks/789/xyz")
            .EmitCall("System.Net.WebClient", "UploadString")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var webClientUploadString = MethodReferenceFactory.Create("System.Net.WebClient", "UploadString");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(webClientUploadString, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Discord webhook");
    }

    [Fact]
    public void AnalyzeContextualPattern_TelegramUrl_WithPostAsync_ReturnsCriticalFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://api.telegram.org/bot123/sendMessage")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeContextualPattern_MultipleUrls_IncludesAllInDescription()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://discord.com/api/webhooks/123/abc")
            .EmitString("https://pastebin.com/raw/xyz")
            .EmitCall("System.Net.Http.HttpClient", "PostAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientPostAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "PostAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientPostAsync, instructions, 2, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("URL(s):");
    }
}
