using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
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
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().NotBeNullOrWhiteSpace();
        _rule.DeveloperGuidance.IsRemediable.Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithPastebinRaw_ReturnsHighSeverityFinding()
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

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Read-only operation to suspicious endpoint");
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithBareIpUrl_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("http://192.168.1.100:8080/payload")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithNgrokUrl_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://abc123.ngrok.io/download")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithTelegramUrl_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://api.telegram.org/file/bot123/document")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithGitHub_ReturnsLowSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://api.github.com/repos/user/repo/releases/latest")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("GitHub");
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithRawGitHubUserContent_ReturnsLowSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://raw.githubusercontent.com/user/repo/main/version.txt")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("likely legitimate");
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithModrinth_ReturnsLowSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://api.modrinth.com/v2/project/abc/version")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("mod hosting site");
    }

    [Fact]
    public void AnalyzeContextualPattern_GetAsync_WithCDN_ReturnsLowSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://cdn.jsdelivr.net/npm/package@1.0.0/dist/file.js")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("CDN");
    }

    [Fact]
    public void AnalyzeContextualPattern_PostAsync_WithSuspiciousUrl_ReturnsNoFindings()
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

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_WebClient_DownloadString_WithPastebin_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://pastebin.com/raw/xyz789")
            .EmitCall("System.Net.WebClient", "DownloadString")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var webClientDownloadString = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadString");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(webClientDownloadString, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_GetByteArrayAsync_WithHastebin_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://hastebin.com/raw/document123")
            .EmitCall("System.Net.Http.HttpClient", "GetByteArrayAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetByteArrayAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetByteArrayAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetByteArrayAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_NoLiteralsNearby_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 0, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NonNetworkCall_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://pastebin.com/raw/abc")
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
    public void AnalyzeContextualPattern_DownloadFile_WithSuspiciousUrl_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("http://10.0.0.5/malicious.dll")
            .EmitCall("System.Net.WebClient", "DownloadFile")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var webClientDownloadFile = MethodReferenceFactory.Create("System.Net.WebClient", "DownloadFile");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(webClientDownloadFile, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeContextualPattern_MultipleUrls_IncludesAllInDescription()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://pastebin.com/raw/abc")
            .EmitString("http://192.168.1.1/data")
            .EmitCall("System.Net.Http.HttpClient", "GetAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetAsync, instructions, 2, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("URL(s):");
    }

    [Fact]
    public void AnalyzeContextualPattern_GetStringAsync_WithGoogleAPIs_ReturnsLowSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("https://www.googleapis.com/storage/v1/b/bucket/o/object")
            .EmitCall("System.Net.Http.HttpClient", "GetStringAsync")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var httpClientGetStringAsync = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetStringAsync");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(httpClientGetStringAsync, instructions, 1, new MethodSignals()).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Low);
    }
}
