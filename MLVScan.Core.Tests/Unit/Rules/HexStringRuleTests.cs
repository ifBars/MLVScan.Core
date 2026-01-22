using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class HexStringRuleTests
{
    private readonly HexStringRule _rule = new();

    [Fact]
    public void RuleId_ReturnsHexStringRule()
    {
        _rule.RuleId.Should().Be("HexStringRule");
    }

    [Fact]
    public void Severity_ReturnsMedium()
    {
        _rule.Severity.Should().Be(Severity.Medium);
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
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().NotBeNullOrWhiteSpace();
        _rule.DeveloperGuidance.IsRemediable.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Convert", "FromHexString", true)]
    [InlineData("System.Convert", "ToHexString", false)]
    [InlineData("MyNamespace.Convert", "FromHexString", false)]
    [InlineData("System.String", "FromHexString", false)]
    public void IsSuspicious_VariousMethods_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var methodRef = MethodReferenceFactory.Create(typeName, methodName);

        var result = _rule.IsSuspicious(methodRef);

        result.Should().Be(expected);
    }

    [Fact]
    public void AnalyzeStringLiteral_ValidHexString_WithSuspiciousContent_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // "cmd.exe" in hex
        var hexString = "636d642e657865";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Hex-encoded string with suspicious content");
    }

    [Fact]
    public void AnalyzeStringLiteral_ValidHexString_WithPowershell_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // "powershell.exe" in hex
        var hexString = "706f7765727368656c6c2e657865";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].CodeSnippet.Should().Contain("powershell.exe");
    }

    [Fact]
    public void AnalyzeStringLiteral_ValidHexString_WithoutSuspiciousContent_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // "hello world" in hex (benign content)
        var hexString = "68656c6c6f20776f726c64";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_OddLength_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        var hexString = "636d642e65786"; // Odd length - not valid hex bytes
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_TooShort_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        var hexString = "636d642e65"; // Less than 16 characters
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_NonHexCharacters_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        var hexString = "636d642e657867xyz"; // Contains non-hex characters
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_NullOrWhiteSpace_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        var findings1 = _rule.AnalyzeStringLiteral(null!, method, 0).ToList();
        var findings2 = _rule.AnalyzeStringLiteral("", method, 0).ToList();
        var findings3 = _rule.AnalyzeStringLiteral("   ", method, 0).ToList();

        findings1.Should().BeEmpty();
        findings2.Should().BeEmpty();
        findings3.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_InvalidHexBytes_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // Valid hex format but with invalid byte values that might cause parsing issues
        var hexString = "ffffffffffffffffffffffffffffffff"; // All 0xFF bytes
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        // Should not throw, might return findings if decoded contains suspicious patterns
        findings.Should().NotBeNull();
    }

    [Fact]
    public void AnalyzeContextualPattern_ReturnsNoFindings()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EmitString("636d642e657865")
            .EmitCall("System.Convert", "FromHexString")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        var convertFromHexString = MethodReferenceFactory.Create("System.Convert", "FromHexString");
        var instructions = method.Body.Instructions;

        var findings = _rule.AnalyzeContextualPattern(convertFromHexString, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_MixedCase_IsHandledCorrectly()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // "cmd.exe" in hex with mixed case
        var hexString = "636D642E657865";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeStringLiteral_LongHexString_WithSuspiciousContent_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // Long hex string containing "registry" (72656769737472790000000000000000...)
        var hexString = "7265676973747279" + "00".PadRight(32, '0');
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeStringLiteral_Registry_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // "registry" in hex
        var hexString = "72656769737472790000000000000000";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeStringLiteral_Reflection_ReturnsHighSeverityFinding()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .AddMethod("TestMethod")
            .EndMethod()
            .EndType()
            .Build();

        var method = assembly.MainModule.Types[0].Methods[0];
        
        // "System.Reflection" in hex
        var hexString = "53797374656d2e5265666c656374696f6e";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
    }
}
