using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
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
    public void DeveloperGuidance_IsNotNull()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().Contain("embedded resource");
    }

    [Fact]
    public void IsSuspicious_ConvertFromHexString_ReturnsTrue()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromHexString");
        
        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_OtherMethods_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.String", "Concat");
        
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeStringLiteral_NullOrWhiteSpace_ReturnsEmpty()
    {
        var method = CreateTestMethod();
        
        var findings1 = _rule.AnalyzeStringLiteral(null!, method, 0);
        var findings2 = _rule.AnalyzeStringLiteral("", method, 0);
        var findings3 = _rule.AnalyzeStringLiteral("   ", method, 0);
        
        findings1.Should().BeEmpty();
        findings2.Should().BeEmpty();
        findings3.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_TooShort_ReturnsEmpty()
    {
        var method = CreateTestMethod();
        
        // Less than 16 characters
        var findings = _rule.AnalyzeStringLiteral("48656C6C6F", method, 0);
        
        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_OddLength_ReturnsEmpty()
    {
        var method = CreateTestMethod();
        
        // Odd length hex string (can't decode to bytes cleanly)
        var findings = _rule.AnalyzeStringLiteral("48656C6C6F576F726C6421", method, 0);
        
        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_NotHex_ReturnsEmpty()
    {
        var method = CreateTestMethod();
        
        // Not hex (contains non-hex characters)
        var findings = _rule.AnalyzeStringLiteral("48656C6C6F576F72G64212", method, 0);
        
        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_ValidHexWithoutSuspiciousContent_ReturnsEmpty()
    {
        var method = CreateTestMethod();
        
        // Valid hex but not suspicious content (decodes to "HelloWorldHello!")
        var hexString = "48656C6C6F576F726C6448656C6C6F21";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0);
        
        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_ValidHexWithSuspiciousContent_ReturnsFindings()
    {
        var method = CreateTestMethod();
        
        // Hex-encoded "ProcessStartInfo" (suspicious keyword)
        // "Process" = 50 72 6F 63 65 73 73 20 53 74 61 72 74 49 6E 66 6F
        var hexString = "50726F6365737353746172";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Hex-encoded string with suspicious content");
        findings[0].Description.Should().Contain("Decoded:");
        findings[0].CodeSnippet.Should().Contain("Encoded:");
        findings[0].CodeSnippet.Should().Contain("Decoded:");
    }

    [Fact]
    public void AnalyzeStringLiteral_EncodedPowershell_DetectsAsSuspicious()
    {
        var method = CreateTestMethod();
        
        // Hex-encoded "powershell.exe" (70 6F 77 65 72 73 68 65 6C 6C 2E 65 78 65)
        var hexString = "706F7765727368656C6C2E657865";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("powershell");
    }

    [Fact]
    public void AnalyzeStringLiteral_EncodedCmdExe_DetectsAsSuspicious()
    {
        var method = CreateTestMethod();
        
        // Hex-encoded "cmd.exe" (63 6D 64 2E 65 78 65)
        var hexString = "636D642E6578652020202020"; // Added padding to reach 16 chars
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("cmd.exe");
    }

    [Fact]
    public void AnalyzeStringLiteral_LowercaseHex_WorksCorrectly()
    {
        var method = CreateTestMethod();
        
        // Lowercase hex-encoded "Process"
        var hexString = "50726f63657373202020"; // "Process" + padding
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        findings.Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeStringLiteral_UppercaseHex_WorksCorrectly()
    {
        var method = CreateTestMethod();
        
        // Uppercase hex-encoded "Process"
        var hexString = "50726F63657373202020"; // "Process" + padding
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        findings.Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeStringLiteral_MixedCaseHex_WorksCorrectly()
    {
        var method = CreateTestMethod();
        
        // Mixed case hex-encoded "Process"
        var hexString = "50726f43657373202020"; // "ProCess" + padding
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        findings.Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeStringLiteral_InvalidHexValue_HandlesGracefully()
    {
        var method = CreateTestMethod();
        
        // Valid hex format but might have decoding issues
        var hexString = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"; // All FF bytes
        
        var act = () => _rule.AnalyzeStringLiteral(hexString, method, 0).ToList();
        
        act.Should().NotThrow();
    }

    [Fact]
    public void AnalyzeContextualPattern_ReturnsEmpty()
    {
        var methodRef = MethodReferenceFactory.Create("System.String", "Concat");
        var instructions = new Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction>();
        var signals = new MethodSignals();
        
        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 0, signals);
        
        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeStringLiteral_SetsFindingLocation_Correctly()
    {
        var method = CreateTestMethod();
        
        // Hex-encoded "Process"
        var hexString = "50726F63657373202020";
        
        var findings = _rule.AnalyzeStringLiteral(hexString, method, 42).ToList();
        
        findings.Should().HaveCount(1);
        findings[0].Location.Should().Contain("TestMethod");
        findings[0].Location.Should().Contain("42");
    }

    private MethodDefinition CreateTestMethod()
    {
        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();
        var type = new TypeDefinition("TestNamespace", "TestType", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);
        
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, assembly.MainModule.TypeSystem.Void);
        type.Methods.Add(method);
        
        return method;
    }
}
