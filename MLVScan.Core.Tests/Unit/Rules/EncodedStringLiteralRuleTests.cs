using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EncodedStringLiteralRuleTests
{
    private readonly EncodedStringLiteralRule _rule = new();

    [Fact]
    public void RuleId_ReturnsEncodedStringLiteralRule()
    {
        _rule.RuleId.Should().Be("EncodedStringLiteralRule");
    }

    [Fact]
    public void Severity_ReturnsHigh()
    {
        _rule.Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        // This rule doesn't check methods directly - it analyzes string literals
        var methodRef = TestUtilities.MethodReferenceFactory.Create("System.String", "Concat");
        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    #region IsEncodedString Tests

    [Theory]
    [InlineData("72-101-108-108-111-32-87-111-114-108-100", true)] // "Hello World" dash-separated (11 segments)
    [InlineData("80-111-119-101-114-115-104-101-108-108", false)] // "powershell" only has 10 segments - too short
    [InlineData("72.101.108.108.111.32.87.111.114.108.100", true)] // dot-separated
    [InlineData("72`101`108`108`111`32`87`111`114`108`100", true)] // backtick-separated
    [InlineData("Hello World", false)] // plain text
    [InlineData("72-101-108", false)] // too short (less than 10 segments)
    [InlineData("abc-def-ghi-jkl-mno-pqr-stu-vwx-yz1-234-567", false)] // non-numeric
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsEncodedString_VariousInputs_ReturnsExpected(string? input, bool expected)
    {
        EncodedStringLiteralRule.IsEncodedString(input!).Should().Be(expected);
    }

    #endregion

    #region DecodeNumericString Tests

    [Fact]
    public void DecodeNumericString_DashSeparated_DecodesCorrectly()
    {
        // "Hello" = 72-101-108-108-111
        var encoded = "72-101-108-108-111";

        var result = EncodedStringLiteralRule.DecodeNumericString(encoded);

        result.Should().Be("Hello");
    }

    [Fact]
    public void DecodeNumericString_DotSeparated_DecodesCorrectly()
    {
        // "Hi" = 72.105
        var encoded = "72.105";

        var result = EncodedStringLiteralRule.DecodeNumericString(encoded);

        result.Should().Be("Hi");
    }

    [Fact]
    public void DecodeNumericString_BacktickSeparated_DecodesCorrectly()
    {
        // "Hi" = 72`105
        var encoded = "72`105";

        var result = EncodedStringLiteralRule.DecodeNumericString(encoded);

        result.Should().Be("Hi");
    }

    [Fact]
    public void DecodeNumericString_InvalidCharCode_ReturnsNull()
    {
        // 999 is not a valid ASCII code (> 127)
        var encoded = "72-999-108";

        var result = EncodedStringLiteralRule.DecodeNumericString(encoded);

        result.Should().BeNull();
    }

    [Fact]
    public void DecodeNumericString_NonNumericSegment_ReturnsNull()
    {
        var encoded = "72-abc-108";

        var result = EncodedStringLiteralRule.DecodeNumericString(encoded);

        result.Should().BeNull();
    }

    #endregion

    #region ContainsSuspiciousContent Tests

    [Theory]
    [InlineData("Process", true)]
    [InlineData("ProcessStartInfo", true)]
    [InlineData("powershell", true)]
    [InlineData("cmd.exe", true)]
    [InlineData("Invoke-WebRequest", true)]
    [InlineData("FromBase64String", true)]
    [InlineData("Assembly.Load", true)]
    [InlineData("Registry", true)]
    [InlineData("RunOnce", true)]
    [InlineData("CurrentVersion\\Run", true)]
    [InlineData("Hello World", false)]
    [InlineData("MyMod.DoSomething", false)]
    [InlineData("", false)]
    public void ContainsSuspiciousContent_VariousInputs_ReturnsExpected(string input, bool expected)
    {
        EncodedStringLiteralRule.ContainsSuspiciousContent(input).Should().Be(expected);
    }

    [Fact]
    public void ContainsSuspiciousContent_CaseInsensitive()
    {
        EncodedStringLiteralRule.ContainsSuspiciousContent("POWERSHELL").Should().BeTrue();
        EncodedStringLiteralRule.ContainsSuspiciousContent("PowerShell").Should().BeTrue();
        EncodedStringLiteralRule.ContainsSuspiciousContent("powershell").Should().BeTrue();
    }

    [Fact]
    public void AnalyzeStringLiteral_EncodedWithSuspiciousDecodedContent_ReturnsFinding()
    {
        var method = CreateMethodDefinition("RunLiteral");
        var encoded = "112-111-119-101-114-115-104-101-108-108-46-101-120-101"; // powershell.exe

        var findings = _rule.AnalyzeStringLiteral(encoded, method, 3).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Decoded: powershell.exe");
    }

    [Fact]
    public void AnalyzeStringLiteral_EncodedWithoutSuspiciousDecodedContent_ReturnsEmpty()
    {
        var method = CreateMethodDefinition("RunLiteral");
        var encoded = "72-101-108-108-111-32-87-111-114-108-100"; // Hello World

        var findings = _rule.AnalyzeStringLiteral(encoded, method, 1).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeAssemblyMetadata_WithEncodedAttributeValue_ReturnsCriticalFinding()
    {
        var assembly = TestUtilities.TestAssemblyBuilder.Create("MetaEncoded")
            .AddAssemblyAttribute("AssemblyMetadataAttribute", "k", "112-111-119-101-114-115-104-101-108-108-120")
            .Build();

        var findings = _rule.AnalyzeAssemblyMetadata(assembly).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Hidden payload in assembly metadata");
    }

    [Fact]
    public void AnalyzeAssemblyMetadata_WithDotSeparatedFourDigitEncoding_UsesFallbackBranch()
    {
        var encoded = "0112.0111.0119.0101.0114.0115.0104.0101.0108.0108"; // powershell
        var assembly = TestUtilities.TestAssemblyBuilder.Create("MetaEncodedDot")
            .AddAssemblyAttribute("AssemblyMetadataAttribute", "k", encoded)
            .Build();

        var findings = _rule.AnalyzeAssemblyMetadata(assembly).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    #endregion

    private static MethodDefinition CreateMethodDefinition(string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("EncodedLiteralRuleTest", new Version(1, 0, 0, 0)), "EncodedLiteralRuleTest", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "LiteralType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        return method;
    }
}
