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
    [InlineData("72_101_108_108_111_32_87_111_114_108_100", true)] // underscore-separated
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
    public void DecodeNumericString_UnderscoreSeparated_DecodesCorrectly()
    {
        // "Hi" = 72_105
        var encoded = "72_105";

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
    public void AnalyzeStringLiteral_UnderscoreEncodedHiddenPowerShellCommand_ReturnsFinding()
    {
        var method = CreateMethodDefinition("RunLiteral");
        var encoded = "47_99_32_112_111_119_101_114_115_104_101_108_108_46_101_120_101_32_45_87_105_110_100_111_119_83_116_121_108_101_32_72_105_100_100_101_110_32_45_67_111_109_109_97_110_100_32_73_110_118_111_107_101_45_87_101_98_82_101_113_117_101_115_116_32_45_79_117_116_70_105_108_101_32_37_84_69_77_80_37_92_116_101_109_112_46_99_109_100";

        var findings = _rule.AnalyzeStringLiteral(encoded, method, 5).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("powershell.exe");
        findings[0].Description.Should().Contain("Invoke-WebRequest");
        findings[0].Description.Should().Contain("%TEMP%\\temp.cmd");
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
    public void AnalyzeStringLiteral_InvisibleUnicodePayloadWithSuspiciousDecodedContent_ReturnsCriticalFinding()
    {
        var method = CreateMethodDefinition("RunLiteral");
        var encoded =
            "\U000E0143\U000E0169\U000E0163\U000E0164\U000E0155\U000E015D\U000E011E\U000E0134\U000E0159\U000E0151\U000E0157\U000E015E\U000E015F\U000E0163\U000E0164\U000E0159\U000E0153\U000E0163\U000E011E\U000E0140\U000E0162\U000E015F\U000E0153\U000E0155\U000E0163\U000E0163";

        var findings = _rule.AnalyzeStringLiteral(encoded, method, 7).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Invisible Unicode payload");
        findings[0].Description.Should().Contain("System.Diagnostics.Process");
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
    public void AnalyzeAssemblyMetadata_WithEncodedAssemblyDescription_ReturnsCriticalFinding()
    {
        var encoded = string.Join("`", new[]
        {
            EncodeAscii("System.Diagnostics.ProcessStartInfo"),
            EncodeAscii("cmd.exe"),
            EncodeAscii("/c powershell -Command \"Invoke-WebRequest -OutFile C:\\ProgramData\\IntelDriver\\windows.cmd\""),
            EncodeAscii("WindowStyle"),
            EncodeAscii("Hidden")
        });
        var assembly = TestUtilities.TestAssemblyBuilder.Create("MetaEncodedDescription")
            .AddAssemblyAttribute("AssemblyDescriptionAttribute", encoded)
            .Build();

        var findings = _rule.AnalyzeAssemblyMetadata(assembly).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Location.Should().Contain("AssemblyDescriptionAttribute");
        findings[0].Description.Should().Contain("ProcessStartInfo");
        findings[0].Description.Should().Contain("cmd.exe");
        findings[0].Description.Should().Contain("Invoke-WebRequest");
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

    [Fact]
    public void AnalyzeAssemblyMetadata_WithInvisibleUnicodePayload_ReturnsCriticalFinding()
    {
        var encoded =
            "\U000E0143\U000E0169\U000E0163\U000E0164\U000E0155\U000E015D\U000E011E\U000E0134\U000E0159\U000E0151\U000E0157\U000E015E\U000E015F\U000E0163\U000E0164\U000E0159\U000E0153\U000E0163\U000E011E\U000E0140\U000E0162\U000E015F\U000E0153\U000E0155\U000E0163\U000E0163";
        var assembly = TestUtilities.TestAssemblyBuilder.Create("MetaEncodedInvisible")
            .AddAssemblyAttribute("AssemblyMetadataAttribute", "k", encoded)
            .Build();

        var findings = _rule.AnalyzeAssemblyMetadata(assembly).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("invisible Unicode payload", Exactly.Once());
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

    private static string EncodeAscii(string value)
    {
        return string.Join("-", value.Select(c => ((int)c).ToString()));
    }
}
