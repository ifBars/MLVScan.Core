using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
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

    #endregion
}
