using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EnvironmentPathRuleSimpleTests
{
    private readonly EnvironmentPathRule _rule = new();

    [Fact]
    public void RuleId_ReturnsEnvironmentPathRule()
    {
        _rule.RuleId.Should().Be("EnvironmentPathRule");
    }

    [Fact]
    public void Severity_ReturnsLow()
    {
        _rule.Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Theory]
    [InlineData(26, "ApplicationData", true)]
    [InlineData(7, "Startup", true)]
    [InlineData(28, "LocalApplicationData", true)]
    [InlineData(35, "CommonApplicationData", true)]
    [InlineData(0, "Folder(0)", false)]
    [InlineData(99, "Folder(99)", false)]
    public void IsSensitiveFolder_VariousValues_ReturnsExpected(int folderValue, string expectedName, bool expectedSensitive)
    {
        var isSensitive = EnvironmentPathRule.IsSensitiveFolder(folderValue);
        var folderName = EnvironmentPathRule.GetFolderName(folderValue);

        isSensitive.Should().Be(expectedSensitive);
        folderName.Should().Be(expectedName);
    }
}