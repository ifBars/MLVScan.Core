using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models;

public class ScanFindingTests
{
    [Fact]
    public void Constructor_SetsPropertiesCorrectly()
    {
        var finding = new ScanFinding(
            "MyNamespace.MyClass.MyMethod:42",
            "Detected suspicious pattern",
            Severity.High,
            "call System.Diagnostics.Process::Start");

        finding.Location.Should().Be("MyNamespace.MyClass.MyMethod:42");
        finding.Description.Should().Be("Detected suspicious pattern");
        finding.Severity.Should().Be(Severity.High);
        finding.CodeSnippet.Should().Be("call System.Diagnostics.Process::Start");
    }

    [Fact]
    public void Constructor_DefaultSeverity_IsLow()
    {
        var finding = new ScanFinding("Location", "Description");

        finding.Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void Constructor_DefaultCodeSnippet_IsNull()
    {
        var finding = new ScanFinding("Location", "Description", Severity.Medium);

        finding.CodeSnippet.Should().BeNull();
    }

    [Fact]
    public void RuleId_DefaultsToNull()
    {
        var finding = new ScanFinding("Location", "Description");

        finding.RuleId.Should().BeNull();
    }

    [Fact]
    public void DeveloperGuidance_DefaultsToNull()
    {
        var finding = new ScanFinding("Location", "Description");

        finding.DeveloperGuidance.Should().BeNull();
    }

    [Fact]
    public void ToString_WithoutSnippet_FormatsCorrectly()
    {
        var finding = new ScanFinding(
            "MyClass.Method",
            "Test description",
            Severity.Medium);

        var result = finding.ToString();

        result.Should().Be("[Medium] Test description at MyClass.Method");
    }

    [Fact]
    public void ToString_WithSnippet_IncludesSnippet()
    {
        var finding = new ScanFinding(
            "MyClass.Method",
            "Test description",
            Severity.Critical,
            "call SomeMethod");

        var result = finding.ToString();

        result.Should().Contain("[Critical]");
        result.Should().Contain("Test description");
        result.Should().Contain("MyClass.Method");
        result.Should().Contain("Snippet: call SomeMethod");
    }

    [Fact]
    public void Properties_AreMutable()
    {
        var finding = new ScanFinding("Original", "Original description");

        finding.Location = "Updated";
        finding.Description = "Updated description";
        finding.Severity = Severity.Critical;
        finding.CodeSnippet = "Updated snippet";
        finding.RuleId = "TestRule";
        finding.DeveloperGuidance = new DeveloperGuidance("Fix it", null, null, true);

        finding.Location.Should().Be("Updated");
        finding.Description.Should().Be("Updated description");
        finding.Severity.Should().Be(Severity.Critical);
        finding.CodeSnippet.Should().Be("Updated snippet");
        finding.RuleId.Should().Be("TestRule");
        finding.DeveloperGuidance.Should().NotBeNull();
    }
}
