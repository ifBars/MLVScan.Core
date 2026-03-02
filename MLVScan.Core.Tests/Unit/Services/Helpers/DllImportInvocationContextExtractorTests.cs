using System.Reflection;
using FluentAssertions;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.Helpers;

/// <summary>
/// Unit tests for DllImportInvocationContextExtractor helper methods.
/// Note: Full integration tests for TryBuildContext require actual assembly scanning
/// since MethodReference.Resolve() requires properly linked assembly definitions.
/// These tests focus on the helper methods and public API surface.
/// </summary>
public class DllImportInvocationContextExtractorTests
{
    private static readonly Assembly CoreAssembly = typeof(MLVScan.Models.ScanFinding).Assembly;
    private static readonly Type ExtractorType = CoreAssembly.GetType("MLVScan.Services.Helpers.DllImportInvocationContextExtractor")!;

    private static readonly MethodInfo NormalizeDisplayValueMethod =
        ExtractorType.GetMethod("NormalizeDisplayValue", BindingFlags.Static | BindingFlags.NonPublic)!;

    #region NormalizeDisplayValue Tests

    [Fact]
    public void NormalizeDisplayValue_WithNull_ReturnsUnknownMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "" });

        result.Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void NormalizeDisplayValue_WithEmptyString_ReturnsUnknownMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "   " });

        result.Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void NormalizeDisplayValue_WithNormalString_ReturnsQuotedValue()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "test.exe" });

        result.Should().Be("\"test.exe\"");
    }

    [Fact]
    public void NormalizeDisplayValue_WithLongString_ReturnsTruncatedValue()
    {
        var longString = new string('a', 200);

        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { longString });

        ((string)result!).Length.Should().BeLessThan(160);
        ((string)result).Should().EndWith("\"");
    }

    [Fact]
    public void NormalizeDisplayValue_WithNewlines_ReturnsNormalizedString()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "line1\r\nline2\nline3" });

        ((string)result!).Should().NotContain("\r");
        ((string)result).Should().NotContain("\n");
    }

    [Fact]
    public void NormalizeDisplayValue_WithInteger_ReturnsIntegerString()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "42" });

        result.Should().Be("42");
    }

    [Fact]
    public void NormalizeDisplayValue_WithAlreadyQuotedString_ReturnsQuotedString()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "\"already quoted\"" });

        result.Should().Be("\"already quoted\"");
    }

    [Fact]
    public void NormalizeDisplayValue_WithUnknownMarker_ReturnsMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "<unknown>" });

        result.Should().Be("<unknown>");
    }

    [Fact]
    public void NormalizeDisplayValue_WithLocalMarker_ReturnsMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "<local V_0>" });

        result.Should().Be("<local V_0>");
    }

    #endregion

    #region IsNativeExecutionPInvoke - Direct Testing

    /// <summary>
    /// These tests use the DllImportRule directly to test IsNativeExecutionEntryPoint
    /// since IsNativeExecutionPInvoke in DllImportInvocationContextExtractor
    /// delegates to DllImportRule.IsNativeExecutionEntryPoint.
    /// </summary>
    [Fact]
    public void IsNativeExecutionEntryPoint_WithShellExecute_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecute");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithCreateProcess_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("createprocess");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithWinExec_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("winexec");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithShellExecuteEx_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecuteex");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithNonExecutionFunction_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("getlasterror");

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithVirtualAlloc_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("virtualalloc");

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithNull_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint(null!);

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithEmptyString_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("");

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithCaseInsensitive_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("SHELLEXECUTE");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithPartialMatch_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecutea");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithSubstring_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecuteexw");

        result.Should().BeTrue();
    }

    #endregion
}
