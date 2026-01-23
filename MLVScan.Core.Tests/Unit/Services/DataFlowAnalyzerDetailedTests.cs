using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Core.Tests.TestUtilities;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

/// <summary>
/// Comprehensive tests for DataFlowAnalyzer using synthetic IL assemblies.
/// Tests pattern recognition for all attack patterns.
/// </summary>
public class DataFlowAnalyzerDetailedTests
{
    #region Pattern Recognition Tests

    [Fact]
    public void AnalyzeMethod_WithDownloadAndExecutePattern_DetectsPattern()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        var assembly = TestAssemblyBuilder.Create("MaliciousDownloader")
            .AddType("Malware.Downloader")
                .AddMethod("DownloadAndRun")
                    .AddLocal("System.Byte[]", out int dataVar)
                    .AddLocal("System.String", out int pathVar)
                    // Network download (source)
                    .EmitCall("System.Net.Http.HttpClient", "GetByteArrayAsync", null)
                    .EmitStloc(dataVar)
                    // Base64 decode (transform)
                    .EmitLdloc(dataVar)
                    .EmitCall("System.Convert", "FromBase64String", null)
                    .EmitStloc(dataVar)
                    // Write to file (sink)
                    .EmitString("payload.exe")
                    .EmitStloc(pathVar)
                    .EmitLdloc(pathVar)
                    .EmitLdloc(dataVar)
                    .EmitCall("System.IO.File", "WriteAllBytes")
                    // Execute process (sink)
                    .EmitLdloc(pathVar)
                    .EmitCall("System.Diagnostics.Process", "Start", null)
                    .Emit(OpCodes.Pop)
                    .EndMethod()
                .EndType()
            .Build();

        var method = assembly.MainModule.Types.First(t => t.Name == "Downloader").Methods.First(m => m.Name == "DownloadAndRun");

        // Act
        var chains = analyzer.AnalyzeMethod(method);

        // Assert
        chains.Should().NotBeEmpty();
        chains.Should().Contain(c => c.Pattern == DataFlowPattern.DownloadAndExecute);
        chains.Should().Contain(c => c.Severity == Severity.Critical);
        chains.Should().Contain(c => c.IsSuspicious);
    }

    [Fact]
    public void AnalyzeMethod_WithOnlyLegitimateOperations_HasLowOrNoSuspiciousChains()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        var assembly = TestAssemblyBuilder.Create("TestAssembly")
            .AddType("Test.Type")
                .AddMethod("LegitMethod")
                    .EmitString("Hello World")
                    .EmitCall("System.Console", "WriteLine")
                    .EndMethod()
                .EndType()
            .Build();

        var method = assembly.MainModule.Types.First(t => t.Name == "Type").Methods.First(m => m.Name == "LegitMethod");

        // Act
        var chains = analyzer.AnalyzeMethod(method);

        // Assert
        var suspiciousChains = chains.Where(c => c.IsSuspicious).ToList();
        suspiciousChains.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeMethod_WithSingleSinkNoSource_ReturnsEmpty()
    {
        // Arrange - Only a sink without a source shouldn't form a suspicious chain
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        var assembly = TestAssemblyBuilder.Create("TestAssembly")
            .AddType("Test.Type")
                .AddMethod("JustWriteFile")
                    .EmitString("test.txt")
                    .EmitString("content")
                    .EmitCall("System.Text.Encoding", "GetBytes", null)
                    .EmitCall("System.IO.File", "WriteAllBytes")
                    .EndMethod()
                .EndType()
            .Build();

        var method = assembly.MainModule.Types.First(t => t.Name == "Type").Methods.First(m => m.Name == "JustWriteFile");

        // Act
        var chains = analyzer.AnalyzeMethod(method);

        // Assert
        chains.Should().BeEmpty();
    }

    #endregion

    #region Integration with BuildDataFlowFindings

    [Fact]
    public void BuildDataFlowFindings_WithSuspiciousChains_CreatesFindings()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        var assembly = TestAssemblyBuilder.Create("MaliciousAssembly")
            .AddType("Malware.Type")
                .AddMethod("MaliciousMethod")
                    .AddLocal("System.Byte[]", out int var1)
                    .EmitCall("System.Net.Http.HttpClient", "GetByteArrayAsync", null)
                    .EmitStloc(var1)
                    .EmitLdloc(var1)
                    .EmitCall("System.IO.File", "WriteAllBytes")
                    .EmitLdloc(var1)
                    .EmitCall("System.Diagnostics.Process", "Start", null)
                    .Emit(OpCodes.Pop)
                    .EndMethod()
                .EndType()
            .Build();

        var method = assembly.MainModule.Types.First(t => t.Name == "Type").Methods.First(m => m.Name == "MaliciousMethod");
        analyzer.AnalyzeMethod(method);

        // Act
        var findings = analyzer.BuildDataFlowFindings().ToList();

        // Assert
        findings.Should().NotBeEmpty();
        findings.Should().OnlyContain(f => f.RuleId == "DataFlowAnalysis");
        findings.Should().OnlyContain(f => f.Severity >= Severity.Medium);
    }

    #endregion
}
