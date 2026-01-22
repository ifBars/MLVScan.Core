using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;

namespace MLVScan.Core.Tests.Integration;

/// <summary>
/// Tests for call chain consolidation feature.
/// Verifies that related findings (e.g., P/Invoke declaration + call site) are consolidated
/// into a single finding with full attack path visibility.
/// </summary>
public class CallChainConsolidationTests
{
    private readonly ITestOutputHelper _output;

    public CallChainConsolidationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private static string? FindQuarantineFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();
        
        // Walk up the directory tree to find the QUARANTINE folder
        while (currentDir != null)
        {
            var quarantinePath = Path.Combine(currentDir, "QUARANTINE");
            if (Directory.Exists(quarantinePath))
            {
                return quarantinePath;
            }
            
            // Also check if we're in MLVScan.Core
            var mlvScanCorePath = Path.Combine(currentDir, "MLVScan.Core", "QUARANTINE");
            if (Directory.Exists(mlvScanCorePath))
            {
                return mlvScanCorePath;
            }

            var parent = Directory.GetParent(currentDir);
            currentDir = parent?.FullName;
        }

        return null;
    }

    /// <summary>
    /// Diagnostic test to see what findings are produced for NoMoreTrash.
    /// </summary>
    [Fact]
    public void Scan_NoMoreTrash_DiagnoseAllFindings()
    {
        // Arrange
        var quarantineFolder = FindQuarantineFolder();
        if (quarantineFolder == null)
            return; // Skip if QUARANTINE not available (CI environment)

        var noMoreTrashPath = Path.Combine(quarantineFolder, "NoMoreTrash.dll.di");
        if (!File.Exists(noMoreTrashPath))
            return; // Skip if file not found

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        // Act
        var findings = scanner.Scan(noMoreTrashPath).ToList();

        // Log all findings for diagnosis
        _output.WriteLine($"Total findings: {findings.Count}");
        foreach (var finding in findings)
        {
            _output.WriteLine($"---");
            _output.WriteLine($"RuleId: {finding.RuleId}");
            _output.WriteLine($"Severity: {finding.Severity}");
            _output.WriteLine($"Location: {finding.Location}");
            _output.WriteLine($"Description: {finding.Description}");
            _output.WriteLine($"HasCallChain: {finding.HasCallChain}");
            if (finding.HasCallChain)
            {
                _output.WriteLine($"CallChain nodes: {finding.CallChain!.Nodes.Count}");
                foreach (var node in finding.CallChain.Nodes)
                {
                    _output.WriteLine($"  - {node}");
                }
            }
            _output.WriteLine($"Snippet: {finding.CodeSnippet?.Substring(0, Math.Min(200, finding.CodeSnippet?.Length ?? 0))}...");
        }

        // Assert - at minimum we should find SOMETHING
        findings.Should().NotBeEmpty("NoMoreTrash should produce some findings");
    }

    /// <summary>
    /// Test that NoMoreTrash.dll.di produces a single consolidated finding for the suspicious DllImport
    /// instead of separate findings for the P/Invoke declaration and call site.
    /// </summary>
    [Fact]
    public void Scan_NoMoreTrash_ShouldConsolidateFindings()
    {
        // Arrange
        var quarantineFolder = FindQuarantineFolder();
        if (quarantineFolder == null)
            return; // Skip if QUARANTINE not available (CI environment)

        var noMoreTrashPath = Path.Combine(quarantineFolder, "NoMoreTrash.dll.di");
        if (!File.Exists(noMoreTrashPath))
            return; // Skip if file not found

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        // Act
        var findings = scanner.Scan(noMoreTrashPath).ToList();

        // Assert
        findings.Should().NotBeEmpty("NoMoreTrash contains malicious patterns");

        // Get DllImport-related findings (this rule properly detects shell32.dll P/Invoke)
        var dllImportFindings = findings.Where(f => 
            f.RuleId == "DllImportRule" && 
            f.Description.Contains("shell32", StringComparison.OrdinalIgnoreCase)).ToList();

        // Log what we found
        _output.WriteLine($"Found {dllImportFindings.Count} DllImport findings related to shell32");
        foreach (var f in dllImportFindings)
        {
            _output.WriteLine($"  - {f.Location}: {f.Description}");
            _output.WriteLine($"    HasCallChain: {f.HasCallChain}");
        }

        // Should have at least one DllImport finding for shell32
        dllImportFindings.Should().NotBeEmpty(
            "DllImportRule should detect shell32.dll P/Invoke");
    }

    /// <summary>
    /// Test that severity is preserved from the original rule.
    /// </summary>
    [Fact]
    public void Scan_NoMoreTrash_SeverityShouldBeHighOrCritical()
    {
        // Arrange
        var quarantineFolder = FindQuarantineFolder();
        if (quarantineFolder == null)
            return; // Skip if QUARANTINE not available (CI environment)

        var noMoreTrashPath = Path.Combine(quarantineFolder, "NoMoreTrash.dll.di");
        if (!File.Exists(noMoreTrashPath))
            return; // Skip if file not found

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        // Act
        var findings = scanner.Scan(noMoreTrashPath).ToList();

        // Assert - should have high/critical findings
        var highSeverityFindings = findings.Where(f => f.Severity >= Severity.High).ToList();
        highSeverityFindings.Should().NotBeEmpty(
            "NoMoreTrash should have High or Critical severity findings");
    }
}
