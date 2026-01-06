using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

/// <summary>
/// Integration tests that scan actual compiled mod DLLs from the repository.
/// These tests verify that MLVScan correctly detects MLVBypass while not flagging Behind-Bars.
/// </summary>
public class RealWorldModScanTests
{
    private readonly string _repoRoot;

    public RealWorldModScanTests()
    {
        // Navigate from test assembly location to repo root
        _repoRoot = GetRepositoryRoot();
    }

    /// <summary>
    /// Finds the repository root by looking for the .sln file or specific directories
    /// </summary>
    private static string GetRepositoryRoot()
    {
        var currentDir = Directory.GetCurrentDirectory();
        
        // Walk up the directory tree to find the repo root
        while (currentDir != null)
        {
            // Check for indicators that we're at the repo root
            if (Directory.Exists(Path.Combine(currentDir, "MLVBypass")) &&
                Directory.Exists(Path.Combine(currentDir, "Behind-Bars")) &&
                Directory.Exists(Path.Combine(currentDir, "MLVScan.Core")))
            {
                return currentDir;
            }

            var parent = Directory.GetParent(currentDir);
            currentDir = parent?.FullName;
        }

        throw new InvalidOperationException("Could not find repository root. Tests must be run from within the repository.");
    }

    /// <summary>
    /// Test that MLVBypass.dll (if built) is detected as malicious
    /// </summary>
    [Fact]
    public void Scan_MLVBypassDll_ShouldDetectAsMalicious()
    {
        var mlvBypassPath = Path.Combine(_repoRoot, "MLVBypass", "bin", "Release", "netstandard2.1", "MLVBypass.dll");

        // Skip test if DLL not built
        if (!File.Exists(mlvBypassPath))
        {
            // Try Debug build
            mlvBypassPath = Path.Combine(_repoRoot, "MLVBypass", "bin", "Debug", "netstandard2.1", "MLVBypass.dll");
            if (!File.Exists(mlvBypassPath))
            {
                throw new SkipException("MLVBypass.dll not found. Build the project first: dotnet build MLVBypass/MLVBypass.csproj");
            }
        }

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        var findings = scanner.Scan(mlvBypassPath).ToList();

        // MLVBypass MUST be detected
        findings.Should().NotBeEmpty("MLVBypass uses reflective shell execution and must be detected");
        
        // Should have high-severity findings
        findings.Should().Contain(f => f.Severity >= Severity.High,
            "MLVBypass contains critical shell execution patterns");
        
        // Should mention reflection, shell, or COM-based execution
        var hasRelevantFinding = findings.Any(f => 
            f.Description.Contains("reflection", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("Shell", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("InvokeMember", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
            (f.RuleId != null && f.RuleId.Contains("Shell", StringComparison.OrdinalIgnoreCase)) ||
            (f.RuleId != null && f.RuleId.Contains("Reflection", StringComparison.OrdinalIgnoreCase)));
        
        hasRelevantFinding.Should().BeTrue("Should specifically identify the reflective shell execution technique");
    }

    /// <summary>
    /// Test that Behind-Bars.dll (if built) is NOT flagged as malicious
    /// Behind-Bars uses extensive reflection for Il2Cpp interop, which is legitimate
    /// </summary>
    [Fact]
    public void Scan_BehindBarsDll_ShouldNotDetectAsMalicious()
    {
        // Try Mono build first (most common for this project)
        var behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Debug Mono", "netstandard2.1", "Behind_Bars-Mono.dll");

        // Skip test if DLL not built
        if (!File.Exists(behindBarsPath))
        {
            // Try Release Mono build
            behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Release Mono", "netstandard2.1", "Behind_Bars-Mono.dll");
            if (!File.Exists(behindBarsPath))
            {
                // Try Il2Cpp builds
                behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Debug", "netstandard2.1", "Behind_Bars.dll");
                if (!File.Exists(behindBarsPath))
                {
                    behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Release", "netstandard2.1", "Behind_Bars.dll");
                    if (!File.Exists(behindBarsPath))
                    {
                        throw new SkipException("Behind-Bars.dll not found. Build the project in Unity or with proper game references.");
                    }
                }
            }
        }

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        var findings = scanner.Scan(behindBarsPath).ToList();

        // Behind-Bars should have NO high-severity findings related to reflection
        var reflectionFindings = findings.Where(f =>
            (f.Description.Contains("reflection", StringComparison.OrdinalIgnoreCase) ||
             (f.RuleId != null && f.RuleId.Contains("Reflection", StringComparison.OrdinalIgnoreCase))) &&
            f.Severity >= Severity.High).ToList();

        reflectionFindings.Should().BeEmpty(
            "Behind-Bars uses reflection extensively for Il2Cpp interop but has no malicious patterns. " +
            "It should not trigger reflection-based detection.");

        // It's acceptable to have low-severity informational findings, but not high/critical
        var criticalFindings = findings.Where(f => f.Severity >= Severity.Critical).ToList();
        criticalFindings.Should().BeEmpty(
            "Behind-Bars is a legitimate mod and should have no critical findings");
    }

    /// <summary>
    /// Test MLVBypass detection with developer mode enabled (via MLVScan.DevCLI simulation)
    /// </summary>
    [Fact]
    public void Scan_MLVBypassDllWithDevMode_ShouldProvideGuidance()
    {
        var mlvBypassPath = Path.Combine(_repoRoot, "MLVBypass", "bin", "Release", "netstandard2.1", "MLVBypass.dll");

        if (!File.Exists(mlvBypassPath))
        {
            mlvBypassPath = Path.Combine(_repoRoot, "MLVBypass", "bin", "Debug", "netstandard2.1", "MLVBypass.dll");
            if (!File.Exists(mlvBypassPath))
            {
                throw new SkipException("MLVBypass.dll not found. Build the project first.");
            }
        }

        var config = new ScanConfig { DeveloperMode = true };
        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules, config);

        var findings = scanner.Scan(mlvBypassPath).ToList();

        findings.Should().NotBeEmpty();
        
        // In developer mode, findings may include guidance
        // This test validates the integration with DevCLI-style usage
        findings.Should().Contain(f => f.Severity >= Severity.High);
    }

    /// <summary>
    /// Test that Behind-Bars with all its reflection doesn't trigger multi-signal detection
    /// </summary>
    [Fact]
    public void Scan_BehindBarsExtensiveReflection_NoMultiSignalFalsePositive()
    {
        // Try Mono build first
        var behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Debug Mono", "netstandard2.1", "Behind_Bars-Mono.dll");

        if (!File.Exists(behindBarsPath))
        {
            behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Release Mono", "netstandard2.1", "Behind_Bars-Mono.dll");
            if (!File.Exists(behindBarsPath))
            {
                behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Debug", "netstandard2.1", "Behind_Bars.dll");
                if (!File.Exists(behindBarsPath))
                {
                    behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Release", "netstandard2.1", "Behind_Bars.dll");
                    if (!File.Exists(behindBarsPath))
                    {
                        throw new SkipException("Behind-Bars.dll not found. Build the project first.");
                    }
                }
            }
        }

        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules, config);

        var findings = scanner.Scan(behindBarsPath).ToList();

        // Even with multi-signal detection, Behind-Bars shouldn't be flagged as malicious
        var highSeverityFindings = findings.Where(f => f.Severity >= Severity.High).ToList();
        
        // Allow for possible low-severity informational findings, but not high/critical reflection issues
        var maliciousReflectionFindings = highSeverityFindings.Where(f =>
            f.Description.Contains("reflection", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("invoke", StringComparison.OrdinalIgnoreCase) && 
            f.RuleId?.Contains("Reflection", StringComparison.OrdinalIgnoreCase) == true).ToList();

        maliciousReflectionFindings.Should().BeEmpty(
            "Behind-Bars reflection usage should not trigger multi-signal detection for malicious patterns");
    }

    /// <summary>
    /// Test scanning InventoryProcessor.cs specifically to ensure its reflection patterns are safe
    /// </summary>
    [Fact]
    public void Scan_BehindBarsInventoryProcessor_SpecificReflectionPatternsShouldPass()
    {
        // Try Mono build first
        var behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Debug Mono", "netstandard2.1", "Behind_Bars-Mono.dll");

        if (!File.Exists(behindBarsPath))
        {
            behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Release Mono", "netstandard2.1", "Behind_Bars-Mono.dll");
            if (!File.Exists(behindBarsPath))
            {
                behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Debug", "netstandard2.1", "Behind_Bars.dll");
                if (!File.Exists(behindBarsPath))
                {
                    behindBarsPath = Path.Combine(_repoRoot, "Behind-Bars", "bin", "Release", "netstandard2.1", "Behind_Bars.dll");
                    if (!File.Exists(behindBarsPath))
                    {
                        throw new SkipException("Behind-Bars.dll not found. Build the project first.");
                    }
                }
            }
        }

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        var findings = scanner.Scan(behindBarsPath).ToList();

        // Check for findings in InventoryProcessor specifically
        var inventoryProcessorFindings = findings.Where(f =>
            f.Location.Contains("InventoryProcessor", StringComparison.OrdinalIgnoreCase)).ToList();

        // InventoryProcessor uses GetMethod, GetProperty, GetField extensively
        // These should NOT be flagged as malicious
        var maliciousInventoryFindings = inventoryProcessorFindings.Where(f =>
            f.Severity >= Severity.High &&
            (f.Description.Contains("reflection", StringComparison.OrdinalIgnoreCase) ||
             f.RuleId?.Contains("Reflection", StringComparison.OrdinalIgnoreCase) == true)).ToList();

        maliciousInventoryFindings.Should().BeEmpty(
            "InventoryProcessor's Il2Cpp reflection patterns (GetMethod, GetProperty, GetField, Invoke) " +
            "are legitimate and should not be flagged as malicious");
    }
}

/// <summary>
/// Custom exception to skip tests when dependencies aren't available
/// </summary>
public class SkipException : Exception
{
    public SkipException(string message) : base(message) { }
}
