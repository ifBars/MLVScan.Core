using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;

namespace MLVScan.Core.Tests.Integration;

public class SyntheticCoverageTests
{
    private readonly ITestOutputHelper _output;
    public SyntheticCoverageTests(ITestOutputHelper output) => _output = output;
    [SkippableTheory]
    [InlineData("Base64CommandExecution", "Suspicious")]
    [InlineData("CharArrayCommandSplit", "Suspicious")]
    [InlineData("COMShellInvoke", "Suspicious")]
    [InlineData("CoordinatedRemoteDelivery", "Suspicious")]
    [InlineData("DynamicEmitAssembly", "Suspicious")]
    [InlineData("EmbeddedResourceStageLoad", "Suspicious")]
    [InlineData("HexCommandExecution", "Suspicious")]
    [InlineData("HiddenWindowCmdLauncher", "Suspicious")]
    [InlineData("MTEST", "Suspicious")]
    [InlineData("HttpWebRequestExfil", "Clean")]
    [InlineData("PInvokeWinExec", "Suspicious")]
    [InlineData("ReflectionProcessInvoke", "Suspicious")]
    [InlineData("RegistryRunKeyPersistence", "Suspicious")]
    [InlineData("ReversedStringCommand", "Suspicious")]
    [InlineData("StartupFolderPersistence", "Clean")]
    [InlineData("UnityWebRequestPostExfil", "Clean")]
    [InlineData("WmiProcessLauncher", "Suspicious")]
    [InlineData("XorBlobAssemblyLoad", "Suspicious")]
    [InlineData("ZipArchiveStageDrop", "Clean")]
    public void Scan_LocalProbe_PreservesEvidenceAndExpectedDisposition(string sample, string expectedDisposition)
    {
        string? path = null;
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
        {
            string relativePath = sample == "MTEST" ? "MTEST.dll" : Path.Combine(sample, sample + ".dll");
            string candidate = Path.Combine(directory.FullName, "SYNTHETIC_SAMPLES", relativePath.Replace('\\', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
            {
                path = candidate;
                break;
            }
        }

        Skip.If(path == null, "Optional local synthetic corpus is not available.");
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig { DeveloperMode = true });
        var findings = scanner.Scan(path!).ToList();
        foreach (var finding in findings)
        {
            _output.WriteLine($"{finding.RuleId} [{finding.Severity}] {finding.Location}: {finding.Description}");
        }
        scanner.Scan(path!).Select(finding => (finding.RuleId, finding.Location, finding.Severity, finding.Description))
            .Should().Equal(findings.Select(finding => (finding.RuleId, finding.Location, finding.Severity, finding.Description)));
        var dto = ScanResultMapper.ToDto(findings, sample + ".dll", File.ReadAllBytes(path!), true);

        dto.Findings.Should().NotBeEmpty("every probe must expose its targeted behavior");
        dto.Disposition!.Classification.Should().Be(expectedDisposition);
        dto.ThreatFamilies.Should().BeNullOrEmpty("synthetic techniques are not confirmed malware families");
        if (expectedDisposition == "Suspicious")
        {
            dto.Disposition.BlockingRecommended.Should().BeTrue();
            dto.Findings.Should().Contain(finding => finding.Visibility == "Default");
        }
    }
}
