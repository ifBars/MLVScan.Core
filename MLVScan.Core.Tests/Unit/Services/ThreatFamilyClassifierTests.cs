using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ThreatFamilyClassifierTests
{
    [Fact]
    public void Classify_WithExactKnownHash_ReturnsExactHashMatch()
    {
        var classifier = new ThreatFamilyClassifier();

        var findings = new List<ScanFinding>();

        var matches = classifier.Classify(findings, "994124671953a3b08d805e5b402719760129a7d19678d85e432dcbac179d0224");

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-resource-shell32-tempcmd-v1");
        matches[0].MatchKind.Should().Be(ThreatMatchKind.ExactSampleHash);
        matches[0].ExactHashMatch.Should().BeTrue();
    }

    [Fact]
    public void Classify_WithPowerShellDownloaderBehavior_ReturnsBehaviorMatch()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Test.Mod.Init:52",
                "Detected Process.Start call which could execute arbitrary programs. Target: \"powershell.exe\". Arguments: iwr ... dl.bat ... Start-Sleep ... Remove-Item [Evasion: UseShellExecute=true, WindowStyle=Hidden]",
                Severity.Critical)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().ContainSingle();
        matches[0].FamilyId.Should().Be("family-powershell-iwr-dlbat-v1");
        matches[0].MatchKind.Should().Be(ThreatMatchKind.BehaviorVariant);
        matches[0].MatchedRules.Should().Contain("ProcessStartRule");
    }

    [Fact]
    public void Classify_WithNoKnownSignals_ReturnsNoMatches()
    {
        var classifier = new ThreatFamilyClassifier();
        var findings = new List<ScanFinding>
        {
            new("Legit.Mod.Start", "Opens explorer for a local folder.", Severity.Low)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var matches = classifier.Classify(findings, null);

        matches.Should().BeEmpty();
    }
}
