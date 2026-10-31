using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ProcessStartTargetAttributesTests
{
    [Theory]
    [InlineData("svchost.exe", FindingTargetKind.Executable)]
    [InlineData("C:\\Tools\\updater.exe", FindingTargetKind.Executable)]
    [InlineData("powershell.exe", FindingTargetKind.Script)]
    [InlineData("/bin/bash", FindingTargetKind.Script)]
    [InlineData("UpdateScript.bat", FindingTargetKind.Script)]
    [InlineData("%TEMP%/da.ps1", FindingTargetKind.Script)]
    [InlineData("github.com", FindingTargetKind.Url)]
    [InlineData("https://www.gnu.org/licenses/gpl-3.0.html", FindingTargetKind.Url)]
    [InlineData("steam://rungameid/123", FindingTargetKind.Url)]
    [InlineData("notes.txt", FindingTargetKind.Path)]
    [InlineData("C:\\Games\\Mods", FindingTargetKind.Path)]
    [InlineData("<dynamic via Ldelem_Ref>/iisStupidMenu/Plugins", FindingTargetKind.Path)]
    [InlineData("<dynamic via Ldelem_Ref>/iisStupidMenu/SoundData.txt", FindingTargetKind.Path)]
    [InlineData("<dynamic via Ldelem_Ref>/Scripts/<dynamic via get_Name>.luau", FindingTargetKind.Path)]
    [InlineData("<dynamic via Ldelem_Ref>/payload.exe", FindingTargetKind.Executable)]
    [InlineData("<unknown/non-literal>", FindingTargetKind.Unresolved)]
    [InlineData("<dynamic via Ldelem_Ref>", FindingTargetKind.Unresolved)]
    [InlineData("<ambiguous field> [Possible values: <folder 40>/Downloads/svchost.exe | <null> | <unknown: field search budget exhausted>]", FindingTargetKind.Executable)]
    [InlineData("<ambiguous field> [Possible values: <unknown: field search budget exhausted>]", FindingTargetKind.Unresolved)]
    [InlineData("<ambiguous field> [Possible values: a.exe | run.bat]", FindingTargetKind.Unresolved)]
    public void ClassifyTarget_ReturnsNeutralKind(string target, FindingTargetKind expected)
    {
        ProcessStartRule.ClassifyTarget(target).Should().Be(expected);
    }

    [Fact]
    public void ExtractTargetCandidates_SkipsPlaceholderValues()
    {
        var candidates = ProcessStartRule.ExtractTargetCandidates(
            "<ambiguous field> [Possible values: <folder 40>/Downloads/svchost.exe | <null> | <unknown: field search budget exhausted>]");

        candidates.Should().Equal("<folder 40>/Downloads/svchost.exe");
    }

    [Fact]
    public void CreateFindingAttributes_StripsQuotesAndPlaceholderArguments()
    {
        var attributes = ProcessStartRule.CreateFindingAttributes(
            "\"powershell.exe\"",
            "<unknown/no-arguments>",
            new[] { "WindowStyle=Hidden" },
            "LOLBin with hidden execution");

        attributes.Target.Should().Be("powershell.exe");
        attributes.TargetKind.Should().Be(FindingTargetKind.Script);
        attributes.TargetCandidates.Should().BeEmpty();
        attributes.Arguments.Should().BeNull();
        attributes.Indicators.Should().Equal("WindowStyle=Hidden");
        attributes.RiskReason.Should().Be("LOLBin with hidden execution");
    }
}
