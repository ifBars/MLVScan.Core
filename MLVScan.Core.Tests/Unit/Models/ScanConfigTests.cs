using FluentAssertions;
using MLVScan.Models;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models;

public class ScanConfigTests
{
    [Fact]
    public void DefaultConfig_HasExpectedDefaults()
    {
        var config = new ScanConfig();

        config.EnableAutoScan.Should().BeTrue();
        config.EnableAutoDisable.Should().BeTrue();
        config.MinSeverityForDisable.Should().Be(Severity.Medium);
        config.ScanDirectories.Should().BeEquivalentTo(new[] { "Mods", "Plugins" });
        config.SuspiciousThreshold.Should().Be(1);
        config.WhitelistedHashes.Should().BeEmpty();
        config.DumpFullIlReports.Should().BeFalse();
        config.MinimumEncodedStringLength.Should().Be(10);
        config.DetectAssemblyMetadata.Should().BeTrue();
        config.EnableMultiSignalDetection.Should().BeTrue();
        config.AnalyzeExceptionHandlers.Should().BeTrue();
        config.AnalyzeLocalVariables.Should().BeTrue();
        config.AnalyzePropertyAccessors.Should().BeTrue();
        config.DeveloperMode.Should().BeFalse();
    }

    [Fact]
    public void Config_PropertiesCanBeModified()
    {
        var config = new ScanConfig
        {
            EnableAutoScan = false,
            EnableAutoDisable = false,
            MinSeverityForDisable = Severity.Critical,
            ScanDirectories = new[] { "CustomMods" },
            SuspiciousThreshold = 5,
            WhitelistedHashes = new[] { "abc123" },
            DumpFullIlReports = true,
            MinimumEncodedStringLength = 20,
            DetectAssemblyMetadata = false,
            EnableMultiSignalDetection = false,
            AnalyzeExceptionHandlers = false,
            AnalyzeLocalVariables = false,
            AnalyzePropertyAccessors = false,
            DeveloperMode = true
        };

        config.EnableAutoScan.Should().BeFalse();
        config.EnableAutoDisable.Should().BeFalse();
        config.MinSeverityForDisable.Should().Be(Severity.Critical);
        config.ScanDirectories.Should().BeEquivalentTo(new[] { "CustomMods" });
        config.SuspiciousThreshold.Should().Be(5);
        config.WhitelistedHashes.Should().BeEquivalentTo(new[] { "abc123" });
        config.DumpFullIlReports.Should().BeTrue();
        config.MinimumEncodedStringLength.Should().Be(20);
        config.DetectAssemblyMetadata.Should().BeFalse();
        config.EnableMultiSignalDetection.Should().BeFalse();
        config.AnalyzeExceptionHandlers.Should().BeFalse();
        config.AnalyzeLocalVariables.Should().BeFalse();
        config.AnalyzePropertyAccessors.Should().BeFalse();
        config.DeveloperMode.Should().BeTrue();
    }
}
