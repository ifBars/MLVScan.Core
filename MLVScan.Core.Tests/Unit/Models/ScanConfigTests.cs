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
            MinimumEncodedStringLength = 20,
            DetectAssemblyMetadata = false,
            EnableMultiSignalDetection = false,
            AnalyzeExceptionHandlers = false,
            AnalyzeLocalVariables = false,
            AnalyzePropertyAccessors = false,
            DeveloperMode = true
        };

        config.MinimumEncodedStringLength.Should().Be(20);
        config.DetectAssemblyMetadata.Should().BeFalse();
        config.EnableMultiSignalDetection.Should().BeFalse();
        config.AnalyzeExceptionHandlers.Should().BeFalse();
        config.AnalyzeLocalVariables.Should().BeFalse();
        config.AnalyzePropertyAccessors.Should().BeFalse();
        config.DeveloperMode.Should().BeTrue();
    }
}
