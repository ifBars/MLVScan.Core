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
        config.MaxExceptionHandlersPerMethod.Should().Be(128);
        config.MaxExceptionHandlerInstructionsPerMethod.Should().Be(16384);
        config.MaxExceptionHandlerFindingsPerMethod.Should().Be(256);
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
            MaxExceptionHandlersPerMethod = 4,
            MaxExceptionHandlerInstructionsPerMethod = 32,
            MaxExceptionHandlerFindingsPerMethod = 2,
            AnalyzeLocalVariables = false,
            AnalyzePropertyAccessors = false,
            DeveloperMode = true
        };

        config.MinimumEncodedStringLength.Should().Be(20);
        config.DetectAssemblyMetadata.Should().BeFalse();
        config.EnableMultiSignalDetection.Should().BeFalse();
        config.AnalyzeExceptionHandlers.Should().BeFalse();
        config.MaxExceptionHandlersPerMethod.Should().Be(4);
        config.MaxExceptionHandlerInstructionsPerMethod.Should().Be(32);
        config.MaxExceptionHandlerFindingsPerMethod.Should().Be(2);
        config.AnalyzeLocalVariables.Should().BeFalse();
        config.AnalyzePropertyAccessors.Should().BeFalse();
        config.DeveloperMode.Should().BeTrue();
    }
}
