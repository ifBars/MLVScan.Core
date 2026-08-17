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
        config.EnableCrossMethodAnalysis.Should().BeTrue();
        config.MaxCallChainDepth.Should().Be(5);
        config.MaxDataFlowOperationsPerMethod.Should().Be(2048);
        config.MaxDataFlowChainsPerMethod.Should().Be(256);
        config.MaxCrossMethodCallEdges.Should().Be(100000);
        config.MaxDeepCallChainEdges.Should().Be(10000);
        config.MaxCrossMethodChains.Should().Be(512);
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
            EnableCrossMethodAnalysis = false,
            MaxCallChainDepth = 2,
            MaxDataFlowOperationsPerMethod = 128,
            MaxDataFlowChainsPerMethod = 32,
            MaxCrossMethodCallEdges = 256,
            MaxDeepCallChainEdges = 64,
            MaxCrossMethodChains = 16,
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
        config.EnableCrossMethodAnalysis.Should().BeFalse();
        config.MaxCallChainDepth.Should().Be(2);
        config.MaxDataFlowOperationsPerMethod.Should().Be(128);
        config.MaxDataFlowChainsPerMethod.Should().Be(32);
        config.MaxCrossMethodCallEdges.Should().Be(256);
        config.MaxDeepCallChainEdges.Should().Be(64);
        config.MaxCrossMethodChains.Should().Be(16);
        config.DeveloperMode.Should().BeTrue();
    }
}
