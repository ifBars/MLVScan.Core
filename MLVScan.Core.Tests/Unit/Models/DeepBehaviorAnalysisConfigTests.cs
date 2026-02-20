using FluentAssertions;
using MLVScan.Models;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models;

public class DeepBehaviorAnalysisConfigTests
{
    [Fact]
    public void DefaultConfig_UsesQuickSafeDefaults()
    {
        var config = new DeepBehaviorAnalysisConfig();

        config.EnableDeepAnalysis.Should().BeFalse();
        config.EmitDiagnosticFindings.Should().BeFalse();
        config.RequireCorrelatedBaseFinding.Should().BeTrue();
        config.DeepScanOnlyFlaggedMethods.Should().BeTrue();
        config.EnableStringDecodeFlow.Should().BeTrue();
        config.EnableExecutionChainAnalysis.Should().BeTrue();
        config.EnableResourcePayloadAnalysis.Should().BeTrue();
    }

    [Fact]
    public void IsAnyDeepAnalysisEnabled_WhenNoFeatureFlags_ReturnsFalse()
    {
        var config = new DeepBehaviorAnalysisConfig
        {
            EnableStringDecodeFlow = false,
            EnableExecutionChainAnalysis = false,
            EnableResourcePayloadAnalysis = false,
            EnableDynamicLoadCorrelation = false,
            EnableNativeInteropCorrelation = false,
            EnableScriptHostLaunchAnalysis = false,
            EnableEnvironmentPivotCorrelation = false,
            EnableNetworkToExecutionCorrelation = false,
            EmitDiagnosticFindings = false
        };

        config.IsAnyDeepAnalysisEnabled().Should().BeFalse();
    }

    [Fact]
    public void IsAnyDeepAnalysisEnabled_WhenOneFeatureEnabled_ReturnsTrue()
    {
        var config = new DeepBehaviorAnalysisConfig
        {
            EnableStringDecodeFlow = false,
            EnableExecutionChainAnalysis = true,
            EnableResourcePayloadAnalysis = false
        };

        config.IsAnyDeepAnalysisEnabled().Should().BeTrue();
    }
}
