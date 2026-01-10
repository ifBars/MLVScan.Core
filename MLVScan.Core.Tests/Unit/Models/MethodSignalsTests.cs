using FluentAssertions;
using MLVScan.Models;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models;

public class MethodSignalsTests
{
    [Fact]
    public void SignalCount_NoSignals_ReturnsZero()
    {
        var signals = new MethodSignals();

        signals.SignalCount.Should().Be(0);
    }

    [Fact]
    public void SignalCount_SingleSignal_ReturnsOne()
    {
        var signals = new MethodSignals { HasBase64 = true };

        signals.SignalCount.Should().Be(1);
    }

    [Fact]
    public void SignalCount_MultipleSignals_ReturnsCorrectCount()
    {
        var signals = new MethodSignals
        {
            HasBase64 = true,
            HasNetworkCall = true,
            HasFileWrite = true,
            HasEncodedStrings = true
        };

        signals.SignalCount.Should().Be(4);
    }

    [Fact]
    public void SignalCount_AllSignals_ReturnsNine()
    {
        var signals = new MethodSignals
        {
            HasEncodedStrings = true,
            HasSuspiciousReflection = true,
            UsesSensitiveFolder = true,
            HasProcessLikeCall = true,
            HasBase64 = true,
            HasNetworkCall = true,
            HasFileWrite = true,
            HasSuspiciousLocalVariables = true,
            HasSuspiciousExceptionHandling = true
        };

        signals.SignalCount.Should().Be(9);
    }

    [Theory]
    [InlineData(true, true, false, false, false, false, false, false, false, true)] // Reflection + Encoded
    [InlineData(true, false, true, false, false, false, false, false, false, false)] // Encoded + Sensitive (not critical alone)
    [InlineData(false, true, true, false, false, false, false, false, false, true)] // Reflection + Sensitive
    [InlineData(true, false, false, true, false, false, false, false, false, true)] // Encoded + Process
    [InlineData(false, false, true, true, false, false, true, false, false, true)] // Sensitive + FileWrite + Process
    [InlineData(false, false, true, false, false, true, true, false, false, true)] // Network + Sensitive + FileWrite
    public void IsCriticalCombination_VariousPatterns_ReturnsExpected(
        bool hasEncoded, bool hasReflection, bool hasSensitive, bool hasProcess,
        bool hasBase64, bool hasNetwork, bool hasFileWrite, bool hasLocalVars,
        bool hasExceptionHandling, bool expectedCritical)
    {
        var signals = new MethodSignals
        {
            HasEncodedStrings = hasEncoded,
            HasSuspiciousReflection = hasReflection,
            UsesSensitiveFolder = hasSensitive,
            HasProcessLikeCall = hasProcess,
            HasBase64 = hasBase64,
            HasNetworkCall = hasNetwork,
            HasFileWrite = hasFileWrite,
            HasSuspiciousLocalVariables = hasLocalVars,
            HasSuspiciousExceptionHandling = hasExceptionHandling
        };

        signals.IsCriticalCombination().Should().Be(expectedCritical);
    }

    [Fact]
    public void IsHighRiskCombination_SensitiveFolderPlusNetwork_ReturnsTrue()
    {
        var signals = new MethodSignals
        {
            UsesSensitiveFolder = true,
            HasNetworkCall = true
        };

        signals.IsHighRiskCombination().Should().BeTrue();
    }
    
    [Fact]
    public void IsHighRiskCombination_SensitiveFolderPlusProcess_ReturnsTrue()
    {
        var signals = new MethodSignals
        {
            UsesSensitiveFolder = true,
            HasProcessLikeCall = true
        };

        signals.IsHighRiskCombination().Should().BeTrue();
    }
    
    [Fact]
    public void IsHighRiskCombination_NetworkPlusFileWrite_ReturnsTrue()
    {
        var signals = new MethodSignals
        {
            HasNetworkCall = true,
            HasFileWrite = true
        };

        signals.IsHighRiskCombination().Should().BeTrue();
    }
    
    [Fact]
    public void IsHighRiskCombination_Base64PlusNetwork_ReturnsTrue()
    {
        var signals = new MethodSignals
        {
            HasBase64 = true,
            HasNetworkCall = true
        };

        signals.IsHighRiskCombination().Should().BeTrue();
    }

    [Fact]
    public void IsHighRiskCombination_CriticalCombination_ReturnsFalse()
    {
        var signals = new MethodSignals
        {
            HasSuspiciousReflection = true,
            HasEncodedStrings = true
        };

        // Critical combinations are not considered "high risk" (they're critical)
        signals.IsHighRiskCombination().Should().BeFalse();
    }

    [Fact]
    public void IsHighRiskCombination_SingleSignal_ReturnsFalse()
    {
        var signals = new MethodSignals { HasBase64 = true };

        signals.IsHighRiskCombination().Should().BeFalse();
    }
    
    [Fact]
    public void IsHighRiskCombination_SensitiveFolderPlusExceptionHandler_ReturnsFalse()
    {
        // This is a legitimate pattern (fallback save directory in catch block)
        // Should NOT trigger high severity
        var signals = new MethodSignals
        {
            UsesSensitiveFolder = true,
            HasSuspiciousExceptionHandling = true
        };

        signals.IsHighRiskCombination().Should().BeFalse();
    }
    
    [Fact]
    public void IsHighRiskCombination_TwoHarmlessPrecursors_ReturnsFalse()
    {
        // Two precursors that can't cause harm alone should not be high risk
        var signals = new MethodSignals
        {
            UsesSensitiveFolder = true,
            HasSuspiciousLocalVariables = true
        };

        signals.IsHighRiskCombination().Should().BeFalse();
    }

    [Fact]
    public void MarkRuleTriggered_AddsRuleId()
    {
        var signals = new MethodSignals();

        signals.MarkRuleTriggered("Base64Rule");

        signals.HasAnyTriggeredRule().Should().BeTrue();
        signals.GetTriggeredRuleIds().Should().Contain("Base64Rule");
    }

    [Fact]
    public void MarkRuleTriggered_NullOrEmpty_DoesNotAdd()
    {
        var signals = new MethodSignals();

        signals.MarkRuleTriggered(null!);
        signals.MarkRuleTriggered("");

        signals.HasAnyTriggeredRule().Should().BeFalse();
    }

    [Fact]
    public void HasTriggeredRuleOtherThan_SingleMatchingRule_ReturnsFalse()
    {
        var signals = new MethodSignals();
        signals.MarkRuleTriggered("Base64Rule");

        signals.HasTriggeredRuleOtherThan("Base64Rule").Should().BeFalse();
    }

    [Fact]
    public void HasTriggeredRuleOtherThan_MultipleRules_ReturnsTrue()
    {
        var signals = new MethodSignals();
        signals.MarkRuleTriggered("Base64Rule");
        signals.MarkRuleTriggered("ProcessStartRule");

        signals.HasTriggeredRuleOtherThan("Base64Rule").Should().BeTrue();
    }

    [Fact]
    public void HasTriggeredRuleOtherThan_NoRules_ReturnsFalse()
    {
        var signals = new MethodSignals();

        signals.HasTriggeredRuleOtherThan("AnyRule").Should().BeFalse();
    }

    [Fact]
    public void GetCombinationDescription_MultipleSignals_ReturnsFormattedString()
    {
        var signals = new MethodSignals
        {
            HasBase64 = true,
            HasNetworkCall = true,
            HasFileWrite = true
        };

        var description = signals.GetCombinationDescription();

        description.Should().Contain("Base64 decoding");
        description.Should().Contain("network call");
        description.Should().Contain("file write");
        description.Should().Contain(" + ");
    }

    [Fact]
    public void GetCombinationDescription_NoSignals_ReturnsEmpty()
    {
        var signals = new MethodSignals();

        signals.GetCombinationDescription().Should().BeEmpty();
    }
}
