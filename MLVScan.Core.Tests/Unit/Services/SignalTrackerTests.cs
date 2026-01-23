using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Services;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class SignalTrackerTests
{
    [Fact]
    public void CreateMethodSignals_MultiSignalEnabled_ReturnsSignals()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var signals = tracker.CreateMethodSignals();

        signals.Should().NotBeNull();
    }

    [Fact]
    public void CreateMethodSignals_MultiSignalDisabled_ReturnsNull()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = false };
        var tracker = new SignalTracker(config);

        var signals = tracker.CreateMethodSignals();

        signals.Should().BeNull();
    }

    [Fact]
    public void GetOrCreateTypeSignals_MultiSignalEnabled_ReturnsSignals()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var signals = tracker.GetOrCreateTypeSignals("MyNamespace.MyType");

        signals.Should().NotBeNull();
    }

    [Fact]
    public void GetOrCreateTypeSignals_MultiSignalDisabled_ReturnsNull()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = false };
        var tracker = new SignalTracker(config);

        var signals = tracker.GetOrCreateTypeSignals("MyNamespace.MyType");

        signals.Should().BeNull();
    }

    [Fact]
    public void GetOrCreateTypeSignals_SameType_ReturnsSameInstance()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var signals1 = tracker.GetOrCreateTypeSignals("MyNamespace.MyType");
        var signals2 = tracker.GetOrCreateTypeSignals("MyNamespace.MyType");

        signals1.Should().BeSameAs(signals2);
    }

    [Fact]
    public void GetOrCreateTypeSignals_DifferentTypes_ReturnsDifferentInstances()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var signals1 = tracker.GetOrCreateTypeSignals("TypeA");
        var signals2 = tracker.GetOrCreateTypeSignals("TypeB");

        signals1.Should().NotBeSameAs(signals2);
    }

    [Fact]
    public void GetTypeSignals_ExistingType_ReturnsSignals()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var created = tracker.GetOrCreateTypeSignals("MyType");
        var retrieved = tracker.GetTypeSignals("MyType");

        retrieved.Should().BeSameAs(created);
    }

    [Fact]
    public void GetTypeSignals_NonExistingType_ReturnsNull()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var signals = tracker.GetTypeSignals("NonExistingType");

        signals.Should().BeNull();
    }

    [Fact]
    public void ClearTypeSignals_RemovesSignals()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        tracker.GetOrCreateTypeSignals("MyType");
        tracker.ClearTypeSignals("MyType");

        tracker.GetTypeSignals("MyType").Should().BeNull();
    }

    [Fact]
    public void UpdateMethodSignals_Base64Call_SetsHasBase64()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        tracker.UpdateMethodSignals(signals, methodRef, null);

        signals.HasBase64.Should().BeTrue();
    }

    [Fact]
    public void UpdateMethodSignals_ProcessStart_SetsHasProcessLikeCall()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        var methodRef = MethodReferenceFactory.Create("System.Diagnostics.Process", "Start");
        tracker.UpdateMethodSignals(signals, methodRef, null);

        signals.HasProcessLikeCall.Should().BeTrue();
    }

    [Fact]
    public void UpdateMethodSignals_ReflectionInvoke_SetsSuspiciousReflection()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        var methodRef = MethodReferenceFactory.Create("System.Reflection.MethodInfo", "Invoke");
        tracker.UpdateMethodSignals(signals, methodRef, null);

        signals.HasSuspiciousReflection.Should().BeTrue();
    }

    [Fact]
    public void UpdateMethodSignals_NetworkCall_SetsHasNetworkCall()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        var methodRef = MethodReferenceFactory.Create("System.Net.Http.HttpClient", "GetAsync");
        tracker.UpdateMethodSignals(signals, methodRef, null);

        signals.HasNetworkCall.Should().BeTrue();
    }

    [Fact]
    public void UpdateMethodSignals_FileWrite_SetsHasFileWrite()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        var methodRef = MethodReferenceFactory.Create("System.IO.File", "WriteAllBytes");
        tracker.UpdateMethodSignals(signals, methodRef, null);

        signals.HasFileWrite.Should().BeTrue();
    }

    [Fact]
    public void UpdateMethodSignals_NullMethod_DoesNotThrow()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        var act = () => tracker.UpdateMethodSignals(signals, null!, null);

        act.Should().NotThrow();
    }

    [Fact]
    public void UpdateMethodSignals_NullSignals_DoesNotThrow()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);

        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");
        var act = () => tracker.UpdateMethodSignals(null!, methodRef, null);

        act.Should().NotThrow();
    }

    [Fact]
    public void MarkEncodedStrings_SetsFlag()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        tracker.MarkEncodedStrings(signals, null);

        signals.HasEncodedStrings.Should().BeTrue();
    }

    [Fact]
    public void MarkSensitiveFolder_SetsFlag()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        tracker.MarkSensitiveFolder(signals, null);

        signals.UsesSensitiveFolder.Should().BeTrue();
    }

    [Fact]
    public void MarkRuleTriggered_AddsRuleIdToSignals()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        tracker.MarkRuleTriggered(signals, null, "TestRule");

        signals.HasAnyTriggeredRule().Should().BeTrue();
        signals.GetTriggeredRuleIds().Should().Contain("TestRule");
    }

    [Fact]
    public void MarkRuleTriggered_NullRuleId_DoesNotAdd()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var signals = new MethodSignals();

        tracker.MarkRuleTriggered(signals, null, null!);

        signals.HasAnyTriggeredRule().Should().BeFalse();
    }
}
