using FluentAssertions;
using MLVScan.Abstractions;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Abstractions;

public class NullScanLoggerTests
{
    [Fact]
    public void Instance_ReturnsSingletonInstance()
    {
        var instance1 = NullScanLogger.Instance;
        var instance2 = NullScanLogger.Instance;

        instance1.Should().BeSameAs(instance2);
        instance1.Should().NotBeNull();
    }

    [Fact]
    public void Debug_DoesNotThrow()
    {
        var act = () => NullScanLogger.Instance.Debug("Test debug message");
        act.Should().NotThrow();
    }

    [Fact]
    public void Info_DoesNotThrow()
    {
        var act = () => NullScanLogger.Instance.Info("Test info message");
        act.Should().NotThrow();
    }

    [Fact]
    public void Warning_DoesNotThrow()
    {
        var act = () => NullScanLogger.Instance.Warning("Test warning message");
        act.Should().NotThrow();
    }

    [Fact]
    public void Error_DoesNotThrow()
    {
        var act = () => NullScanLogger.Instance.Error("Test error message");
        act.Should().NotThrow();
    }

    [Fact]
    public void Error_WithException_DoesNotThrow()
    {
        var exception = new InvalidOperationException("Test exception");
        var act = () => NullScanLogger.Instance.Error("Test error with exception", exception);

        act.Should().NotThrow();
    }

    [Fact]
    public void Debug_WithNullMessage_DoesNotThrow()
    {
        var act = () => NullScanLogger.Instance.Debug(null!);
        act.Should().NotThrow();
    }

    [Fact]
    public void Error_WithNullException_DoesNotThrow()
    {
        var act = () => NullScanLogger.Instance.Error("Test error", null!);
        act.Should().NotThrow();
    }
}
