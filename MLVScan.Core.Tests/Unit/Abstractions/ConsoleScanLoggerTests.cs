using FluentAssertions;
using MLVScan.Abstractions;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Abstractions;

public class ConsoleScanLoggerTests : IDisposable
{
    private readonly ConsoleScanLogger _logger;
    private readonly StringWriter _stringWriter;
    private readonly TextWriter _originalOutput;

    public ConsoleScanLoggerTests()
    {
        _logger = ConsoleScanLogger.Instance;
        _stringWriter = new StringWriter();
        _originalOutput = Console.Out;
        Console.SetOut(_stringWriter);
    }

    public void Dispose()
    {
        Console.SetOut(_originalOutput);
        _stringWriter.Dispose();
    }

    [Fact]
    public void Instance_ReturnsSingletonInstance()
    {
        var instance1 = ConsoleScanLogger.Instance;
        var instance2 = ConsoleScanLogger.Instance;

        instance1.Should().BeSameAs(instance2);
        instance1.Should().NotBeNull();
    }

    [Fact]
    public void Debug_WritesToConsoleWithPrefix()
    {
        _logger.Debug("Test debug message");

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan DEBUG] Test debug message");
    }

    [Fact]
    public void Info_WritesToConsoleWithPrefix()
    {
        _logger.Info("Test info message");

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan INFO] Test info message");
    }

    [Fact]
    public void Warning_WritesToConsoleWithPrefix()
    {
        _logger.Warning("Test warning message");

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan WARN] Test warning message");
    }

    [Fact]
    public void Error_WritesToConsoleWithPrefix()
    {
        _logger.Error("Test error message");

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan ERROR] Test error message");
    }

    [Fact]
    public void Error_WithException_WritesToConsoleWithExceptionDetails()
    {
        var exception = new InvalidOperationException("Test exception");

        _logger.Error("Test error with exception", exception);

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan ERROR] Test error with exception:");
        output.Should().Contain("Test exception");
    }

    [Fact]
    public void Debug_WithEmptyString_WritesToConsole()
    {
        _logger.Debug(string.Empty);

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan DEBUG]");
    }

    [Fact]
    public void Info_WithSpecialCharacters_WritesToConsole()
    {
        _logger.Info("Message with special chars: @#$%^&*()");

        var output = _stringWriter.ToString();
        output.Should().Contain("[MLVScan INFO] Message with special chars: @#$%^&*()");
    }
}
