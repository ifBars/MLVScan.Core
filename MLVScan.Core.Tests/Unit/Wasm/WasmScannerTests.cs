using System.Reflection;
using System.Text.Json;
using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.WASM;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Wasm;

public class WasmScannerTests
{
#pragma warning disable CS0618
    [Fact]
    public void ScanAssembly_NullBytes_ThrowsArgumentException()
    {
        var scanner = new WasmScanner();

        var act = () => scanner.ScanAssembly(null!, "sample.dll");

        act.Should().Throw<ArgumentException>()
            .WithMessage("Assembly bytes cannot be null or empty*");
    }

    [Fact]
    public void ScanAssembly_EmptyBytes_ThrowsArgumentException()
    {
        var scanner = new WasmScanner();

        var act = () => scanner.ScanAssembly(Array.Empty<byte>(), "sample.dll");

        act.Should().Throw<ArgumentException>()
            .WithMessage("Assembly bytes cannot be null or empty*");
    }

    [Fact]
    public void ScanAssembly_InvalidAssemblyBytes_ReturnsSchemaJsonWithDefaultFileName()
    {
        var scanner = new WasmScanner();

        var json = scanner.ScanAssembly([0x01, 0x02, 0x03], " ");

        var result = JsonSerializer.Deserialize(json, WasmJsonContext.Default.ScanResultDto);
        result.Should().NotBeNull();
        result!.Metadata.Platform.Should().Be("wasm");
        result.Metadata.PlatformVersion.Should().Be(WasmScanner.GetVersion());
        result.Input.FileName.Should().Be("unknown.dll");
        result.Input.SizeBytes.Should().Be(3);
        result.Summary.TotalFindings.Should().Be(result.Findings.Count);
    }

    [Fact]
    public void ScanAssemblyWithConfig_InvalidConfigFallsBackToDefaultConfig()
    {
        var scanner = new WasmScanner(new ScanConfig { DeveloperMode = true });

        var json = scanner.ScanAssemblyWithConfig([0x7f], "bad.dll", "{not-json");

        var result = JsonSerializer.Deserialize(json, WasmJsonContext.Default.ScanResultDto);
        result.Should().NotBeNull();
        result!.Input.FileName.Should().Be("bad.dll");
        result.Summary.TotalFindings.Should().Be(result.Findings.Count);
    }

    [Fact]
    public void ScanAssemblyWithConfig_ValidConfigUsesNestedScanner()
    {
        var scanner = new WasmScanner();
        var configJson = JsonSerializer.Serialize(new ScanConfig { DeveloperMode = true }, WasmJsonContext.Default.ScanConfig);

        var json = scanner.ScanAssemblyWithConfig([0x7f], "bad-configured.dll", configJson);

        var result = JsonSerializer.Deserialize(json, WasmJsonContext.Default.ScanResultDto);
        result.Should().NotBeNull();
        result!.Input.FileName.Should().Be("bad-configured.dll");
        result.Summary.TotalFindings.Should().Be(result.Findings.Count);
    }

    [Fact]
    public void ScanAssembly_ValidSyntheticAssembly_ReturnsSchemaJson()
    {
        using var stream = TestAssemblyBuilder.Create("WasmCleanAssembly")
            .AddType("Test.Clean")
            .AddMethod("Run")
            .Emit(Mono.Cecil.Cil.OpCodes.Ret)
            .EndMethod()
            .EndType()
            .ToStream();
        var bytes = stream.ToArray();
        var scanner = new WasmScanner();

        var json = scanner.ScanAssembly(bytes, "clean.dll");

        var result = JsonSerializer.Deserialize(json, WasmJsonContext.Default.ScanResultDto);
        result.Should().NotBeNull();
        result!.Input.FileName.Should().Be("clean.dll");
        result.Input.SizeBytes.Should().Be(bytes.Length);
        result.Metadata.Platform.Should().Be("wasm");
        result.Metadata.PlatformVersion.Should().Be(WasmScanner.GetVersion());
    }
#pragma warning restore CS0618

    [Fact]
    public void ScannerExports_VersionMethods_ReturnWasmVersions()
    {
#pragma warning disable CS0618
        ScannerExports.GetVersion().Should().Be(WasmScanner.GetVersion());
        ScannerExports.GetSchemaVersion().Should().Be(WasmScanner.GetSchemaVersion());
#pragma warning restore CS0618
    }

    [Fact]
    public void ProgramMain_CanBeInvokedForCoverage()
    {
        var main = typeof(Program).GetMethod("Main", BindingFlags.Static | BindingFlags.NonPublic);

        main.Should().NotBeNull();
        var act = () => main!.Invoke(null, [Array.Empty<string>()]);

        act.Should().NotThrow();
    }
}
