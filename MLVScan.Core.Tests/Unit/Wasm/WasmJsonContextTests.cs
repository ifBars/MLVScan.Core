using System.Text.Json;
using FluentAssertions;
using MLVScan.Models.Dto;
using MLVScan.WASM;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Wasm;

public class WasmJsonContextTests
{
    [Fact]
    public void Serialize_ScanResult_WithAssemblyMetadata_IncludesAssemblyPayload()
    {
        var result = new ScanResultDto
        {
            SchemaVersion = "1.2.0",
            Metadata = new ScanMetadataDto
            {
                CoreVersion = "1.0.0",
                PlatformVersion = "1.0.0",
                ScannerVersion = "1.0.0",
                Timestamp = DateTime.UtcNow.ToString("O"),
                Platform = "wasm",
                ScanMode = "summary"
            },
            Input = new ScanInputDto
            {
                FileName = "ConsoleForAll.dll",
                SizeBytes = 123,
                Sha256Hash = "abc123"
            },
            Assembly = new AssemblyMetadataDto
            {
                Name = "ConsoleForAll",
                AssemblyVersion = "0.4.4.0",
                FileVersion = "0.4.4",
                InformationalVersion = "0.4.4+test",
                TargetFramework = ".NETFramework,Version=v4.7.2",
                ModuleRuntimeVersion = "v4.0.30319",
                ReferencedAssemblies = ["BepInEx.Core", "Il2CppInterop.Runtime"]
            },
            Summary = new ScanSummaryDto
            {
                TotalFindings = 0
            }
        };

        var json = JsonSerializer.Serialize(result, WasmJsonContext.Default.ScanResultDto);

        json.Should().Contain("\"assembly\":");
        json.Should().Contain("\"name\":\"ConsoleForAll\"");
        json.Should().Contain("\"referencedAssemblies\":[\"BepInEx.Core\",\"Il2CppInterop.Runtime\"]");
    }
}
