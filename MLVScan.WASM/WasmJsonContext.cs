using System.Text.Json.Serialization;
using MLVScan.Models;
using MLVScan.Models.Dto;

namespace MLVScan.WASM;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ScanResultDto))]
[JsonSerializable(typeof(ScanMetadataDto))]
[JsonSerializable(typeof(ScanInputDto))]
[JsonSerializable(typeof(ScanSummaryDto))]
[JsonSerializable(typeof(FindingDto))]
[JsonSerializable(typeof(CallChainDto))]
[JsonSerializable(typeof(CallChainNodeDto))]
[JsonSerializable(typeof(DataFlowChainDto))]
[JsonSerializable(typeof(DataFlowNodeDto))]
[JsonSerializable(typeof(DeveloperGuidanceDto))]
[JsonSerializable(typeof(Dictionary<string, int>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(ScanConfig))]
[JsonSerializable(typeof(Severity))]
public partial class WasmJsonContext : JsonSerializerContext
{
}
