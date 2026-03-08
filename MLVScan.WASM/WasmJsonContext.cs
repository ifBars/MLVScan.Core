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
[JsonSerializable(typeof(ThreatFamilyDto))]
[JsonSerializable(typeof(ThreatFamilyEvidenceDto))]
[JsonSerializable(typeof(Dictionary<string, int>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(List<ThreatFamilyDto>))]
[JsonSerializable(typeof(List<ThreatFamilyEvidenceDto>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(ScanConfig))]
[JsonSerializable(typeof(DeepBehaviorAnalysisConfig))]
[JsonSerializable(typeof(Severity))]
public partial class WasmJsonContext : JsonSerializerContext
{
}
