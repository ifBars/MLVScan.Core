using System.Security.Cryptography;
using MLVScan.Models;
using MLVScan.Models.Dto;

namespace MLVScan.Services;

/// <summary>
/// Maps MLVScan.Core models to schema-compliant DTOs.
/// This mapper is platform-agnostic and can be used by CLI, WASM, Server, and Desktop implementations.
/// </summary>
public static class ScanResultMapper
{
    /// <summary>
    /// Converts a collection of ScanFinding to a complete ScanResultDto.
    /// </summary>
    /// <param name="findings">The scan findings from MLVScan.Core</param>
    /// <param name="fileName">Name of the scanned file</param>
    /// <param name="assemblyBytes">Raw bytes of the scanned assembly (for hash computation)</param>
    /// <param name="options">Options controlling output format and metadata</param>
    public static ScanResultDto ToDto(
        IEnumerable<ScanFinding> findings,
        string fileName,
        byte[] assemblyBytes,
        ScanResultOptions options)
    {
        var findingsList = findings.ToList();
        var result = new ScanResultDto
        {
            SchemaVersion = options.SchemaVersion,
            Metadata = new ScanMetadataDto
            {
                CoreVersion = options.CoreVersion,
                PlatformVersion = options.PlatformVersion,
                Timestamp = DateTime.UtcNow.ToString("o"),
                ScanMode = options.ScanMode,
                Platform = options.Platform
            },
            Input = new ScanInputDto
            {
                FileName = fileName,
                SizeBytes = assemblyBytes.Length,
                Sha256Hash = ComputeSha256(assemblyBytes)
            },
            Summary = BuildSummary(findingsList),
            Findings = findingsList.Select(ToFindingDto).ToList()
        };

        // Add call chains if present and enabled
        if (options.IncludeCallChains)
        {
            var findingsWithCallChains = findingsList.Where(f => f.HasCallChain).ToList();
            if (findingsWithCallChains.Any())
            {
                result.CallChains = findingsWithCallChains
                    .Select(f => f.CallChain!)
                    .Distinct()
                    .Select(ToCallChainDto)
                    .ToList();
            }
        }

        // Add data flows if present and enabled
        if (options.IncludeDataFlows)
        {
            var findingsWithDataFlows = findingsList.Where(f => f.HasDataFlow).ToList();
            if (findingsWithDataFlows.Any())
            {
                result.DataFlows = findingsWithDataFlows
                    .Select(f => f.DataFlowChain!)
                    .Distinct()
                    .Select(ToDataFlowChainDto)
                    .ToList();
            }
        }

        // Add developer guidance if enabled
        if (options.IncludeDeveloperGuidance)
        {
            var guidances = findingsList
                .Where(f => f.DeveloperGuidance != null)
                .Select(f => f.DeveloperGuidance!)
                .GroupBy(g => g.Remediation)
                .Select(g => g.First())
                .Select(ToDeveloperGuidanceDto)
                .ToList();

            if (guidances.Any())
            {
                result.DeveloperGuidance = guidances;
            }
        }

        return result;
    }

    /// <summary>
    /// Converts a collection of ScanFinding to a complete ScanResultDto using default options.
    /// </summary>
    /// <param name="findings">The scan findings from MLVScan.Core</param>
    /// <param name="fileName">Name of the scanned file</param>
    /// <param name="assemblyBytes">Raw bytes of the scanned assembly (for hash computation)</param>
    /// <param name="developerMode">Whether to include developer guidance</param>
    public static ScanResultDto ToDto(
        IEnumerable<ScanFinding> findings,
        string fileName,
        byte[] assemblyBytes,
        bool developerMode = false)
    {
        var options = new ScanResultOptions
        {
            IncludeDeveloperGuidance = developerMode,
            ScanMode = developerMode ? "developer" : "detailed"
        };
        return ToDto(findings, fileName, assemblyBytes, options);
    }

    private static ScanSummaryDto BuildSummary(List<ScanFinding> findings)
    {
        var summary = new ScanSummaryDto
        {
            TotalFindings = findings.Count,
            CountBySeverity = findings
                .GroupBy(f => f.Severity.ToString())
                .ToDictionary(g => g.Key, g => g.Count()),
            TriggeredRules = findings
                .Where(f => f.RuleId != null)
                .Select(f => f.RuleId!)
                .Distinct()
                .OrderBy(r => r)
                .ToList()
        };

        return summary;
    }

    private static FindingDto ToFindingDto(ScanFinding finding)
    {
        var dto = new FindingDto
        {
            Id = Guid.NewGuid().ToString("N"),
            RuleId = finding.RuleId,
            Description = finding.Description,
            Severity = finding.Severity.ToString(),
            Location = finding.Location,
            CodeSnippet = finding.CodeSnippet
        };

        // Embed call chain if present
        if (finding.HasCallChain)
        {
            dto.CallChain = ToCallChainDto(finding.CallChain!);
        }

        // Embed data flow chain if present
        if (finding.HasDataFlow)
        {
            dto.DataFlowChain = ToDataFlowChainDto(finding.DataFlowChain!);
        }

        return dto;
    }

    private static CallChainDto ToCallChainDto(CallChain callChain)
    {
        return new CallChainDto
        {
            Id = callChain.ChainId,
            RuleId = callChain.RuleId,
            Description = callChain.Summary,
            Severity = callChain.Severity.ToString(),
            Nodes = callChain.Nodes.Select(node => new CallChainNodeDto
            {
                NodeType = node.NodeType.ToString(),
                Location = node.Location,
                Description = node.Description,
                CodeSnippet = node.CodeSnippet
            }).ToList()
        };
    }

    private static DataFlowChainDto ToDataFlowChainDto(DataFlowChain dataFlow)
    {
        return new DataFlowChainDto
        {
            Id = dataFlow.ChainId,
            Description = dataFlow.Summary,
            Severity = dataFlow.Severity.ToString(),
            Pattern = dataFlow.Pattern.ToString(),
            Confidence = dataFlow.Confidence,
            SourceVariable = dataFlow.SourceVariable,
            MethodLocation = dataFlow.MethodLocation,
            IsCrossMethod = dataFlow.IsCrossMethod,
            InvolvedMethods = dataFlow.InvolvedMethods.Count > 0 ? dataFlow.InvolvedMethods : null,
            Nodes = dataFlow.Nodes.Select(node => new DataFlowNodeDto
            {
                NodeType = node.NodeType.ToString(),
                Location = node.Location,
                Operation = node.Operation,
                DataDescription = node.DataDescription,
                InstructionOffset = node.InstructionOffset,
                MethodKey = node.MethodKey,
                IsMethodBoundary = node.IsMethodBoundary,
                TargetMethodKey = node.TargetMethodKey,
                CodeSnippet = node.CodeSnippet
            }).ToList()
        };
    }

    private static DeveloperGuidanceDto ToDeveloperGuidanceDto(IDeveloperGuidance guidance)
    {
        return new DeveloperGuidanceDto
        {
            RuleId = null, // Set by caller if needed
            Remediation = guidance.Remediation,
            DocumentationUrl = guidance.DocumentationUrl,
            AlternativeApis = guidance.AlternativeApis,
            IsRemediable = guidance.IsRemediable
        };
    }

    private static string ComputeSha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
}
