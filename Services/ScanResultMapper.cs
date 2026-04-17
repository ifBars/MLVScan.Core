using System.Security.Cryptography;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;
using Mono.Cecil;

namespace MLVScan.Services;

/// <summary>
/// Maps MLVScan.Core models to schema-compliant DTOs.
/// This mapper is platform-agnostic and can be used by CLI, WASM, Server, and Desktop implementations.
/// </summary>
public static class ScanResultMapper
{
    private static readonly ThreatFamilyClassifier ThreatFamilyClassifier = new();
    private static readonly ThreatDispositionClassifier ThreatDispositionClassifier = new();

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
        var callChains = findingsList
            .Where(f => f.HasCallChain)
            .Select(f => f.CallChain!)
            .Distinct()
            .ToList();
        var dataFlows = findingsList
            .Where(f => f.HasDataFlow)
            .Select(f => f.DataFlowChain!)
            .Distinct()
            .ToList();
        var sha256Hash = ComputeSha256(assemblyBytes);
        var threatFamilies = ThreatFamilyClassifier.Classify(findingsList, callChains, dataFlows, sha256Hash);
        var disposition = ThreatDispositionClassifier.Classify(findingsList, threatFamilies);
        var relatedFindings = disposition.RelatedFindings.ToHashSet();
        var findingDtos = findingsList
            .Select(finding => ToFindingDto(
                finding,
                options,
                relatedFindings.Contains(finding) ? FindingVisibility.Default : FindingVisibility.Advanced))
            .ToList();
        var findingIdsByReference = findingsList
            .Zip(findingDtos, static (finding, dto) => new { finding, dto.Id })
            .Where(static item => !string.IsNullOrWhiteSpace(item.Id))
            .ToDictionary(static item => item.finding, static item => item.Id!, ReferenceEqualityComparer.Instance);
        var result = new ScanResultDto
        {
            SchemaVersion = options.SchemaVersion,
            Metadata = new ScanMetadataDto
            {
                CoreVersion = options.CoreVersion,
                PlatformVersion = options.PlatformVersion,
                ScannerVersion = options.PlatformVersion,
                Timestamp = DateTime.UtcNow.ToString("o"),
                ScanMode = options.ScanMode,
                Platform = options.Platform
            },
            Input = new ScanInputDto
            {
                FileName = fileName, SizeBytes = assemblyBytes.Length, Sha256Hash = sha256Hash
            },
            Assembly = ExtractAssemblyMetadata(assemblyBytes),
            Summary = BuildSummary(findingsList),
            Findings = findingDtos,
            Disposition = ToThreatDispositionDto(disposition, findingIdsByReference)
        };

        if (threatFamilies.Count > 0)
        {
            result.ThreatFamilies = threatFamilies.Select(ToThreatFamilyDto).ToList();
        }

        // Add call chains if present and enabled
        if (options.IncludeCallChains)
        {
            if (callChains.Any())
            {
                result.CallChains = callChains
                    .Select(ToCallChainDto)
                    .ToList();
            }
        }

        // Add data flows if present and enabled
        if (options.IncludeDataFlows)
        {
            if (dataFlows.Any())
            {
                result.DataFlows = dataFlows
                    .Select(ToDataFlowChainDto)
                    .ToList();
            }
        }

        // Add developer guidance if enabled
        if (options.IncludeDeveloperGuidance)
        {
            var guidances = findingsList
                .Where(f => f.DeveloperGuidance != null)
                .GroupBy(f => f.DeveloperGuidance!.Remediation, StringComparer.Ordinal)
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
            IncludeDeveloperGuidance = developerMode, ScanMode = developerMode ? "developer" : "detailed"
        };
        return ToDto(findings, fileName, assemblyBytes, options);
    }

    private static AssemblyMetadataDto? ExtractAssemblyMetadata(byte[] assemblyBytes)
    {
        if (assemblyBytes.Length == 0)
        {
            return null;
        }

        try
        {
            using var stream = new MemoryStream(assemblyBytes, writable: false);
            using var assembly = AssemblyDefinition.ReadAssembly(stream, new ReaderParameters
            {
                ReadSymbols = false
            });

            var referencedAssemblies = assembly.MainModule.AssemblyReferences
                .Select(static reference => reference.Name)
                .Where(static name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return new AssemblyMetadataDto
            {
                Name = NullIfWhiteSpace(assembly.Name?.Name),
                AssemblyVersion = assembly.Name?.Version?.ToString(),
                FileVersion = GetAssemblyAttributeValue(assembly, "System.Reflection.AssemblyFileVersionAttribute"),
                InformationalVersion = GetAssemblyAttributeValue(assembly, "System.Reflection.AssemblyInformationalVersionAttribute"),
                TargetFramework = GetAssemblyAttributeValue(assembly, "System.Runtime.Versioning.TargetFrameworkAttribute"),
                ModuleRuntimeVersion = NullIfWhiteSpace(assembly.MainModule.RuntimeVersion),
                ReferencedAssemblies = referencedAssemblies.Count > 0 ? referencedAssemblies : null
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? GetAssemblyAttributeValue(AssemblyDefinition assembly, string fullAttributeName)
    {
        var attribute = assembly.CustomAttributes.FirstOrDefault(candidate =>
            string.Equals(candidate.AttributeType.FullName, fullAttributeName, StringComparison.Ordinal));
        if (attribute == null || attribute.ConstructorArguments.Count == 0)
        {
            return null;
        }

        return NullIfWhiteSpace(attribute.ConstructorArguments[0].Value?.ToString());
    }

    private static string? NullIfWhiteSpace(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
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

    private static FindingDto ToFindingDto(
        ScanFinding finding,
        ScanResultOptions options,
        FindingVisibility visibility)
    {
        var dto = new FindingDto
        {
            Id = Guid.NewGuid().ToString("N"),
            RuleId = finding.RuleId,
            Description = finding.Description,
            Severity = finding.Severity.ToString(),
            Location = finding.Location,
            CodeSnippet = finding.CodeSnippet,
            RiskScore = finding.RiskScore,
            CallChainId = finding.CallChain?.ChainId,
            DataFlowChainId = finding.DataFlowChain?.ChainId,
            Visibility = visibility.ToString()
        };

        if (options.IncludeDeveloperGuidance && finding.DeveloperGuidance != null)
        {
            dto.DeveloperGuidance = ToDeveloperGuidanceDto(
                finding.DeveloperGuidance,
                string.IsNullOrWhiteSpace(finding.RuleId)
                    ? null
                    : new List<string> { finding.RuleId! });
        }

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
            SourceVariable = dataFlow.SourceVariable,
            MethodLocation = dataFlow.MethodLocation,
            IsCrossMethod = dataFlow.IsCrossMethod,
            IsSuspicious = dataFlow.IsSuspicious,
            CallDepth = dataFlow.CallDepth,
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

    private static DeveloperGuidanceDto ToDeveloperGuidanceDto(IGrouping<string, ScanFinding> guidanceGroup)
    {
        var primaryGuidance = guidanceGroup.First().DeveloperGuidance!;
        var ruleIds = guidanceGroup
            .Select(f => f.RuleId)
            .Where(static ruleId => !string.IsNullOrWhiteSpace(ruleId))
            .Select(static ruleId => ruleId!)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static ruleId => ruleId, StringComparer.Ordinal)
            .ToList();
        var documentationUrl = guidanceGroup
            .Select(f => f.DeveloperGuidance!.DocumentationUrl)
            .FirstOrDefault(static url => !string.IsNullOrWhiteSpace(url));
        var alternativeApis = guidanceGroup
            .SelectMany(f => f.DeveloperGuidance!.AlternativeApis ?? Array.Empty<string>())
            .Where(static api => !string.IsNullOrWhiteSpace(api))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return new DeveloperGuidanceDto
        {
            RuleId = ruleIds.Count == 1 ? ruleIds[0] : null,
            RuleIds = ruleIds.Count > 0 ? ruleIds : null,
            Remediation = primaryGuidance.Remediation,
            DocumentationUrl = documentationUrl,
            AlternativeApis = alternativeApis.Length > 0 ? alternativeApis : null,
            IsRemediable = guidanceGroup.All(f => f.DeveloperGuidance!.IsRemediable)
        };
    }

    private static DeveloperGuidanceDto ToDeveloperGuidanceDto(
        IDeveloperGuidance guidance,
        List<string>? ruleIds)
    {
        return new DeveloperGuidanceDto
        {
            RuleId = ruleIds is { Count: 1 } ? ruleIds[0] : null,
            RuleIds = ruleIds is { Count: > 0 } ? ruleIds : null,
            Remediation = guidance.Remediation,
            DocumentationUrl = guidance.DocumentationUrl,
            AlternativeApis = guidance.AlternativeApis,
            IsRemediable = guidance.IsRemediable
        };
    }

    private static ThreatFamilyDto ToThreatFamilyDto(ThreatFamilyMatch match)
    {
        return new ThreatFamilyDto
        {
            FamilyId = match.FamilyId,
            VariantId = match.VariantId,
            DisplayName = match.DisplayName,
            Summary = match.Summary,
            MatchKind = match.MatchKind.ToString(),
            Confidence = match.Confidence,
            ExactHashMatch = match.ExactHashMatch,
            MatchedRules = match.MatchedRules,
            AdvisorySlugs = match.AdvisorySlugs,
            Evidence = match.Evidence.Select(e => new ThreatFamilyEvidenceDto
            {
                Kind = e.Kind,
                Value = e.Value,
                RuleId = e.RuleId,
                Location = e.Location,
                CallChainId = e.CallChainId,
                DataFlowChainId = e.DataFlowChainId,
                Pattern = e.Pattern,
                MethodLocation = e.MethodLocation,
                Confidence = e.Confidence
            }).ToList()
        };
    }

    private static ThreatDispositionDto ToThreatDispositionDto(
        ThreatDispositionResult disposition,
        IReadOnlyDictionary<ScanFinding, string> findingIdsByReference)
    {
        return new ThreatDispositionDto
        {
            Classification = disposition.Classification.ToString(),
            Headline = disposition.Headline,
            Summary = disposition.Summary,
            BlockingRecommended = disposition.BlockingRecommended,
            PrimaryThreatFamilyId = disposition.PrimaryThreatFamilyId,
            RelatedFindingIds = disposition.RelatedFindings
                .Where(findingIdsByReference.ContainsKey)
                .Select(finding => findingIdsByReference[finding])
                .Distinct(StringComparer.Ordinal)
                .ToList()
        };
    }

    private static string ComputeSha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    private sealed class ReferenceEqualityComparer : IEqualityComparer<ScanFinding>
    {
        public static ReferenceEqualityComparer Instance { get; } = new();

        public bool Equals(ScanFinding? x, ScanFinding? y)
        {
            return ReferenceEquals(x, y);
        }

        public int GetHashCode(ScanFinding obj)
        {
            return System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
        }
    }
}
