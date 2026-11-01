#nullable enable
using System.Collections.ObjectModel;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Models.Telemetry;

namespace MLVScan.Services;

/// <summary>Bounded numeric projection of existing results. No identity, text, IO or reclassification.</summary>
public sealed class ScanDiagnosticSummary
{
    public const int SchemaVersion = 3;
    public const int MaxGroups = 192;
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);
    private readonly HashSet<string> _findingIds;

    /// <summary>
    /// Every finding ID Core can emit: rule IDs plus scanner, correlation and budget findings.
    /// Reviewed explicitly so telemetry never derives property names from input. Other consumers
    /// (for example the website allowlist generator) read this literal. Unlisted IDs count as "other".
    /// </summary>
    public static readonly IReadOnlyList<string> FindingIds = new ReadOnlyCollection<string>(new[] { "AssemblyDynamicLoadRule", "AssemblyScanner", "Base64Rule", "ByteArrayManipulationRule", "COMReflectionAttackRule", "CoordinatedPayloadDeliveryRule", "CrossAssemblyDependency", "DataExfiltrationRule", "DataFlowAnalysis", "DataFlowScanWarning", "DataInfiltrationRule", "DllImportRule", "EmbeddedArchivePayloadRule", "EmbeddedResourceScriptRule", "EncodedBlobSplittingRule", "EncodedStringLiteralRule", "EncodedStringPipelineRule", "ExceptionHandlerScanWarning", "HexStringRule", "MethodScanWarning", "MultiSignalDetection", "ObfuscatedReflectiveExecutionRule", "PersistenceRule", "ProcessStartRule", "ReflectionRule", "RegistryRule", "StaticRvaScanWarning", "SuspiciousAssemblyNameRule", "SuspiciousLocalVariableRule", "TypeScanWarning", "ValueResolutionBudget" });

    /// <summary>
    /// Creates an empty summary. Hosts may allowlist finding IDs they create themselves; each must
    /// be a short alphanumeric identifier so property names stay bounded and parseable.
    /// </summary>
    public ScanDiagnosticSummary(IEnumerable<string>? hostFindingIds = null)
    {
        _findingIds = new HashSet<string>(FindingIds, StringComparer.Ordinal);
        foreach (var id in hostFindingIds ?? Enumerable.Empty<string>())
        {
            if (id == null || id.Length is 0 or > 64 || !IsAsciiLetter(id[0]) || !id.All(c => IsAsciiLetter(c) || c is >= '0' and <= '9'))
                throw new ArgumentException("Host finding IDs must be 1-64 ASCII letters or digits, starting with a letter.", nameof(hostFindingIds));
            _findingIds.Add(id);
        }
    }

    private static bool IsAsciiLetter(char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z';

    private static readonly HashSet<string> Patterns = new(Enum.GetNames(typeof(DataFlowPattern)), StringComparer.Ordinal);

    private static readonly HashSet<string> FamilyIds = new(new[] { "family-blockchain-java-stager-v1", "family-dynamic-assembly-reflection-loader-v2", "family-embedded-resource-script-stager-v1", "family-encoded-powershell-tempcmd-stager-v1", "family-hex-remote-config-tempcmd-stager-v1", "family-obfuscated-metadata-loader-v2", "family-pawns-app-dropper-v1", "family-powershell-iwr-dlbat-v1", "family-remote-script-pipe-shell-v1", "family-remote-text-shell-exec-v1", "family-resource-shell32-tempcmd-v2", "family-webdownload-stage-exec-v3" }, StringComparer.Ordinal);

    private void Add(string key, int count = 1)
    {
        if (!_counts.ContainsKey(key) && _counts.Count >= MaxGroups && key != "diagnostic_overflow_count")
        { Add("diagnostic_overflow_count", count); return; }
        _counts.TryGetValue(key, out var previous);
        _counts[key] = (int)Math.Min(int.MaxValue, (long)previous + count);
    }

    /// <summary>Records one observation; repeated cached observations are not unique files or users.</summary>
    public void Observe(ScanResultDto result, bool cached = false, ScanTelemetryOutcome? outcome = null)
    {
        var verdict = (outcome ?? ScanTelemetrySummary.GetOutcome(result)).ToString();
        if (!Enum.IsDefined(typeof(ScanTelemetryOutcome), outcome ?? ScanTelemetrySummary.GetOutcome(result))) verdict = "Unknown";
        Add(cached ? "cached_result_count" : "fresh_result_count");
        Add(result.AnalysisCompleteness?.IsComplete == true ? "complete_result_count" : "incomplete_result_count");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var finding in result.Findings ?? new())
        {
            var rule = AllowedFindingId(finding.RuleId);
            var severity = finding.Severity is "Low" or "Medium" or "High" or "Critical" ? finding.Severity : "Unknown";
            var visibility = finding.Visibility is "Default" or "Advanced" ? finding.Visibility : "Unknown";
            var group = $"rule_{rule}_{severity}_{visibility}_{verdict}";
            Add(group + "_findings");
            if (seen.Add(group)) Add(group + "_results");
        }
        var families = result.ThreatFamilies ?? new();
        Add(families.Any(f => f.ExactHashMatch) ? "exact_match_result_count"
            : families.Count > 0 ? "family_match_result_count" : "no_family_match_result_count");
        foreach (var family in families.Select(f => FamilyIds.Contains(f.FamilyId) ? f.FamilyId : "other").Distinct())
            Add($"family_{family}_{verdict}_count");
        foreach (var flow in result.DataFlows ?? new())
        {
            var pattern = flow.Pattern != null && Patterns.Contains(flow.Pattern) ? flow.Pattern : "Unknown";
            Add($"flow_{pattern}_{verdict}_count");
        }
        // One count per result and finding ID that made analysis incomplete (for example MethodScanWarning).
        foreach (var source in (result.AnalysisCompleteness?.Reasons ?? new()).Select(r => AllowedFindingId(r.RuleId)).Distinct())
            Add($"incomplete_{source}_count");
    }

    private string AllowedFindingId(string? id) => id != null && _findingIds.Contains(id) ? id : "other";

    public ScanDiagnosticSummary Copy()
    {
        var copy = new ScanDiagnosticSummary();
        copy._findingIds.UnionWith(_findingIds);
        foreach (var item in _counts) copy._counts.Add(item.Key, item.Value);
        return copy;
    }

    /// <summary>Returns a detached snapshot containing only bounded, allowlisted keys and numeric values.</summary>
    public IReadOnlyDictionary<string, int> Snapshot() => new ReadOnlyDictionary<string, int>(new Dictionary<string, int>(_counts));
}
