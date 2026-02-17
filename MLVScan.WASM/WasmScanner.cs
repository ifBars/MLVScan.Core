using System.Text.Json;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Services;

namespace MLVScan.WASM;

/// <summary>
/// Main WASM API for scanning assemblies in the browser.
/// This is the primary entry point for JavaScript/TypeScript code.
/// </summary>
public class WasmScanner
{
    private readonly ScanConfig _config;

    /// <summary>
    /// Creates a new WasmScanner with the specified configuration.
    /// </summary>
    /// <param name="config">Optional scan configuration. Uses defaults if not specified.</param>
    public WasmScanner(ScanConfig? config = null)
    {
        _config = config ?? new ScanConfig
        {
            // WASM-friendly defaults
            EnableAutoScan = false,
            EnableAutoDisable = false,
            DeveloperMode = false,
            DumpFullIlReports = false
        };
    }

    /// <summary>
    /// Scans a single assembly from raw bytes.
    /// This is the primary method for WASM usage.
    /// </summary>
    /// <param name="assemblyBytes">Raw bytes of the .dll file.</param>
    /// <param name="fileName">Original file name (for reporting).</param>
    /// <returns>JSON string containing the scan results following schema v1.</returns>
    public string ScanAssembly(byte[] assemblyBytes, string fileName)
    {
        if (assemblyBytes == null || assemblyBytes.Length == 0)
        {
            throw new ArgumentException("Assembly bytes cannot be null or empty", nameof(assemblyBytes));
        }

        if (string.IsNullOrWhiteSpace(fileName))
        {
            fileName = "unknown.dll";
        }

        try
        {
            // Create scanner with default rules
            var rules = RuleFactory.CreateDefaultRules();
            var scanner = new AssemblyScanner(rules, _config);

            // Scan using stream-based API (WASM-friendly)
            using var stream = new MemoryStream(assemblyBytes);
            var findings = scanner.Scan(stream, fileName);

            // Convert to DTO using WASM-specific options
            var options = ScanResultOptions.ForWasm(_config.DeveloperMode);
            options.PlatformVersion = GetVersion();
            var result = ScanResultMapper.ToDto(findings, fileName, assemblyBytes, options);

            // Serialize to JSON using Source Generator
            return JsonSerializer.Serialize(result, WasmJsonContext.Default.ScanResultDto);
        }
        catch (Exception ex)
        {
            // Return error as JSON
            var errorResult = new ScanResultDto
            {
                Metadata = new ScanMetadataDto
                {
                    PlatformVersion = GetVersion(),
                    Platform = "wasm"
                },
                Input = new ScanInputDto
                {
                    FileName = fileName,
                    SizeBytes = assemblyBytes.Length
                },
                Summary = new ScanSummaryDto
                {
                    TotalFindings = 1
                },
                Findings = new List<FindingDto>
                {
                    new FindingDto
                    {
                        RuleId = "ScanError",
                        Description = $"Failed to scan assembly: {ex.Message}",
                        Severity = "Low",
                        Location = "Assembly scanning"
                    }
                }
            };

            return JsonSerializer.Serialize(errorResult, WasmJsonContext.Default.ScanResultDto);
        }
    }

    /// <summary>
    /// Scans an assembly with custom configuration (advanced usage).
    /// </summary>
    /// <param name="assemblyBytes">Raw bytes of the .dll file.</param>
    /// <param name="fileName">Original file name.</param>
    /// <param name="configJson">JSON string containing ScanConfig.</param>
    /// <returns>JSON string containing the scan results.</returns>
    public string ScanAssemblyWithConfig(byte[] assemblyBytes, string fileName, string configJson)
    {
        ScanConfig config;
        try
        {
            config = JsonSerializer.Deserialize(configJson, WasmJsonContext.Default.ScanConfig) ?? new ScanConfig();
        }
        catch
        {
            config = new ScanConfig();
        }

        var scanner = new WasmScanner(config);
        return scanner.ScanAssembly(assemblyBytes, fileName);
    }

    /// <summary>
    /// Gets the scanner version.
    /// </summary>
    /// <returns>Version string.</returns>
    public static string GetVersion()
    {
        return $"{MLVScanVersions.CoreVersion}-wasm";
    }

    /// <summary>
    /// Gets the supported schema version.
    /// </summary>
    /// <returns>Schema version string (semver).</returns>
    public static string GetSchemaVersion()
    {
        return MLVScanVersions.SchemaVersion;
    }
}
