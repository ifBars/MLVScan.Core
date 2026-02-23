using System.Xml.Linq;
using FluentAssertions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Integration;

/// <summary>
/// Integration tests that run false-positive samples with a game-aware assembly resolver.
/// This mirrors real MLVScan runtime behavior where game and loader assemblies are resolvable.
/// </summary>
public class FalsePositiveGameResolverScanTests
{
    private readonly ITestOutputHelper _output;

    public FalsePositiveGameResolverScanTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [SkippableFact]
    public void Scan_Il2CppFalsePositives_WithGameAssemblyResolver_ShouldNotProduceBlockingFindings()
    {
        var falsePositivesFolder = FindFalsePositivesFolder();
        Skip.If(falsePositivesFolder == null,
            "FALSE_POSITIVES folder not found. This test requires local sample assemblies.");

        var resolverPaths = FindGameResolverSearchPaths();
        Skip.If(resolverPaths.Count == 0,
            "Game assembly resolver paths not found. Set MLVSCAN_GAME_MANAGED_PATH/MLVSCAN_MELONLOADER_NET6_PATH or provide MLVScan/local.build.props.");

        var samples = new[]
        {
            "DeliveryCartPlus_v.1.0.dll",
            "S1APILoader.MelonLoader.dll"
        };

        var resolverProvider = new TestGameAssemblyResolverProvider(resolverPaths);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig(), resolverProvider);

        _output.WriteLine("Resolver search paths:");
        foreach (var path in resolverPaths)
        {
            _output.WriteLine($"- {path}");
        }

        var findingsBySample = new Dictionary<string, List<ScanFinding>>(StringComparer.OrdinalIgnoreCase);

        foreach (var sample in samples)
        {
            var assemblyPath = Path.Combine(falsePositivesFolder!, sample);
            Skip.IfNot(File.Exists(assemblyPath), $"Sample not found: {sample}");

            var findings = scanner.Scan(assemblyPath).ToList();
            findingsBySample[sample] = findings;

            _output.WriteLine($"=== {sample} ===");
            _output.WriteLine($"Total findings: {findings.Count}");
            foreach (var finding in findings)
            {
                _output.WriteLine($"[{finding.Severity}] {finding.RuleId} | {finding.Location}");
                _output.WriteLine($"  {finding.Description}");
            }

        }

        findingsBySample.Should().ContainKey("DeliveryCartPlus_v.1.0.dll");
        var deliveryFindings = findingsBySample["DeliveryCartPlus_v.1.0.dll"];

        deliveryFindings.Should().NotContain(f => f.Severity >= Severity.High,
            "DeliveryCartPlus should not emit blocking findings for Il2Cpp interop glue code when game assemblies resolve correctly");

        deliveryFindings.Should().NotContain(f => f.RuleId == "ReflectionRule",
            "legitimate UI/input interop reflection should not be treated as a bypass pattern");

        deliveryFindings.Should().NotContain(f => f.RuleId == "DllImportRule",
            "Il2CppInterop Runtime bridge calls to GameAssembly should not be treated as suspicious native imports");

        findingsBySample.Should().ContainKey("S1APILoader.MelonLoader.dll");
        var s1ApiLoaderFindings = findingsBySample["S1APILoader.MelonLoader.dll"];

        s1ApiLoaderFindings.Should().NotContain(f => f.Severity >= Severity.High,
            "S1APILoader is a known false-positive sample and should not be blocked when resolver context is available");
    }

    private static string? FindFalsePositivesFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var direct = Path.Combine(currentDir, "FALSE_POSITIVES");
            if (Directory.Exists(direct))
            {
                return direct;
            }

            var nested = Path.Combine(currentDir, "MLVScan.Core", "FALSE_POSITIVES");
            if (Directory.Exists(nested))
            {
                return nested;
            }

            currentDir = Directory.GetParent(currentDir)?.FullName;
        }

        return null;
    }

    private static List<string> FindGameResolverSearchPaths()
    {
        var paths = new List<string>();

        AddIfExists(paths, Environment.GetEnvironmentVariable("MLVSCAN_GAME_MANAGED_PATH"));
        AddIfExists(paths, Environment.GetEnvironmentVariable("MLVSCAN_MELONLOADER_NET6_PATH"));

        var localBuildPropsPath = FindSiblingMlvScanLocalBuildProps();
        if (localBuildPropsPath != null)
        {
            TryAddPathFromLocalBuildProps(paths, localBuildPropsPath, "GameManagedPath");
            TryAddPathFromLocalBuildProps(paths, localBuildPropsPath, "MelonLoaderPath");
        }

        return paths
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? FindSiblingMlvScanLocalBuildProps()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var candidate = Path.Combine(currentDir, "MLVScan", "local.build.props");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            currentDir = Directory.GetParent(currentDir)?.FullName;
        }

        return null;
    }

    private static void TryAddPathFromLocalBuildProps(List<string> paths, string localBuildPropsPath, string elementName)
    {
        try
        {
            var doc = XDocument.Load(localBuildPropsPath);
            var value = doc.Descendants(elementName).FirstOrDefault()?.Value?.Trim();
            AddIfExists(paths, value);
        }
        catch
        {
            // Ignore malformed local.build.props in tests.
        }
    }

    private static void AddIfExists(List<string> paths, string? maybePath)
    {
        if (!string.IsNullOrWhiteSpace(maybePath) && Directory.Exists(maybePath))
        {
            paths.Add(maybePath);
        }
    }

    private sealed class TestGameAssemblyResolverProvider : IAssemblyResolverProvider
    {
        private readonly IReadOnlyList<string> _searchPaths;

        public TestGameAssemblyResolverProvider(IReadOnlyList<string> searchPaths)
        {
            _searchPaths = searchPaths;
        }

        public IAssemblyResolver CreateResolver()
        {
            var resolver = new DefaultAssemblyResolver();
            foreach (var path in _searchPaths)
            {
                resolver.AddSearchDirectory(path);
            }

            return resolver;
        }
    }
}
