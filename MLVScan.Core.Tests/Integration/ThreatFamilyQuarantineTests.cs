using FluentAssertions;
using System.Text;
using MLVScan.Models.Dto;
using MLVScan.Services;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace MLVScan.Core.Tests.Integration;

public class ThreatFamilyQuarantineTests
{
    private static readonly HashSet<string> TrackedQuarantineSamples = new(StringComparer.OrdinalIgnoreCase)
    {
        "CustomTV_IL2CPP.dll.di",
        "DynamicOrders.dll.di",
        "EndlessGraffiti.dll.di",
        "FasterGrowth.dll.di",
        "LongLastingFertilizer.dll.di",
        "MelonLoaderMod55.dll.di",
        "MoreTrees.dll.di",
        "NoMoreTrash.dll.di",
        "NoPolice.dll.di",
        "RealRadio.dll.di",
        "RentalCars.dll.di",
        "S1API.Il2Cpp.MelonLoader.dll.di",
        "ScheduleIMoreNpcs.dll.di",
        "Skitching.dll.di",
        "StorageHub.dll.di",
        "UnlimitedGraffiti.dll.di",
        "vortex_backuprtilizer.dll.di"
    };

    private readonly ITestOutputHelper _output;
    private readonly string? _quarantineFolder;

    public ThreatFamilyQuarantineTests(ITestOutputHelper output)
    {
        _output = output;
        _quarantineFolder = FindQuarantineFolder();
    }

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di", "family-resource-shell32-tempcmd-v2")]
    [InlineData("CustomTV_IL2CPP.dll.di", "family-resource-shell32-tempcmd-v2")]
    [InlineData("RealRadio.dll.di", "family-resource-shell32-tempcmd-v2")]
    [InlineData("S1API.Il2Cpp.MelonLoader.dll.di", "family-resource-shell32-tempcmd-v2")]
    [InlineData("EndlessGraffiti.dll.di", "family-powershell-iwr-dlbat-v1")]
    [InlineData("FasterGrowth.dll.di", "family-powershell-iwr-dlbat-v1")]
    [InlineData("DynamicOrders.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("LongLastingFertilizer.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("MoreTrees.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("MelonLoaderMod55.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("NoPolice.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("RentalCars.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("ScheduleIMoreNpcs.dll.di", "family-obfuscated-metadata-loader-v1")]
    [InlineData("Skitching.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("StorageHub.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("UnlimitedGraffiti.dll.di", "family-webdownload-stage-exec-v2")]
    [InlineData("vortex_backuprtilizer.dll.di", "family-webdownload-stage-exec-v2")]
    public void Scan_QuarantineSample_ShouldEmitExpectedThreatFamily(string filename, string expectedFamilyId)
    {
        var path = GetSamplePath(filename);
        var assemblyBytes = File.ReadAllBytes(path);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        var dto = ScanResultMapper.ToDto(findings, Path.GetFileName(path), assemblyBytes, false);

        dto.ThreatFamilies.Should().NotBeNullOrEmpty();
        dto.ThreatFamilies!.Should().Contain(match => match.FamilyId == expectedFamilyId);
        dto.Disposition.Should().NotBeNull();
        dto.Disposition!.Classification.Should().Be("KnownThreat");

        WriteThreatFamilyLog(filename, dto.ThreatFamilies!, dto.Findings);
    }

    [SkippableTheory]
    [InlineData("DynamicOrders.dll.di", "webdownload-temp-ps1-hidden-powershell")]
    [InlineData("LongLastingFertilizer.dll.di", "webdownload-temp-ps1-hidden-powershell")]
    [InlineData("MoreTrees.dll.di", "webdownload-temp-batch-hidden-cmd")]
    [InlineData("MelonLoaderMod55.dll.di", "webdownload-temp-exe-direct-launch")]
    [InlineData("StorageHub.dll.di", "webdownload-temp-ps1-hidden-powershell")]
    public void Scan_QuarantineSample_ShouldEmitExpectedThreatVariant(string filename, string expectedVariantId)
    {
        var path = GetSamplePath(filename);
        var assemblyBytes = File.ReadAllBytes(path);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        var dto = ScanResultMapper.ToDto(findings, Path.GetFileName(path), assemblyBytes, false);

        dto.ThreatFamilies.Should().NotBeNullOrEmpty();
        dto.ThreatFamilies!.Should().Contain(match =>
            match.FamilyId == "family-webdownload-stage-exec-v2" &&
            match.VariantId == expectedVariantId);

        WriteThreatFamilyLog(filename, dto.ThreatFamilies!, dto.Findings);
    }

    [SkippableFact]
    public void Scan_ExactDuplicateSamples_ShouldShareBehaviorFamilyMatchWithoutHashShortcut()
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var realRadioPath = GetSamplePath("RealRadio.dll.di");
        var s1ApiPath = GetSamplePath("S1API.Il2Cpp.MelonLoader.dll.di");

        var realRadioDto = ScanResultMapper.ToDto(scanner.Scan(realRadioPath).ToList(), Path.GetFileName(realRadioPath), File.ReadAllBytes(realRadioPath), false);
        var s1ApiDto = ScanResultMapper.ToDto(scanner.Scan(s1ApiPath).ToList(), Path.GetFileName(s1ApiPath), File.ReadAllBytes(s1ApiPath), false);

        realRadioDto.Input.Sha256Hash.Should().Be(s1ApiDto.Input.Sha256Hash);
        realRadioDto.ThreatFamilies.Should().NotBeNullOrEmpty();
        s1ApiDto.ThreatFamilies.Should().NotBeNullOrEmpty();
        realRadioDto.Disposition.Should().NotBeNull();
        s1ApiDto.Disposition.Should().NotBeNull();
        realRadioDto.Disposition!.Classification.Should().Be("KnownThreat");
        s1ApiDto.Disposition!.Classification.Should().Be("KnownThreat");
        realRadioDto.ThreatFamilies!.First().FamilyId.Should().Be("family-resource-shell32-tempcmd-v2");
        s1ApiDto.ThreatFamilies!.First().FamilyId.Should().Be("family-resource-shell32-tempcmd-v2");
        realRadioDto.ThreatFamilies!.First().ExactHashMatch.Should().BeFalse();
        s1ApiDto.ThreatFamilies!.First().ExactHashMatch.Should().BeFalse();

        WriteThreatFamilyLog("RealRadio.dll.di", realRadioDto.ThreatFamilies!, realRadioDto.Findings);
        WriteThreatFamilyLog("S1API.Il2Cpp.MelonLoader.dll.di", s1ApiDto.ThreatFamilies!, s1ApiDto.Findings);
    }

    [SkippableFact]
    public void Scan_AllTopLevelQuarantineSamples_AreTrackedByThreatFamilyTests()
    {
        var actualSamples = GetTopLevelQuarantineSampleNames();

        actualSamples.Should().BeEquivalentTo(TrackedQuarantineSamples,
            "every top-level quarantine assembly should be covered by the threat-family quarantine suite");
    }

    private void WriteThreatFamilyLog(string filename, IReadOnlyList<ThreatFamilyDto> families, IReadOnlyList<FindingDto> findings)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"Sample: {filename}");
        builder.AppendLine($"Threat family matches: {families.Count}");

        foreach (var family in families)
        {
            builder.AppendLine($"- FamilyId: {family.FamilyId}");
            builder.AppendLine($"  DisplayName: {family.DisplayName}");
            builder.AppendLine($"  VariantId: {family.VariantId}");
            builder.AppendLine($"  MatchKind: {family.MatchKind}");
            builder.AppendLine($"  Confidence: {family.Confidence:P0}");
            builder.AppendLine($"  ExactHashMatch: {family.ExactHashMatch}");

            if (family.MatchedRules.Count > 0)
            {
                builder.AppendLine($"  MatchedRules: {string.Join(", ", family.MatchedRules)}");
            }

            if (family.AdvisorySlugs.Count > 0)
            {
                builder.AppendLine($"  AdvisorySlugs: {string.Join(", ", family.AdvisorySlugs)}");
            }

            if (family.Evidence.Count > 0)
            {
                builder.AppendLine("  Evidence:");
                foreach (var evidence in family.Evidence)
                {
                    builder.AppendLine($"    - {evidence.Kind}: {evidence.Value}");
                }
            }
        }

        if (findings.Count > 0)
        {
            builder.AppendLine("Findings:");
            foreach (var finding in findings.OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId).ThenBy(f => f.Location))
            {
                builder.AppendLine($"- [{finding.Severity}] {finding.RuleId} @ {finding.Location}");
                builder.AppendLine($"  {finding.Description}");
            }
        }

        _output.WriteLine(builder.ToString().TrimEnd());
    }

    private string GetSamplePath(string filename)
    {
        Skip.If(_quarantineFolder == null, "QUARANTINE folder not found. This test requires malware samples which are not available in CI.");

        var path = Path.Combine(_quarantineFolder!, filename);
        Skip.IfNot(File.Exists(path), $"Sample {filename} not found in QUARANTINE folder.");
        return path;
    }

    private IReadOnlyList<string> GetTopLevelQuarantineSampleNames()
    {
        Skip.If(_quarantineFolder == null,
            "QUARANTINE folder not found. This test requires malware samples which are not available in CI.");

        return Directory
            .EnumerateFiles(_quarantineFolder!, "*", SearchOption.TopDirectoryOnly)
            .Where(path =>
                path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".dll.di", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".exe.di", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".winmd", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".winmd.di", StringComparison.OrdinalIgnoreCase))
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? FindQuarantineFolder()
    {
        var currentDir = Directory.GetCurrentDirectory();

        while (currentDir != null)
        {
            var quarantinePath = Path.Combine(currentDir, "QUARANTINE");
            if (Directory.Exists(quarantinePath))
            {
                return quarantinePath;
            }

            var mlvScanCorePath = Path.Combine(currentDir, "MLVScan.Core", "QUARANTINE");
            if (Directory.Exists(mlvScanCorePath))
            {
                return mlvScanCorePath;
            }

            currentDir = Directory.GetParent(currentDir)?.FullName;
        }

        return null;
    }
}
