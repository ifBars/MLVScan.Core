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
    private readonly ITestOutputHelper _output;
    private readonly string? _quarantineFolder;

    public ThreatFamilyQuarantineTests(ITestOutputHelper output)
    {
        _output = output;
        _quarantineFolder = FindQuarantineFolder();
    }

    [SkippableTheory]
    [InlineData("NoMoreTrash.dll.di", "family-resource-shell32-tempcmd-v1")]
    [InlineData("CustomTV_IL2CPP.dll.di", "family-resource-shell32-tempcmd-v1")]
    [InlineData("RealRadio.dll.di", "family-resource-shell32-tempcmd-v1")]
    [InlineData("S1API.Il2Cpp.MelonLoader.dll.di", "family-resource-shell32-tempcmd-v1")]
    [InlineData("EndlessGraffiti.dll.di", "family-powershell-iwr-dlbat-v1")]
    [InlineData("FasterGrowth.dll.di", "family-powershell-iwr-dlbat-v1")]
    [InlineData("MoreTrees.dll.di", "family-webclient-stage-exec-v1")]
    [InlineData("MelonLoaderMod55.dll.di", "family-webclient-stage-exec-v1")]
    [InlineData("ScheduleIMoreNpcs.dll", "family-obfuscated-metadata-loader-v1")]
    public void Scan_QuarantineSample_ShouldEmitExpectedThreatFamily(string filename, string expectedFamilyId)
    {
        var path = GetSamplePath(filename);
        var assemblyBytes = File.ReadAllBytes(path);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        var dto = ScanResultMapper.ToDto(findings, Path.GetFileName(path), assemblyBytes, false);

        dto.ThreatFamilies.Should().NotBeNullOrEmpty();
        dto.ThreatFamilies!.Should().Contain(match => match.FamilyId == expectedFamilyId);

        WriteThreatFamilyLog(filename, dto.ThreatFamilies!, dto.Findings);
    }

    [SkippableFact]
    public void Scan_ExactDuplicateSamples_ShouldShareExactHashFamilyMatch()
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var realRadioPath = GetSamplePath("RealRadio.dll.di");
        var s1ApiPath = GetSamplePath("S1API.Il2Cpp.MelonLoader.dll.di");

        var realRadioDto = ScanResultMapper.ToDto(scanner.Scan(realRadioPath).ToList(), Path.GetFileName(realRadioPath), File.ReadAllBytes(realRadioPath), false);
        var s1ApiDto = ScanResultMapper.ToDto(scanner.Scan(s1ApiPath).ToList(), Path.GetFileName(s1ApiPath), File.ReadAllBytes(s1ApiPath), false);

        realRadioDto.Input.Sha256Hash.Should().Be(s1ApiDto.Input.Sha256Hash);
        realRadioDto.ThreatFamilies.Should().NotBeNullOrEmpty();
        s1ApiDto.ThreatFamilies.Should().NotBeNullOrEmpty();
        realRadioDto.ThreatFamilies!.First().ExactHashMatch.Should().BeTrue();
        s1ApiDto.ThreatFamilies!.First().ExactHashMatch.Should().BeTrue();

        WriteThreatFamilyLog("RealRadio.dll.di", realRadioDto.ThreatFamilies!, realRadioDto.Findings);
        WriteThreatFamilyLog("S1API.Il2Cpp.MelonLoader.dll.di", s1ApiDto.ThreatFamilies!, s1ApiDto.Findings);
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
