using FluentAssertions;
using MLVScan.Services;
using MLVScan.Services.ThreatIntel;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

public class NewSampleThreatFamilyTests
{
    [SkippableTheory]
    [InlineData(@"AutoBarnCoopDoor\AutoBarnCoopDoor.dll.di", "family-remote-text-shell-exec-v1", "remote-text-hidden-shell-command")]
    [InlineData(@"BetterPatrols1\bin\Win64_Shipping_Client\BetterPatrols.dll.di", "family-pawns-app-dropper-v1", "archive-userprofile-runkey-hidden-launch")]
    [InlineData(@"BetterPatrols2\bin\Win64_Shipping_Client\BetterPatrols.dll.di", "family-pawns-app-dropper-v1", "archive-userprofile-runkey-hidden-launch")]
    [InlineData(@"BloodAndBanners\bin\Win64_Shipping_Client\BloodAndBanners.Core.dll.di", "family-pawns-app-dropper-v1", "archive-userprofile-runkey-hidden-launch")]
    [InlineData(@"Meowtopia\Meowtopia.dll.di", "family-webdownload-stage-exec-v3", "webdownload-temp-hidden-launch-generic")]
    [InlineData(@"Polygamy\ValleyPolygamy.dll.di", "family-blockchain-java-stager-v1", "evm-resolved-jar-runas")]
    [InlineData(@"SunriseFurrowCoach\SunriseFurrowCoach.dll.di", "family-blockchain-java-stager-v1", "evm-resolved-jar-runas")]
    public void Scan_NewMaliciousSample_WithoutHashEvidence_ShouldMatchBehaviorFamily(
        string relativePath,
        string expectedFamilyId,
        string expectedVariantId)
    {
        string path = GetSamplePath(relativePath);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        var matches = new ThreatFamilyClassifier().Classify(findings, sha256Hash: null);

        matches.Should().Contain(match =>
                match.FamilyId == expectedFamilyId &&
                match.VariantId == expectedVariantId &&
                !match.ExactHashMatch,
            "the confirmed sample must be recognized from behavior before an exact hash is added");
    }

    [SkippableFact]
    public void Scan_BloodAndBannersWrapper_WithoutCoreCompanion_ShouldRemainClean()
    {
        string path = GetSamplePath(@"BloodAndBanners\bin\Win64_Shipping_Client\BloodAndBanners.dll.di");
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(path).ToList();
        var matches = new ThreatFamilyClassifier().Classify(findings, sha256Hash: null);

        findings.Should().BeEmpty("the wrapper has no retained malicious behavior in isolation");
        matches.Should().BeEmpty("the malicious behavior resides in BloodAndBanners.Core.dll");
    }

    [SkippableTheory]
    [InlineData(@"AutoBarnCoopDoor\AutoBarnCoopDoor.dll.di", "family-remote-text-shell-exec-v1")]
    [InlineData(@"BetterPatrols1\bin\Win64_Shipping_Client\BetterPatrols.dll.di", "family-pawns-app-dropper-v1")]
    [InlineData(@"BetterPatrols2\bin\Win64_Shipping_Client\BetterPatrols.dll.di", "family-pawns-app-dropper-v1")]
    [InlineData(@"BloodAndBanners\bin\Win64_Shipping_Client\BloodAndBanners.Core.dll.di", "family-pawns-app-dropper-v1")]
    [InlineData(@"Meowtopia\Meowtopia.dll.di", "family-webdownload-stage-exec-v3")]
    [InlineData(@"Polygamy\ValleyPolygamy.dll.di", "family-blockchain-java-stager-v1")]
    [InlineData(@"SunriseFurrowCoach\SunriseFurrowCoach.dll.di", "family-blockchain-java-stager-v1")]
    public void Scan_NewMaliciousSample_WithHashEvidence_ShouldBeExactKnownThreat(
        string relativePath,
        string expectedFamilyId)
    {
        string path = GetSamplePath(relativePath);
        byte[] bytes = File.ReadAllBytes(path);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var dto = ScanResultMapper.ToDto(scanner.Scan(path).ToList(), Path.GetFileName(path), bytes, false);

        dto.ThreatFamilies.Should().Contain(match =>
            match.FamilyId == expectedFamilyId &&
            match.VariantId == "exact-known-sample" &&
            match.ExactHashMatch);
        dto.Disposition.Should().NotBeNull();
        dto.Disposition!.Classification.Should().Be("KnownThreat");
    }

    private static string GetSamplePath(string relativePath)
    {
        string? current = Directory.GetCurrentDirectory();

        while (current != null)
        {
            string candidate = Path.Combine(current, "QUARANTINE", relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = Directory.GetParent(current)?.FullName;
        }

        Skip.If(true, $"Static sample not found in QUARANTINE: {relativePath}");
        return string.Empty;
    }
}
