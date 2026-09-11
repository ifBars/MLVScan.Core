using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services.ThreatIntel;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class NewThreatFamilyClassifierTests
{
    [Fact]
    public void Classify_ArchiveAutorunHiddenLaunch_ReturnsPawnsBehaviorFamily()
    {
        var findings = new[]
        {
            Finding(
                "CoordinatedPayloadDeliveryRule",
                "Detected coordinated archive payload delivery to a user-profile location, Windows autorun persistence, and hidden executable launch across sibling methods."),
            Finding("DataInfiltrationRule", "Suspicious payload URL is passed to a local download helper."),
            Finding("RegistryRule", "Detected Windows Registry write operation."),
            Finding(
                "ProcessStartRule",
                "Arguments: --hidden [Evasion: CreateNoWindow=true, WindowStyle=Hidden]")
        };

        var matches = new ThreatFamilyClassifier().Classify(findings, sha256Hash: null);

        matches.Should().ContainSingle(match =>
            match.FamilyId == "family-pawns-app-dropper-v1" &&
            match.VariantId == "archive-userprofile-runkey-hidden-launch" &&
            match.MatchKind == ThreatMatchKind.BehaviorVariant &&
            !match.ExactHashMatch);
    }

    [Fact]
    public void Classify_ArchiveUpdaterWithoutAutorun_DoesNotReturnPawnsFamily()
    {
        var findings = new[]
        {
            Finding("DataInfiltrationRule", "Downloaded update.zip from a release endpoint."),
            Finding("ProcessStartRule", "Target: updater.exe. CreateNoWindow=true")
        };

        var matches = new ThreatFamilyClassifier().Classify(findings, sha256Hash: null);

        matches.Should().NotContain(match => match.FamilyId == "family-pawns-app-dropper-v1");
    }

    [Fact]
    public void Classify_EvmResolvedConcealedJavaStager_ReturnsBehaviorFamily()
    {
        var findings = new[]
        {
            Finding(
                "CoordinatedPayloadDeliveryRule",
                "Detected coordinated blockchain-resolved Java archive stager: EVM RPC service discovery, fixed-key string decoding, JAR staging, and hidden or elevated Java execution."),
            Finding(
                "EncodedStringPipelineRule",
                "Detected fixed-key byte-array XOR string reconstruction concealing network indicators."),
            Finding("EmbeddedArchivePayloadRule", "Detected embedded ZIP/JAR archive payload."),
            Finding("DataExfiltrationRule", "Detected transformed host data sent to a runtime-computed endpoint."),
            Finding("ProcessStartRule", "UseShellExecute=true, WindowStyle=Hidden")
        };

        var matches = new ThreatFamilyClassifier().Classify(findings, sha256Hash: null);

        matches.Should().ContainSingle(match =>
            match.FamilyId == "family-blockchain-java-stager-v1" &&
            match.VariantId == "evm-resolved-jar-runas" &&
            match.MatchKind == ThreatMatchKind.BehaviorVariant &&
            !match.ExactHashMatch);
    }

    [Fact]
    public void Classify_OrdinaryRpcJavaClient_DoesNotReturnBlockchainJavaFamily()
    {
        var findings = new[]
        {
            Finding("ProcessStartRule", "Target: java.exe. Arguments: -cp client.jar"),
            Finding("DataInfiltrationRule", "Read-only network operation to API endpoint.")
        };

        var matches = new ThreatFamilyClassifier().Classify(findings, sha256Hash: null);

        matches.Should().NotContain(match => match.FamilyId == "family-blockchain-java-stager-v1");
    }

    [Theory]
    [InlineData("4f1f3bc0028d9059939c9218dc6d975974b656f4c540ee83a51a7a39278c9c8b", "family-pawns-app-dropper-v1")]
    [InlineData("9dcc2c192b1b5e8bb9e9db99e03f58a385c4aff0bd117c8b60d93ff482d67516", "family-pawns-app-dropper-v1")]
    [InlineData("7b96c506a062bc7a8deb99fb8429c7b72db5a7fbe86f85b46584fc7f4e3d48f7", "family-pawns-app-dropper-v1")]
    [InlineData("3a6a9292767af6c4df205c766cda0e811b8ac12a61a7e2aa5c88d08a7a8de144", "family-blockchain-java-stager-v1")]
    public void Classify_ConfirmedHash_ReturnsExactKnownThreat(string hash, string expectedFamily)
    {
        var classifier = new ThreatFamilyClassifier();

        var matches = classifier.Classify([], hash);
        var disposition = new ThreatDispositionClassifier().Classify([], matches);

        matches.Should().ContainSingle(match =>
            match.FamilyId == expectedFamily &&
            match.MatchKind == ThreatMatchKind.ExactSampleHash &&
            match.ExactHashMatch);
        disposition.Classification.Should().Be(ThreatDispositionClassification.KnownThreat);
    }

    private static ScanFinding Finding(string ruleId, string description)
    {
        return new ScanFinding("Test.Sample", description, Severity.High, description)
        {
            RuleId = ruleId
        };
    }
}
