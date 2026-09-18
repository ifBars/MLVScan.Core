using MLVScan.Models;

namespace MLVScan.Services.ThreatIntel;

internal static partial class ThreatFamilyCatalog
{
    private static ThreatFamilyDefinition CreatePawnsAppDropperFamily()
    {
        return new ThreatFamilyDefinition
        {
            FamilyId = "family-pawns-app-dropper-v1",
            DisplayName = "Pawns.app credential-seeded autorun dropper",
            Summary = "Downloads and extracts a per-user archive payload, seeds application state, installs Windows autorun persistence, and launches the payload hidden.",
            AdvisorySlugs = ["2026-09-malware-pawns-app-dropper"],
            ExactSampleHashes =
            [
                "4f1f3bc0028d9059939c9218dc6d975974b656f4c540ee83a51a7a39278c9c8b",
                "9dcc2c192b1b5e8bb9e9db99e03f58a385c4aff0bd117c8b60d93ff482d67516",
                "7b96c506a062bc7a8deb99fb8429c7b72db5a7fbe86f85b46584fc7f4e3d48f7"
            ],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "archive-userprofile-runkey-hidden-launch",
                    DisplayName = "User-profile archive -> Run key -> hidden launch",
                    Summary = "Stages a downloaded archive under the user profile, establishes CurrentVersion Run persistence, and starts the installed executable with hidden-process settings.",
                    Confidence = 0.98,
                    Matcher = MatchArchiveUserProfileRunKeyHiddenLaunch
                }
            ]
        };
    }

    private static ThreatFamilyDefinition CreateBlockchainJavaStagerFamily()
    {
        return new ThreatFamilyDefinition
        {
            FamilyId = "family-blockchain-java-stager-v1",
            DisplayName = "Blockchain-resolved Java payload stager",
            Summary = "Uses blockchain RPC service discovery and fixed-key decoding to retrieve or embed a Java archive, then executes it through a concealed Java child process.",
            AdvisorySlugs = ["2026-09-malware-blockchain-java-stager"],
            ExactSampleHashes =
            [
                "3a6a9292767af6c4df205c766cda0e811b8ac12a61a7e2aa5c88d08a7a8de144"
            ],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "evm-resolved-jar-runas",
                    DisplayName = "EVM-resolved JAR -> hidden elevated Java",
                    Summary = "Resolves service infrastructure through EVM RPC calls, decodes concealed runtime strings, writes a JAR payload, and launches Java hidden or elevated.",
                    Confidence = 0.99,
                    Matcher = MatchEvmResolvedJarRunAs
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "embedded-jar-stdin-bootstrap",
                    DisplayName = "Embedded JAR -> redirected Java bootstrap",
                    Summary = "Materializes an embedded JAR bootstrap and transfers a second payload to a concealed Java process through redirected standard input.",
                    Confidence = 0.97,
                    Matcher = MatchEmbeddedJarStdinBootstrap
                }
            ]
        };
    }

    private static ThreatFamilyDefinition CreateRemoteTextShellExecutionFamily()
    {
        return new ThreatFamilyDefinition
        {
            FamilyId = "family-remote-text-shell-exec-v1",
            DisplayName = "Remote text hidden shell executor",
            Summary = "Retrieves remote text, parses or rewrites it into runtime-computed command arguments, and executes the result through a concealed system shell.",
            AdvisorySlugs = ["2026-09-malware-autobarncoopdoor"],
            ExactSampleHashes =
            [
                "fe8c78fe1bde7e5edf114f22d554d2786058e0dbf8d697123714da0484cded64"
            ],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "remote-text-hidden-shell-command",
                    DisplayName = "Remote text -> hidden shell command",
                    Summary = "Downloads text and transforms it into dynamic arguments for a hidden PowerShell, CMD, Windows Script Host, or MSHTA process in the same method.",
                    Confidence = 0.98,
                    Matcher = MatchRemoteTextHiddenShellCommand
                }
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchArchiveUserProfileRunKeyHiddenLaunch(
        ThreatFamilyAnalysisContext context)
    {
        var coordinator = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "CoordinatedPayloadDeliveryRule", StringComparison.Ordinal) &&
            FindingContainsAll(finding, "archive payload delivery", "autorun persistence", "hidden executable launch"));
        var registry = context.FindFinding("RegistryRule");
        var process = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            FindingContainsAll(finding, "--hidden", "CreateNoWindow=true", "WindowStyle=Hidden"));
        if (coordinator == null || registry == null || process == null)
        {
            return null;
        }

        var download = context.FindFinding("DataInfiltrationRule");
        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "CoordinatedPayloadDeliveryRule",
                "DataInfiltrationRule",
                "RegistryRule",
                "ProcessStartRule"),
            Evidence =
            [
                context.CreateRuleEvidence("behavior-chain", "archive -> user profile -> autorun -> hidden launch", coordinator),
                context.CreateRuleEvidence("download", "remote archive acquisition", download),
                context.CreateRuleEvidence("persistence", "CurrentVersion Run registry write", registry),
                context.CreateRuleEvidence("execution", "concealed executable launch with --hidden", process)
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchRemoteTextHiddenShellCommand(
        ThreatFamilyAnalysisContext context)
    {
        var coordinator = context.FindFinding(
            "CoordinatedPayloadDeliveryRule",
            "remote text retrieval",
            "hidden shell command");
        var process = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            FindingContainsAny(finding, "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe") &&
            FindingContainsAny(finding, "CreateNoWindow=true", "WindowStyle=Hidden", "UseShellExecute=true") &&
            FindingContainsAny(finding, "<dynamic", "<arg"));
        if (coordinator == null || process == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "CoordinatedPayloadDeliveryRule",
                "ProcessStartRule"),
            Evidence =
            [
                context.CreateRuleEvidence("behavior-chain", "remote text transformed into a runtime-computed shell command", coordinator),
                context.CreateRuleEvidence("execution", "concealed system shell with dynamic arguments", process)
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchEvmResolvedJarRunAs(ThreatFamilyAnalysisContext context)
    {
        var coordinator = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "CoordinatedPayloadDeliveryRule", StringComparison.Ordinal) &&
            FindingContainsAll(finding, "blockchain-resolved Java archive stager", "EVM RPC", "JAR staging"));
        var decoder = context.FindFinding("EncodedStringPipelineRule", "fixed-key", "XOR");
        var process = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            (FindingContainsAll(finding, "WindowStyle=Hidden") ||
             FindingContainsAll(finding, "Redirected I/O")));
        if (coordinator == null || decoder == null || process == null)
        {
            return null;
        }

        var embeddedArchive = context.FindFinding("EmbeddedArchivePayloadRule");
        var exfiltration = context.FindFinding("DataExfiltrationRule");
        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "CoordinatedPayloadDeliveryRule",
                "EncodedStringPipelineRule",
                "EmbeddedArchivePayloadRule",
                "DataExfiltrationRule",
                "ProcessStartRule"),
            Evidence =
            [
                context.CreateRuleEvidence("behavior-chain", "EVM-resolved JAR staging and concealed Java execution", coordinator),
                context.CreateRuleEvidence("transform", "fixed-key XOR decoded runtime and network strings", decoder),
                context.CreateRuleEvidence("embedded-payload", "embedded ZIP/JAR bootstrap", embeddedArchive),
                context.CreateRuleEvidence("outbound-channel", "runtime-computed transformed network send", exfiltration),
                context.CreateRuleEvidence("execution", "hidden/elevated Java process", process)
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchEmbeddedJarStdinBootstrap(ThreatFamilyAnalysisContext context)
    {
        var embeddedArchive = context.FindFinding("EmbeddedArchivePayloadRule");
        var coordinator = context.FindFinding("CoordinatedPayloadDeliveryRule", "Java archive stager");
        var process = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            FindingContainsAll(finding, "Redirected I/O"));
        if (embeddedArchive == null || coordinator == null || process == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "CoordinatedPayloadDeliveryRule",
                "EmbeddedArchivePayloadRule",
                "ProcessStartRule"),
            Evidence =
            [
                context.CreateRuleEvidence("embedded-payload", "embedded ZIP/JAR bootstrap", embeddedArchive),
                context.CreateRuleEvidence("behavior-chain", "archive materialization and Java execution", coordinator),
                context.CreateRuleEvidence("execution", "redirected child-process payload handoff", process)
            ]
        };
    }
}
