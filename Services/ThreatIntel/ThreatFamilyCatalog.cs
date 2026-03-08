using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

internal static class ThreatFamilyCatalog
{
    private static readonly StringComparer Comparer = StringComparer.OrdinalIgnoreCase;

    public static IReadOnlyList<ThreatFamilyDefinition> Families { get; } =
    [
        new ThreatFamilyDefinition
        {
            FamilyId = "family-resource-shell32-tempcmd-v1",
            DisplayName = "Embedded resource ShellExecute temp CMD dropper",
            Summary = "Extracts an embedded resource to a temporary .cmd file and executes it hidden via ShellExecuteEx.",
            AdvisorySlugs =
            [
                "2025-12-malware-customtv-il2cpp",
                "2025-12-malware-nomoretrash",
                "2025-12-malware-realandwaitingtimeonfire"
            ],
            ExactSampleHashes =
            [
                "2f8f2b41ab22ebc9ae69f5938a4887c9bfb2f78b984e5be7789c6a67a6d54cb1",
                "a090d5cf0db9100fac2c7e30c5a8609b1d128d99c2402dbe3bfadfac4800f3ea",
                "994124671953a3b08d805e5b402719760129a7d19678d85e432dcbac179d0224"
            ],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "resource-shell32-tempcmd-hidden",
                    DisplayName = "Embedded resource -> temp .cmd -> hidden ShellExecuteEx",
                    Summary = "Embedded payload materialized to a temporary .cmd file and launched with hidden native shell execution.",
                    Confidence = 0.99,
                    Matcher = MatchEmbeddedShellExecuteTempCmd
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-powershell-iwr-dlbat-v1",
            DisplayName = "PowerShell IWR temp batch downloader",
            Summary = "Launches hidden PowerShell to download a batch file into TEMP, run it, then remove it.",
            AdvisorySlugs = ["2026-01-malware-endlessgraffiti"],
            ExactSampleHashes =
            [
                "6c15802426e22e8a0376af1be8bb5caebb5b2e2f4f06a8e7944c80c647a548e6",
                "5e3bb51b52725c2f0f2a4d9eb4ecbadbd169aec0e0ac474d9127f205da4e3b72"
            ],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "powershell-iwr-dlbat-cleanup",
                    DisplayName = "Hidden PowerShell IWR temp batch chain",
                    Summary = "Uses hidden PowerShell with Invoke-WebRequest to stage dl.bat in TEMP, execute it, sleep, and delete it.",
                    Confidence = 0.98,
                    Matcher = MatchPowerShellIwrDlBat
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-webclient-stage-exec-v1",
            DisplayName = "WebClient staged payload executor",
            Summary = "Downloads a payload to TEMP with WebClient and then executes it via hidden or shell-assisted process launch.",
            AdvisorySlugs = ["2026-02-malware-moretrees"],
            ExactSampleHashes =
            [
                "6cb8afc1bf0e504d6b95bc05a36142f81f42b200c178e0ce6988bdf1a2c6ec0e",
                "b5133362b4327a1bfecd45fe651b841372a1394fcbb6f8906a6724990b50e8a4"
            ],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "webclient-temp-download-execute",
                    DisplayName = "WebClient download -> temp stage -> hidden execute",
                    Summary = "Downloads a payload with WebClient, stages it in TEMP, then executes it through cmd.exe or direct Process.Start.",
                    Confidence = 0.96,
                    Matcher = MatchWebClientStageExecute
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-obfuscated-metadata-loader-v1",
            DisplayName = "Obfuscated metadata-backed loader",
            Summary = "Uses encoded numeric strings and assembly metadata to reconstruct a hidden command launcher at runtime.",
            AdvisorySlugs = ["2025-11-malware-scheduleimorenpcs"],
            ExactSampleHashes = ["b6ea902d5eda7bb210c31715f2c90a4b249ce8b6c1747d571028719d025d59db"],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "numeric-metadata-hidden-loader",
                    DisplayName = "Numeric decode + metadata hidden loader",
                    Summary = "Reconstructs hidden cmd.exe/powershell.exe launcher details from numeric-encoded strings and metadata attributes.",
                    Confidence = 0.95,
                    Matcher = MatchObfuscatedMetadataLoader
                }
            ]
        }
    ];

    private static ThreatFamilyVariantMatch? MatchEmbeddedShellExecuteTempCmd(IReadOnlyList<ScanFinding> findings)
    {
        var dllImportFinding = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "DllImportRule") &&
            ContainsAll(f.Description, "ShellExecuteEx", ".cmd", "%TEMP%", "embedded resource"));

        if (dllImportFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = ["DllImportRule"],
            Evidence =
            [
                Evidence("rule", "DllImportRule"),
                Evidence("api", "ShellExecuteEx"),
                Evidence("staging", "embedded resource -> %TEMP%/<guid>.cmd"),
                Evidence("execution", "hidden shell execution")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchPowerShellIwrDlBat(IReadOnlyList<ScanFinding> findings)
    {
        var processFinding = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "ProcessStartRule") &&
            ContainsAll(f.Description, "powershell.exe", "iwr", "dl.bat", "Start-Sleep", "Remove-Item"));

        if (processFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = ["ProcessStartRule"],
            Evidence =
            [
                Evidence("rule", "ProcessStartRule"),
                Evidence("launcher", "powershell.exe"),
                Evidence("download", "Invoke-WebRequest / iwr"),
                Evidence("staging", "%TEMP%/dl.bat"),
                Evidence("cleanup", "sleep then remove temp batch")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchWebClientStageExecute(IReadOnlyList<ScanFinding> findings)
    {
        var networkFinding = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "DataInfiltrationRule") &&
            ContainsAny(f.Description, "DownloadFileTaskAsync", "malicious domain", "payload delivery"));
        var executionFinding = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "ProcessStartRule") &&
            (ContainsAll(f.Description, "Downloads data from network", "executes as a program") ||
             ContainsAll(f.Description, "cmd.exe", "%TEMP%/d.bat") ||
             ContainsAny(f.Description, "WorkingDirectory=Temp", "UseShellExecute=true")));

        if (networkFinding == null || executionFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = new[] { "DataInfiltrationRule", "ProcessStartRule" },
            Evidence =
            [
                Evidence("rule", "DataInfiltrationRule"),
                Evidence("rule", "ProcessStartRule"),
                Evidence("download", "WebClient download to TEMP"),
                Evidence("execution", "staged payload execution from TEMP")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchObfuscatedMetadataLoader(IReadOnlyList<ScanFinding> findings)
    {
        var encodedLiteral = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "EncodedStringLiteralRule") &&
            ContainsAll(f.Description, "ProcessStartInfo", "powershell.exe", "Invoke-WebRequest"));
        var reflectionFinding = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "ReflectionRule") &&
            ContainsAll(f.Description, "AssemblyMetadataAttribute"));
        var pipelineFinding = findings.FirstOrDefault(f =>
            Comparer.Equals(f.RuleId, "EncodedStringPipelineRule"));

        if (encodedLiteral == null || reflectionFinding == null || pipelineFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = new[] { "EncodedStringLiteralRule", "EncodedStringPipelineRule", "ReflectionRule" },
            Evidence =
            [
                Evidence("rule", "EncodedStringLiteralRule"),
                Evidence("rule", "EncodedStringPipelineRule"),
                Evidence("rule", "ReflectionRule"),
                Evidence("obfuscation", "numeric string decode pipeline"),
                Evidence("payload-source", "assembly metadata value"),
                Evidence("execution", "hidden cmd.exe / powershell.exe loader")
            ]
        };
    }

    private static ThreatFamilyEvidence Evidence(string kind, string value)
    {
        return new ThreatFamilyEvidence { Kind = kind, Value = value };
    }

    private static bool ContainsAll(string value, params string[] needles)
    {
        return needles.All(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsAny(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }
}
