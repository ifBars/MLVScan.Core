using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Built-in catalog of threat families used by the classifier.
/// </summary>
internal static class ThreatFamilyCatalog
{
    /// <summary>
    /// Gets the built-in threat families recognized by the classifier.
    /// </summary>
    public static IReadOnlyList<ThreatFamilyDefinition> Families { get; } =
    [
        new ThreatFamilyDefinition
        {
            FamilyId = "family-resource-shell32-tempcmd-v2",
            DisplayName = "Embedded resource temp CMD dropper",
            Summary = "Extracts an embedded resource to a temporary .cmd file and executes it via ShellExecuteEx or Process.Start.",
            AdvisorySlugs =
            [
                "2025-12-malware-customtv-il2cpp",
                "2025-12-malware-nomoretrash",
                "2025-12-malware-realandwaitingtimeonfire"
            ],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "resource-shell32-tempcmd-shell32",
                    DisplayName = "Embedded resource -> temp .cmd -> ShellExecuteEx",
                    Summary = "Embedded payload materialized to a temporary .cmd file and launched through ShellExecuteEx.",
                    Confidence = 0.99,
                    Matcher = MatchEmbeddedShellExecuteTempCmd
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "resource-shell32-tempcmd-process-start",
                    DisplayName = "Embedded resource -> temp .cmd -> Process.Start",
                    Summary = "Embedded payload materialized to a temporary .cmd file and launched through Process.Start.",
                    Confidence = 0.97,
                    Matcher = MatchEmbeddedProcessStartTempCmd
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

    private static ThreatFamilyVariantMatch? MatchEmbeddedShellExecuteTempCmd(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.EmbeddedResourceDropAndExecute);
        var shellExecuteFinding = context.FindFinding("DllImportRule", "ShellExecuteEx");
        var shellExecuteChain = context.FindCallChain("DllImportRule", "ShellExecuteEx");
        var hasShellExecute = shellExecuteFinding != null || shellExecuteChain != null;
        var hasCmdStaging = context.AnyDataFlowContainsAll(".cmd") ||
                            context.AnyFindingContainsAll(".cmd") ||
                            context.AnyCallChainContainsAll(".cmd");

        if (dataFlow == null || !hasShellExecute || !hasCmdStaging)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("DataFlowAnalysis", "DllImportRule"),
            Evidence =
            [
                context.CreateDataFlowEvidence("pattern", DataFlowPattern.EmbeddedResourceDropAndExecute.ToString(), dataFlow),
                context.CreateDataFlowEvidence("data-flow-chain", dataFlow?.ChainId ?? "not-available", dataFlow),
                context.CreateRuleEvidence("api", "ShellExecuteEx", shellExecuteFinding),
                context.CreateCallChainEvidence("call-chain", shellExecuteChain?.ChainId ?? "not-available", shellExecuteChain),
                Evidence("staging", "embedded resource -> temp .cmd"),
                Evidence("execution", "ShellExecuteEx via shell32.dll")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchEmbeddedProcessStartTempCmd(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.EmbeddedResourceDropAndExecute);
        var processFinding = context.FindFinding("ProcessStartRule");

        if (dataFlow == null || processFinding == null)
        {
            return null;
        }

        var hasCmdStaging = context.AnyDataFlowContainsAll(".cmd") ||
                            context.AnyFindingContainsAll(".cmd") ||
                            context.AnyCallChainContainsAll(".cmd") ||
                            context.AnyDataFlowContainsAll(".bat") ||
                            context.AnyFindingContainsAll(".bat") ||
                            context.AnyCallChainContainsAll(".bat");

        if (!hasCmdStaging)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("DataFlowAnalysis", "ProcessStartRule"),
            Evidence =
            [
                context.CreateDataFlowEvidence("pattern", DataFlowPattern.EmbeddedResourceDropAndExecute.ToString(), dataFlow),
                context.CreateDataFlowEvidence("data-flow-chain", dataFlow.ChainId, dataFlow),
                context.CreateRuleEvidence("rule", "ProcessStartRule", processFinding),
                Evidence("staging", "embedded resource -> temp script"),
                Evidence("execution", "Process.Start script execution")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchPowerShellIwrDlBat(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.DownloadAndExecute);
        var processFinding = context.FindFinding("ProcessStartRule", "powershell.exe");

        if (processFinding == null)
        {
            return null;
        }

        var hasDownloaderMarkers = context.AnyContextContainsAll("iwr") ||
                                   context.AnyContextContainsAll("Invoke-WebRequest");
        var hasTempBatchMarkers = context.AnyContextContainsAll("dl.bat") ||
                                  context.AnyContextContainsAll("%TEMP%", ".bat");
        var hasCleanupMarkers = context.AnyContextContainsAll("Start-Sleep") ||
                                context.AnyContextContainsAll("Remove-Item");

        if (!hasDownloaderMarkers || !hasTempBatchMarkers || !hasCleanupMarkers)
        {
            return null;
        }

        var hasBehavioralContext = dataFlow != null ||
                                   context.FindCallChain("ProcessStartRule", "powershell.exe") != null ||
                                   context.AnyFindingContainsAll("powershell.exe", "iwr", "dl.bat", "Start-Sleep", "Remove-Item");

        if (!hasBehavioralContext)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("DataFlowAnalysis", "ProcessStartRule"),
            Evidence =
            [
                context.CreateDataFlowEvidence("pattern", dataFlow?.Pattern.ToString() ?? "standalone-process-chain", dataFlow),
                context.CreateDataFlowEvidence("data-flow-chain", dataFlow?.ChainId ?? "not-available", dataFlow),
                context.CreateRuleEvidence("rule", "ProcessStartRule", processFinding),
                context.CreateRuleEvidence("launcher", "powershell.exe", processFinding),
                Evidence("download", "Invoke-WebRequest / iwr"),
                Evidence("staging", "%TEMP%/dl.bat"),
                Evidence("cleanup", "sleep then remove temp batch")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchWebClientStageExecute(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.DownloadAndExecute);
        var executionFinding = context.FindFinding("ProcessStartRule");
        var hasWebClientSource = context.AnyDataFlowContainsAll("DownloadFileTaskAsync") ||
                                 context.AnyDataFlowContainsAll("WebClient") ||
                                 context.AnyFindingContainsAll("DownloadFileTaskAsync") ||
                                 context.AnyCallChainContainsAll("WebClient");

        if (dataFlow == null || executionFinding == null || !hasWebClientSource)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("DataFlowAnalysis", "DataInfiltrationRule", "ProcessStartRule"),
            Evidence =
            [
                context.CreateDataFlowEvidence("pattern", DataFlowPattern.DownloadAndExecute.ToString(), dataFlow),
                context.CreateDataFlowEvidence("data-flow-chain", dataFlow.ChainId, dataFlow),
                context.CreateDataFlowEvidence("source", "WebClient download", dataFlow),
                context.CreateRuleEvidence("rule", "ProcessStartRule", executionFinding),
                Evidence("download", "network download to TEMP"),
                Evidence("execution", "staged payload execution from TEMP")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchObfuscatedMetadataLoader(ThreatFamilyAnalysisContext context)
    {
        var encodedLiteral = context.FindFinding("EncodedStringLiteralRule");
        var reflectionFinding = context.FindFinding("ReflectionRule", "AssemblyMetadataAttribute");
        var reflectionChain = context.FindCallChain("ReflectionRule", "AssemblyMetadataAttribute");
        var pipelineFinding = context.FindFinding("EncodedStringPipelineRule");
        var dynamicLoadFlow = context.FindDataFlow(DataFlowPattern.DynamicCodeLoading);

        if (encodedLiteral == null || reflectionFinding == null || pipelineFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "EncodedStringLiteralRule",
                "EncodedStringPipelineRule",
                "ReflectionRule",
                dynamicLoadFlow != null ? "DataFlowAnalysis" : string.Empty),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "EncodedStringLiteralRule", encodedLiteral),
                context.CreateRuleEvidence("rule", "EncodedStringPipelineRule", pipelineFinding),
                context.CreateRuleEvidence("rule", "ReflectionRule", reflectionFinding),
                context.CreateCallChainEvidence("call-chain", reflectionChain?.ChainId ?? "not-available", reflectionChain),
                context.CreateDataFlowEvidence("data-flow-pattern", dynamicLoadFlow?.Pattern.ToString() ?? "not-available", dynamicLoadFlow),
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

    private static ThreatFamilyEvidence Evidence(string kind, string value, string? pattern, string? methodLocation, double? confidence)
    {
        return new ThreatFamilyEvidence
        {
            Kind = kind,
            Value = value,
            Pattern = pattern,
            MethodLocation = methodLocation,
            Confidence = confidence
        };
    }

}
