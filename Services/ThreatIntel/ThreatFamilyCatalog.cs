using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Built-in catalog of threat families used by the classifier.
/// </summary>
internal static partial class ThreatFamilyCatalog
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
            AdvisorySlugs =
            [
                "2026-01-malware-endlessgraffiti",
                "2026-01-malware-fastergrowth"
            ],
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
            FamilyId = "family-webdownload-stage-exec-v3",
            DisplayName = "Web download staged payload executor",
            Summary = "Downloads a payload to TEMP through WebClient, HttpClient, or a similar network API and then executes it via hidden or shell-assisted process launch.",
            AdvisorySlugs =
            [
                "2026-02-malware-moretrees",
                "2026-03-malware-customer-search-bar",
                "2026-03-malware-longlastingfertilizer",
                "2026-03-malware-nopolice",
                "2026-03-malware-rentalcars",
                "2026-03-malware-skitching",
                "2026-03-malware-storagehub",
                "2026-03-malware-unlimitedgraffiti",
                "2026-03-malware-vortex-backuprtilizer",
                "2026-04-malware-dynamicorders"
            ],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "webdownload-temp-ps1-hidden-powershell",
                    DisplayName = "Web download -> temp .ps1 -> hidden PowerShell",
                    Summary = "Downloads a script payload into TEMP and launches it through a hidden powershell.exe chain, which helps platforms quickly cluster trojanized mod loaders using the same script-stager tradecraft.",
                    Confidence = 0.98,
                    Matcher = MatchWebDownloadTempPowerShellScript
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "webdownload-temp-batch-hidden-cmd",
                    DisplayName = "Web download -> temp batch -> hidden cmd.exe",
                    Summary = "Downloads a batch payload into TEMP and pivots through hidden cmd.exe execution, separating command-shell stagers from PowerShell-script variants during triage.",
                    Confidence = 0.97,
                    Matcher = MatchWebDownloadTempBatchCmd
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "webdownload-temp-exe-direct-launch",
                    DisplayName = "Web download -> temp executable -> direct launch",
                    Summary = "Downloads an executable payload and launches it directly from a temporary working directory, distinguishing direct binary droppers from script-based stagers.",
                    Confidence = 0.97,
                    Matcher = MatchWebDownloadTempExecutable
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "webdownload-temp-hidden-launch-generic",
                    DisplayName = "Web download staged payload executor",
                    Summary = "Downloads a payload over the network, stages it in TEMP, then executes it through powershell.exe, cmd.exe, or a hidden direct process launch.",
                    Confidence = 0.95,
                    Matcher = MatchWebDownloadStageExecute
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-embedded-resource-script-stager-v1",
            DisplayName = "Embedded resource script stager",
            Summary = "Stores a script payload in a referenced embedded resource, stages it at runtime, and uses hidden shell or PowerShell execution to retrieve or run a payload.",
            AdvisorySlugs = [],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "embedded-resource-powershell-download-tempbat",
                    DisplayName = "Embedded resource -> PowerShell download -> temp batch",
                    Summary = "Referenced embedded resource contains a PowerShell/WebClient download command that stages a batch payload under TEMP and executes it.",
                    Confidence = 0.97,
                    Matcher = MatchEmbeddedResourcePowerShellDownloadTempBatch
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-remote-script-pipe-shell-v1",
            DisplayName = "Remote script piped to shell",
            Summary = "Launches a command shell that retrieves a remote script and pipes it directly into another shell interpreter without staging a visible payload file.",
            AdvisorySlugs = [],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "curl-pipe-cmd-remote-script",
                    DisplayName = "curl URL piped to cmd.exe",
                    Summary = "Runs cmd.exe with a curl command that fetches a remote script and pipes the response directly into cmd.exe.",
                    Confidence = 0.98,
                    Matcher = MatchCurlPipeCmdRemoteScript
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-encoded-powershell-tempcmd-stager-v1",
            DisplayName = "Encoded hidden PowerShell temp command stager",
            Summary = "Stores command-line process, PowerShell, and TEMP command script arguments as numeric-encoded strings before reflectively launching a hidden downloader.",
            AdvisorySlugs = [],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "numeric-decoded-iwr-tempcmd-hidden-launch",
                    DisplayName = "Numeric decode -> hidden PowerShell -> TEMP command",
                    Summary = "Decodes a hidden cmd.exe or powershell.exe launcher that downloads a command script into TEMP and starts it hidden.",
                    Confidence = 0.97,
                    Matcher = MatchEncodedPowerShellTempCommandStager
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-hex-remote-config-tempcmd-stager-v1",
            DisplayName = "Hex remote config temp CMD stager",
            Summary = "Decodes remote command configuration URLs and reflectively stages the fetched command into a temporary script before hidden cmd.exe execution.",
            AdvisorySlugs = [],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "hex-config-reflective-tempcmd-hidden-cmd",
                    DisplayName = "Hex config -> reflected WebClient -> temp .cmd -> hidden cmd.exe",
                    Summary = "Uses hex/byte-array string reconstruction to hide config URLs, WebClient.DownloadString, temp command-file staging, and a hidden reflected cmd.exe launch.",
                    Confidence = 0.97,
                    Matcher = MatchHexRemoteConfigReflectiveTempCmd
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-dynamic-assembly-reflection-loader-v2",
            DisplayName = "Dynamic assembly reflection loader",
            Summary = "Loads opaque assembly payloads at runtime and pairs reflective invocation with confirmed staged execution or hidden system-binary-name launch behavior.",
            AdvisorySlugs = [],
            ExactSampleHashes = [],
            Variants =
            [
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "assembly-load-reflective-invoke-confirmed-payload",
                    DisplayName = "Opaque Assembly.Load payload with reflective invoke",
                    Summary = "Loads an opaque assembly payload dynamically, invokes unresolved reflected code, and has confirmed execution evidence such as embedded payload launch or staged process execution.",
                    Confidence = 0.90,
                    Matcher = MatchAssemblyLoadReflectiveInvokeConfirmedPayload
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "dynamic-code-loader-hidden-system-process",
                    DisplayName = "Dynamic code loader with hidden system-binary-name launch",
                    Summary = "Combines dynamic code loading or plugin assembly loading with hidden launch of a Windows system binary name.",
                    Confidence = 0.96,
                    Matcher = MatchDynamicLoaderHiddenSystemProcess
                }
            ]
        },
        new ThreatFamilyDefinition
        {
            FamilyId = "family-obfuscated-metadata-loader-v2",
            DisplayName = "Obfuscated metadata-backed loader",
            Summary = "Uses encoded strings, numeric transforms, or assembly metadata to reconstruct a staged hidden command launcher at runtime.",
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
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "assembly-description-encoded-hidden-launcher",
                    DisplayName = "Assembly description encoded hidden launcher",
                    Summary = "Stores hidden ProcessStartInfo, cmd.exe, and PowerShell downloader launch arguments as numeric segments in AssemblyDescription metadata.",
                    Confidence = 0.96,
                    Matcher = MatchAssemblyDescriptionEncodedHiddenLauncher
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "base64-tempbat-hidden-cmd",
                    DisplayName = "Base64 decoded temp batch hidden cmd",
                    Summary = "Decodes an embedded Base64 payload, writes it as a temporary batch or command script, and executes it through hidden cmd.exe.",
                    Confidence = 0.97,
                    Matcher = MatchBase64TempBatchHiddenCmd
                },
                new ThreatFamilyVariantDefinition
                {
                    VariantId = "obfuscated-reflective-hidden-process-launch",
                    DisplayName = "Obfuscated reflective hidden process launch",
                    Summary = "Correlates Base64 or numeric decode behavior with reflective or native execution bridging and hidden process launch.",
                    Confidence = 0.95,
                    Matcher = MatchObfuscatedReflectiveHiddenProcessLaunch
                }
            ]
        }
    ];

    private static ThreatFamilyVariantMatch? MatchHexRemoteConfigReflectiveTempCmd(ThreatFamilyAnalysisContext context)
    {
        var obfuscatedFinding = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ObfuscatedReflectiveExecutionRule", StringComparison.Ordinal) &&
            FindingContainsAny(finding, "hex remote config reflective temp command stager") &&
            FindingContainsAny(finding, "WebClient.DownloadString", "DownloadString") &&
            FindingContainsAny(finding, "GetTempFileName") &&
            FindingContainsAny(finding, ".cmd", ".bat") &&
            FindingContainsAny(finding, "File.WriteAllText", "WriteAllText") &&
            FindingContainsAny(finding, "ProcessStartInfo") &&
            FindingContainsAny(finding, "cmd.exe") &&
            FindingContainsAny(finding, "WindowStyle=Hidden", "WindowStyle Hidden", "Hidden") &&
            FindingContainsAny(finding, "MethodInfo.Invoke", "MethodBase.Invoke"));

        if (obfuscatedFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("ObfuscatedReflectiveExecutionRule"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "ObfuscatedReflectiveExecutionRule", obfuscatedFinding),
                Evidence("config", "hex-encoded remote command configuration URLs"),
                Evidence("download", "reflected WebClient.DownloadString"),
                Evidence("staging", "Path.GetTempFileName + .cmd + File.WriteAllText"),
                Evidence("execution", "reflected hidden cmd.exe ProcessStartInfo launch")
            ]
        };
    }

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

    private static ThreatFamilyVariantMatch? MatchAssemblyDescriptionEncodedHiddenLauncher(
        ThreatFamilyAnalysisContext context)
    {
        var encodedExecutionFinding = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "EncodedStringLiteralRule", StringComparison.Ordinal) &&
            FindingContainsAny(finding, "AssemblyDescriptionAttribute") &&
            FindingContainsAny(finding, "ProcessStartInfo") &&
            FindingContainsAny(finding, "cmd.exe") &&
            FindingContainsAny(finding, "Invoke-WebRequest", "DownloadFile", "WebClient") &&
            FindingContainsAny(finding, ".cmd", ".bat", "ProgramData", "%TEMP%", "$env:TEMP") &&
            FindingContainsAny(finding, "WindowStyle Hidden", "WindowStyle", "Hidden", "CreateNoWindow"));

        if (encodedExecutionFinding == null)
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("EncodedStringLiteralRule"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "EncodedStringLiteralRule", encodedExecutionFinding),
                Evidence("payload-source", "AssemblyDescriptionAttribute"),
                Evidence("decode", "multi-level numeric encoded launcher metadata"),
                Evidence("download", "PowerShell web request command"),
                Evidence("execution", "hidden cmd.exe / powershell launcher")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchBase64TempBatchHiddenCmd(ThreatFamilyAnalysisContext context)
    {
        var base64Finding = context.FindFinding("Base64Rule");
        var processFinding = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            FindingContainsAll(finding, "Target: \"cmd.exe\"") &&
            HasScriptStagingIndicators(finding) &&
            HasHiddenExecutionIndicators(finding));
        var multiSignalFinding = context.FindFinding("MultiSignalDetection", "process execution", "Base64", "file write");

        if (base64Finding == null || processFinding == null || multiSignalFinding == null)
        {
            return null;
        }

        if (!LocationsShareMethod(base64Finding.Location, processFinding.Location) ||
            !LocationsShareMethod(processFinding.Location, multiSignalFinding.Location))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("Base64Rule", "MultiSignalDetection", "ProcessStartRule"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "Base64Rule", base64Finding),
                context.CreateRuleEvidence("rule", "MultiSignalDetection", multiSignalFinding),
                context.CreateRuleEvidence("rule", "ProcessStartRule", processFinding),
                Evidence("decode", "Base64 payload materialization"),
                Evidence("staging", "decoded payload -> temporary .bat/.cmd script"),
                Evidence("execution", "hidden cmd.exe script execution")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchEncodedPowerShellTempCommandStager(ThreatFamilyAnalysisContext context)
    {
        var encodedExecutionFinding = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "EncodedStringLiteralRule", StringComparison.Ordinal) &&
            FindingContainsAny(finding, "powershell.exe", "cmd.exe") &&
            FindingContainsAny(finding, "Invoke-WebRequest", "iwr ", "DownloadFile") &&
            FindingContainsAny(finding, "%TEMP%", "$env:TEMP", "temp.cmd", ".cmd", ".bat") &&
            FindingContainsAny(finding, "WindowStyle Hidden", "-WindowStyle Hidden", "Hidden"));
        var pipelineFinding = context.FindFinding("EncodedStringPipelineRule");
        var base64Finding = context.FindFinding("Base64Rule");
        var obfuscatedClusterFinding = context.FindFinding("ObfuscatedReflectiveExecutionRule", "cross-method obfuscated reflection staging cluster");

        if (encodedExecutionFinding == null ||
            (pipelineFinding == null && base64Finding == null && obfuscatedClusterFinding == null))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "EncodedStringLiteralRule",
                "EncodedStringPipelineRule",
                "Base64Rule",
                "ObfuscatedReflectiveExecutionRule"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "EncodedStringLiteralRule", encodedExecutionFinding),
                context.CreateRuleEvidence("rule", "EncodedStringPipelineRule", pipelineFinding),
                context.CreateRuleEvidence("rule", "Base64Rule", base64Finding),
                context.CreateRuleEvidence("rule", "ObfuscatedReflectiveExecutionRule", obfuscatedClusterFinding),
                Evidence("decode", "numeric encoded command-line payload"),
                Evidence("download", "PowerShell web request"),
                Evidence("staging", "TEMP .cmd/.bat payload"),
                Evidence("execution", "hidden cmd.exe / powershell.exe launcher")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchAssemblyLoadReflectiveInvokeConfirmedPayload(ThreatFamilyAnalysisContext context)
    {
        var dynamicLoadFinding = context.Findings
            .Where(IsAssemblyDynamicLoadFinding)
            .Where(IsHighRiskOpaqueDynamicLoad)
            .FirstOrDefault(dynamicFinding => context.Findings.Any(reflectionFinding =>
                IsUnresolvedReflectionInvokeFinding(reflectionFinding) &&
                LocationsShareMethod(dynamicFinding.Location, reflectionFinding.Location)));
        var reflectionFinding = dynamicLoadFinding == null
            ? null
            : context.Findings.FirstOrDefault(finding =>
                IsUnresolvedReflectionInvokeFinding(finding) &&
                LocationsShareMethod(dynamicLoadFinding.Location, finding.Location));
        var executionFinding = FindConfirmedDynamicPayloadExecutionFinding(context);
        var executionFlow = FindConfirmedDynamicPayloadExecutionFlow(context);

        if (dynamicLoadFinding == null ||
            reflectionFinding == null ||
            (executionFinding == null && executionFlow == null))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "AssemblyDynamicLoadRule",
                "ReflectionRule",
                executionFinding?.RuleId ?? string.Empty,
                executionFlow != null ? "DataFlowAnalysis" : string.Empty),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "AssemblyDynamicLoadRule", dynamicLoadFinding),
                context.CreateRuleEvidence("rule", "ReflectionRule", reflectionFinding),
                context.CreateRuleEvidence("rule", executionFinding?.RuleId ?? "execution", executionFinding),
                context.CreateDataFlowEvidence("data-flow-pattern", executionFlow?.Pattern.ToString() ?? "not-available", executionFlow),
                Evidence("payload", "opaque dynamic assembly payload"),
                Evidence("reflection", "unresolved reflected method invocation"),
                Evidence("execution", "confirmed staged or embedded payload execution")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchDynamicLoaderHiddenSystemProcess(ThreatFamilyAnalysisContext context)
    {
        var processFinding = context.Findings.FirstOrDefault(IsHiddenSystemBinaryNameProcessLaunch);
        var dynamicLoadFinding = context.Findings.FirstOrDefault(IsAssemblyDynamicLoadFinding);
        var dynamicCodeFlow = context.FindDataFlow(DataFlowPattern.DynamicCodeLoading);

        if (processFinding == null ||
            (dynamicCodeFlow == null && !IsHighRiskOpaqueDynamicLoad(dynamicLoadFinding)))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "ProcessStartRule",
                "AssemblyDynamicLoadRule",
                dynamicCodeFlow != null ? "DataFlowAnalysis" : string.Empty),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "ProcessStartRule", processFinding),
                context.CreateRuleEvidence("rule", "AssemblyDynamicLoadRule", dynamicLoadFinding),
                context.CreateDataFlowEvidence("data-flow-pattern", dynamicCodeFlow?.Pattern.ToString() ?? "not-available", dynamicCodeFlow),
                Evidence("loader", "dynamic code loading present"),
                Evidence("execution", "hidden Windows system-binary-name process launch")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchObfuscatedReflectiveHiddenProcessLaunch(ThreatFamilyAnalysisContext context)
    {
        var obfuscatedFinding = context.FindFinding("ObfuscatedReflectiveExecutionRule");
        var processFinding = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            HasHiddenExecutionIndicators(finding));
        var base64Finding = context.FindFinding("Base64Rule");
        var multiSignalFinding = context.FindFinding("MultiSignalDetection");

        if (obfuscatedFinding == null || processFinding == null ||
            !FindingContainsAny(obfuscatedFinding, "process execution sink", "native execution bridge", "staged execution"))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules(
                "ObfuscatedReflectiveExecutionRule",
                "ProcessStartRule",
                "Base64Rule",
                "MultiSignalDetection"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "ObfuscatedReflectiveExecutionRule", obfuscatedFinding),
                context.CreateRuleEvidence("rule", "ProcessStartRule", processFinding),
                context.CreateRuleEvidence("rule", "Base64Rule", base64Finding),
                context.CreateRuleEvidence("rule", "MultiSignalDetection", multiSignalFinding),
                Evidence("decode", "obfuscated Base64 or numeric reconstruction"),
                Evidence("bridge", "reflective/native execution bridge"),
                Evidence("execution", "hidden process launch")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchEmbeddedResourcePowerShellDownloadTempBatch(ThreatFamilyAnalysisContext context)
    {
        var resourceFinding = context.FindFinding("EmbeddedResourceScriptRule", "staged script payload");

        if (resourceFinding == null ||
            !FindingContainsAny(resourceFinding, "powershell", "Invoke-WebRequest", "WebClient", "DownloadFile") ||
            !FindingContainsAny(resourceFinding, "%TEMP%", "$env:TEMP", ".bat", ".cmd") ||
            !FindingContainsAny(resourceFinding, "WindowStyle Hidden", "-WindowStyle Hidden", "ExecutionPolicy Bypass", "Start-Process", "& "))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("EmbeddedResourceScriptRule"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "EmbeddedResourceScriptRule", resourceFinding),
                Evidence("source", "referenced embedded script resource"),
                Evidence("download", "PowerShell/WebClient payload retrieval"),
                Evidence("staging", "TEMP batch or command script"),
                Evidence("execution", "hidden script execution")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchCurlPipeCmdRemoteScript(ThreatFamilyAnalysisContext context)
    {
        var processFinding = context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
            FindingContainsAll(finding, "Target: \"cmd.exe\"") &&
            FindingContainsAny(finding, "curl ", "curl.exe", "iwr ", "Invoke-WebRequest") &&
            FindingContainsAny(finding, "| cmd", "|cmd", "| powershell", "|powershell", " | "));

        if (processFinding == null || !FindingContainsAny(processFinding, "http://", "https://"))
        {
            return null;
        }

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("ProcessStartRule"),
            Evidence =
            [
                context.CreateRuleEvidence("rule", "ProcessStartRule", processFinding),
                Evidence("download", "remote script fetched by command-line web client"),
                Evidence("execution", "remote response piped directly to shell")
            ]
        };
    }

    private static bool IsAssemblyDynamicLoadFinding(ScanFinding? finding)
    {
        return finding != null &&
               string.Equals(finding.RuleId, "AssemblyDynamicLoadRule", StringComparison.Ordinal);
    }

    private static bool IsUnresolvedReflectionInvokeFinding(ScanFinding finding)
    {
        return string.Equals(finding.RuleId, "ReflectionRule", StringComparison.Ordinal) &&
               FindingContainsAny(
                   finding,
                   "non-literal target method name",
                   "without determinable target method",
                   "cannot determine what is being invoked");
    }

    private static bool IsHighRiskOpaqueDynamicLoad(ScanFinding? finding)
    {
        if (!IsAssemblyDynamicLoadFinding(finding))
        {
            return false;
        }

        if (finding!.Severity >= Severity.Critical)
        {
            return true;
        }

        var hasOpaqueLoadApi = FindingContainsAny(
            finding,
            "Assembly.Load(byte[])",
            "Assembly.Load(byte[], byte[])",
            "AssemblyLoadContext.LoadFromStream");
        var hasHighRiskProvenance = FindingContainsAny(
            finding,
            "provenance: network",
            "provenance: base64",
            "provenance: crypto",
            "provenance: compression",
            "provenance: resource",
            "provenance: temp-path",
            "provenance: sensitive-path",
            "provenance: write-then-load");

        return hasOpaqueLoadApi &&
               hasHighRiskProvenance &&
               (finding.BypassCompanionCheck || finding.RiskScore >= 75);
    }

    private static ScanFinding? FindConfirmedDynamicPayloadExecutionFinding(ThreatFamilyAnalysisContext context)
    {
        return context.Findings.FirstOrDefault(finding =>
                   string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
                   (HasHiddenExecutionIndicators(finding) ||
                    FindingContainsAny(
                        finding,
                        "Staged loader chain",
                        "download -> temp drop -> execute",
                        "Correlated data flow"))) ??
               context.FindFinding("DllImportRule", "ShellExecuteEx") ??
               context.FindFinding("ObfuscatedReflectiveExecutionRule", "staged execution") ??
               context.FindFinding("EmbeddedResourceScriptRule", "staged script payload");
    }

    private static DataFlowChain? FindConfirmedDynamicPayloadExecutionFlow(ThreatFamilyAnalysisContext context)
    {
        return context.FindDataFlow(DataFlowPattern.DownloadAndExecute) ??
               context.FindDataFlow(DataFlowPattern.EmbeddedResourceDropAndExecute);
    }

    private static bool IsHiddenSystemBinaryNameProcessLaunch(ScanFinding finding)
    {
        return string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) &&
               FindingContainsAny(
                   finding,
                   "Target: \"svchost.exe\"",
                   "Target: \"rundll32.exe\"",
                   "Target: \"regsvr32.exe\"") &&
               HasHiddenExecutionIndicators(finding);
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

    private static bool FindingContainsAny(ScanFinding finding, params string[] needles)
    {
        return needles.Any(needle =>
            !string.IsNullOrWhiteSpace(needle) &&
            EnumerateFindingTexts(finding).Any(value => value.Contains(needle, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool HasScriptStagingIndicators(ScanFinding finding)
    {
        return FindingContainsAny(finding, ".bat", ".cmd") &&
               FindingContainsAny(finding, "%TEMP%", "WorkingDirectory=Temp", "GetTempPath", "TEMP");
    }

    private static bool LocationsShareMethod(string? left, string? right)
    {
        var leftMethod = NormalizeMethodLocation(left);
        var rightMethod = NormalizeMethodLocation(right);

        return !string.IsNullOrWhiteSpace(leftMethod) &&
               string.Equals(leftMethod, rightMethod, StringComparison.Ordinal);
    }

    private static string NormalizeMethodLocation(string? location)
    {
        if (string.IsNullOrWhiteSpace(location))
        {
            return string.Empty;
        }

        var separator = location.IndexOf(':');
        return separator >= 0 ? location[..separator] : location;
    }

    private static IEnumerable<string> EnumerateFindingTexts(ScanFinding finding)
    {
        yield return finding.Location;
        yield return finding.Description;

        if (!string.IsNullOrWhiteSpace(finding.CodeSnippet))
        {
            yield return finding.CodeSnippet;
        }
    }

}
