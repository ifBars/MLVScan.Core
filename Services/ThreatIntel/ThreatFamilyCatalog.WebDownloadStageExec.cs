using MLVScan.Models;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Services.ThreatIntel;

/// <summary>
/// Web-download staged-execution variants grouped under the shared family definition.
/// </summary>
internal static partial class ThreatFamilyCatalog
{
    private static ThreatFamilyVariantMatch? MatchWebDownloadTempPowerShellScript(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.DownloadAndExecute);
        var downloadFinding = FindDownloadFinding(context, ".ps1");
        var executionFinding = FindProcessStartFinding(context, finding =>
            FindingContainsAll(finding, "Target: \"powershell.exe\"", ".ps1"));

        if (dataFlow == null || downloadFinding == null || executionFinding == null ||
            !HasTempScriptStaging(context, ".ps1") || !HasHiddenExecutionContext(context))
        {
            return null;
        }

        var launcherStyle = context.AnyContextContainsAll("where.exe", "powershell") ||
                            context.AnyContextContainsAll("SysNative", "powershell.exe") ||
                            context.AnyContextContainsAll("System32", "powershell.exe") ||
                            context.AnyContextContainsAll("SysWOW64", "powershell.exe")
            ? "PowerShell path resolution before execution"
            : FindProcessStartFinding(context, finding => FindingContainsAll(finding, "Target: \"cmd.exe\"", ".ps1")) != null
                ? "cmd.exe fallback for PowerShell script launch"
                : context.AnyContextContainsAll("UseShellExecute=true") || context.AnyContextContainsAll("UseShellExecute set")
                    ? "shell-assisted powershell.exe launch"
                    : "hidden powershell.exe launch";

        return new ThreatFamilyVariantMatch
        {
            MatchedRules = context.BuildMatchedRules("DataFlowAnalysis", "DataInfiltrationRule", "ProcessStartRule"),
            Evidence =
            [
                context.CreateDataFlowEvidence("pattern", DataFlowPattern.DownloadAndExecute.ToString(), dataFlow),
                context.CreateDataFlowEvidence("data-flow-chain", dataFlow.ChainId, dataFlow),
                context.CreateDataFlowEvidence("source", DescribeDownloadSource(context), dataFlow),
                context.CreateRuleEvidence("rule", "DataInfiltrationRule", downloadFinding),
                context.CreateRuleEvidence("rule", "ProcessStartRule", executionFinding),
                Evidence("staging", "%TEMP%/*.ps1"),
                Evidence("launcher", launcherStyle),
                Evidence("execution", "hidden powershell.exe script execution")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchWebDownloadTempBatchCmd(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.DownloadAndExecute);
        var downloadFinding = context.FindFinding("DataInfiltrationRule");
        var executionFinding = FindProcessStartFinding(context, finding =>
            FindingContainsAll(finding, "Target: \"cmd.exe\"") &&
            (FindingContainsAll(finding, ".bat") || FindingContainsAll(finding, ".cmd")));

        if (dataFlow == null || downloadFinding == null || executionFinding == null ||
            !HasTempBatchStaging(context) || !HasHiddenExecutionContext(context))
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
                context.CreateDataFlowEvidence("source", DescribeDownloadSource(context), dataFlow),
                context.CreateRuleEvidence("rule", "DataInfiltrationRule", downloadFinding),
                context.CreateRuleEvidence("rule", "ProcessStartRule", executionFinding),
                Evidence("staging", "%TEMP%/*.bat or *.cmd"),
                Evidence("launcher", "hidden cmd.exe launch"),
                Evidence("execution", "batch payload execution through cmd.exe")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchWebDownloadTempExecutable(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.DownloadAndExecute);
        var downloadFinding = FindDownloadFinding(context, ".exe");
        var executionFinding = FindProcessStartFinding(context, IsDirectExecutableLaunchFinding);

        if (dataFlow == null || downloadFinding == null || executionFinding == null ||
            !HasTempExecutableStaging(context) || !HasHiddenExecutionContext(context))
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
                context.CreateDataFlowEvidence("source", DescribeDownloadSource(context), dataFlow),
                context.CreateRuleEvidence("rule", "DataInfiltrationRule", downloadFinding),
                context.CreateRuleEvidence("rule", "ProcessStartRule", executionFinding),
                Evidence("staging", "temporary executable payload"),
                Evidence("launcher", "direct Process.Start on staged executable"),
                Evidence("execution", "direct executable launch from TEMP")
            ]
        };
    }

    private static ThreatFamilyVariantMatch? MatchWebDownloadStageExecute(ThreatFamilyAnalysisContext context)
    {
        var dataFlow = context.FindDataFlow(DataFlowPattern.DownloadAndExecute);
        var downloadFinding = context.FindFinding("DataInfiltrationRule");
        var executionFinding = FindPrimaryStagedExecutionFinding(context);

        if (dataFlow == null || downloadFinding == null || executionFinding == null ||
            !HasTempStagingContext(context) || !HasHiddenExecutionContext(context))
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
                context.CreateDataFlowEvidence("source", DescribeDownloadSource(context), dataFlow),
                context.CreateRuleEvidence("rule", "DataInfiltrationRule", downloadFinding),
                context.CreateRuleEvidence("rule", "ProcessStartRule", executionFinding),
                Evidence("staging", DescribeStagedPayload(context)),
                Evidence("execution", DescribeExecutionStyle(executionFinding))
            ]
        };
    }

    private static ScanFinding? FindDownloadFinding(ThreatFamilyAnalysisContext context, string extension)
    {
        return context.FindFinding("DataInfiltrationRule", extension);
    }

    private static ScanFinding? FindProcessStartFinding(ThreatFamilyAnalysisContext context, Func<ScanFinding, bool> predicate)
    {
        return context.Findings.FirstOrDefault(finding =>
            string.Equals(finding.RuleId, "ProcessStartRule", StringComparison.Ordinal) && predicate(finding));
    }

    private static ScanFinding? FindPrimaryStagedExecutionFinding(ThreatFamilyAnalysisContext context)
    {
        return FindProcessStartFinding(context, finding =>
            !FindingContainsAll(finding, "Target: \"where.exe\"") &&
            (FindingContainsAll(finding, "Correlated data flow") || HasTempStagingIndicators(finding)) &&
            HasHiddenExecutionIndicators(finding));
    }

    private static bool HasTempScriptStaging(ThreatFamilyAnalysisContext context, string extension)
    {
        return context.AnyContextContainsAll("%TEMP%", extension) ||
               context.AnyContextContainsAll("WorkingDirectory=Temp", extension) ||
               context.AnyContextContainsAll("GetTempPath", extension);
    }

    private static bool HasTempBatchStaging(ThreatFamilyAnalysisContext context)
    {
        return HasTempScriptStaging(context, ".bat") || HasTempScriptStaging(context, ".cmd");
    }

    private static bool HasTempExecutableStaging(ThreatFamilyAnalysisContext context)
    {
        return context.AnyContextContainsAll("WorkingDirectory=Temp") ||
               context.AnyContextContainsAll("%TEMP%", ".exe") ||
               context.AnyContextContainsAll("GetTempPath", ".exe");
    }

    private static bool HasTempStagingContext(ThreatFamilyAnalysisContext context)
    {
        return context.AnyContextContainsAll("%TEMP%") ||
               context.AnyContextContainsAll("WorkingDirectory=Temp") ||
               context.AnyContextContainsAll("GetTempPath");
    }

    private static bool HasHiddenExecutionContext(ThreatFamilyAnalysisContext context)
    {
        return context.AnyContextContainsAll("CreateNoWindow") ||
               context.AnyContextContainsAll("WindowStyle=Hidden") ||
               context.AnyContextContainsAll("UseShellExecute=true") ||
               context.AnyContextContainsAll("UseShellExecute set");
    }

    private static bool HasTempStagingIndicators(ScanFinding finding)
    {
        return FindingContainsAll(finding, "%TEMP%") ||
               FindingContainsAll(finding, "WorkingDirectory=Temp") ||
               FindingContainsAll(finding, "GetTempPath");
    }

    private static bool HasHiddenExecutionIndicators(ScanFinding finding)
    {
        return FindingContainsAll(finding, "CreateNoWindow") ||
               FindingContainsAll(finding, "WindowStyle=Hidden") ||
               FindingContainsAll(finding, "UseShellExecute=true") ||
               FindingContainsAll(finding, "UseShellExecute set");
    }

    private static bool IsDirectExecutableLaunchFinding(ScanFinding finding)
    {
        if (!HasHiddenExecutionIndicators(finding))
        {
            return false;
        }

        if (!FindingContainsAll(finding, ".exe") ||
            FindingContainsAll(finding, "Target: \"powershell.exe\"") ||
            FindingContainsAll(finding, "Target: \"cmd.exe\"") ||
            FindingContainsAll(finding, "Target: \"where.exe\""))
        {
            return false;
        }

        return true;
    }

    private static string DescribeDownloadSource(ThreatFamilyAnalysisContext context)
    {
        if (context.AnyContextContainsAll("DownloadFileTaskAsync") || context.AnyContextContainsAll("WebClient"))
        {
            return "WebClient download";
        }

        if (context.AnyContextContainsAll("GetByteArrayAsync") || context.AnyContextContainsAll("HttpClient"))
        {
            return "HttpClient download";
        }

        return "network download";
    }

    private static string DescribeStagedPayload(ThreatFamilyAnalysisContext context)
    {
        if (HasTempScriptStaging(context, ".ps1"))
        {
            return "%TEMP%/*.ps1";
        }

        if (HasTempBatchStaging(context))
        {
            return "%TEMP%/*.bat or *.cmd";
        }

        if (HasTempExecutableStaging(context))
        {
            return "temporary executable payload";
        }

        return "TEMP staged payload";
    }

    private static string DescribeExecutionStyle(ScanFinding executionFinding)
    {
        if (FindingContainsAll(executionFinding, "Target: \"powershell.exe\""))
        {
            return "hidden powershell.exe execution";
        }

        if (FindingContainsAll(executionFinding, "Target: \"cmd.exe\""))
        {
            return "hidden cmd.exe execution";
        }

        return "hidden staged payload execution";
    }

    private static bool FindingContainsAll(ScanFinding finding, params string[] needles)
    {
        return needles.All(needle =>
            !string.IsNullOrWhiteSpace(needle) &&
            (finding.Description?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true ||
             finding.Location?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true ||
             finding.CodeSnippet?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true));
    }
}
