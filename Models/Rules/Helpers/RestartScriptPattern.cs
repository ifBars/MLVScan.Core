using System.Text.RegularExpressions;

namespace MLVScan.Models.Rules.Helpers;

/// <summary>
/// A closed PowerShell language for waiting on the current process and relaunching a fixed Steam app.
/// Tokens are supplied by IL analysis, never accepted from assembly string literals.
/// </summary>
internal static class RestartScriptPattern
{
    internal const string CurrentPid = "\u0001pid\u0002";
    internal const string LogPath = "\u0001log\u0002";
    internal const string DirectoryPath = "\u0001directory\u0002";
    internal const string ScriptPath = "\u0001script\u0002";
    internal const string EncodedCommand = "\u0001encoded\u0002";
    internal const string LauncherPrefix = "-NoProfile -WindowStyle Hidden -EncodedCommand ";
    internal const string DetachedPrefix = "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"";
    internal const string DetachedSuffix = "\"'} | Out-Null";

    private const string ErrorAction = " -ErrorAction SilentlyContinue";
    private const string Message = @"(?:[^'\r\n\x01\x02]|''){0,200}";
    private const string Log = @"Add-Content \$l \(\(Get-Date -Format s\)\+'" + Message + @"'\)";
    private const string Sleep = @"Start-Sleep -Seconds (?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300); ";
    private static readonly Regex Script = new(
        @"\A(?:\$l='" + LogPath + "'; )?Wait-Process -Id " + CurrentPid + ErrorAction + "; " +
        "(?:" + Log + "; )?" +
        "(?:Get-ChildItem -LiteralPath '" + DirectoryPath + "' -Filter \\*\\.delete" + ErrorAction +
        " \\| Remove-Item -Force" + ErrorAction + "; )?" +
        "(?:" + Sleep + ")?Start-Process 'steam://run/(?<app>[1-9][0-9]{0,9})'" +
        "(?:; " + Log + ")?" +
        "(?:; " + Sleep + @"if \(-not \(Get-Process -Name '[A-Za-z0-9 _.-]{1,100}'" + ErrorAction +
        @"\)\) \{ Start-Process 'steam://run/\k<app>'; " + Log + @" \} else \{ " + Log + @" \})?\z",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, TimeSpan.FromMilliseconds(100));

    internal static bool Matches(string script)
    {
        if (script.Length > 8192 || (script.Contains("$l", StringComparison.Ordinal) &&
                                   !script.StartsWith("$l='" + LogPath + "'; ", StringComparison.Ordinal)))
            return false;

        return Script.IsMatch(script);
    }

    internal static string FormatEvidence(string script) => script
        .Replace(CurrentPid, "<current process ID>")
        .Replace(LogPath, "<bound log path>")
        .Replace(DirectoryPath, "<bound directory>")
        .Replace(ScriptPath, "<bound script path>");
}
