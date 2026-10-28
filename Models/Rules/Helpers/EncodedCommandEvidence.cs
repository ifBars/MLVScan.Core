using System.Text;
using System.Text.RegularExpressions;

namespace MLVScan.Models.Rules.Helpers;

internal static class EncodedCommandEvidence
{
    private static readonly Regex Argument = new(
        "\\G\\s*(?:\"(?<value>[^\"]*)\"|'(?<value>[^']*)'|(?<value>[^\\s\"']+))",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    internal static string Expand(string target, string arguments)
    {
        var executable = target.Trim().Trim('"').Replace('\\', '/').Split('/').Last().ToLowerInvariant();
        if (executable is not ("powershell" or "powershell.exe" or "pwsh" or "pwsh.exe") || arguments.Length > 16384)
            return arguments;
        var evidence = new List<string>();
        var pending = arguments;
        for (var depth = 0; depth < 3; depth++)
        {
            var payload = FindEncodedPayload(pending);
            if (payload == null || payload.Length > 12000) break;
            try
            {
                var bytes = Convert.FromBase64String(payload);
                if (bytes.Length % 2 != 0) break;
                var text = new UnicodeEncoding(false, false, true).GetString(bytes);
                if (text.Length > 8192 || text.Any(c => char.IsControl(c) && c is not '\r' and not '\n' and not '\t')) break;
                evidence.Add("[Decoded UTF-16LE command: " + text + "]");
                var separator = text.IndexOf(' ');
                if (separator < 0 || text[..separator].ToLowerInvariant() is not ("powershell" or "powershell.exe" or "pwsh" or "pwsh.exe")) break;
                pending = text[(separator + 1)..];
            }
            catch (FormatException) { break; }
            catch (DecoderFallbackException) { break; }
        }
        return evidence.Count == 0 ? arguments : arguments + " " + string.Join(" ", evidence);
    }

    private static string? FindEncodedPayload(string arguments)
    {
        for (var offset = 0; offset < arguments.Length;)
        {
            var match = Argument.Match(arguments, offset);
            if (!match.Success) return null;
            offset = match.Index + match.Length;
            var token = match.Groups["value"].Value;
            if (token.Length < 2 || token[0] is not ('-' or '/')) continue;
            var option = token[1..];
            if ("command".StartsWith(option, StringComparison.OrdinalIgnoreCase) ||
                "file".StartsWith(option, StringComparison.OrdinalIgnoreCase)) return null;
            if (!"encodedcommand".StartsWith(option, StringComparison.OrdinalIgnoreCase) &&
                !option.Equals("ec", StringComparison.OrdinalIgnoreCase)) continue;
            var payload = Argument.Match(arguments, offset);
            return payload.Success ? payload.Groups["value"].Value : null;
        }
        return null;
    }
}
