using System.Collections.Generic;
using System.Text.RegularExpressions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects download-oriented network activity that points to suspicious payload delivery,
    /// including known malicious domains, raw paste links, and direct payload URLs.
    /// </summary>
    public class DataInfiltrationRule : IScanRule
    {
        private static readonly HashSet<string> KnownMaliciousDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "minecraftmods.xyz"
        };

        private static readonly HashSet<string> UrlShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "cutt.ly",
            "rebrand.ly",
            "shorturl.at"
        };

        private static readonly HashSet<string> SuspiciousPayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com"
        };

        private static readonly HashSet<string> CommonHostingPayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".scr", ".com"
        };

        /// <summary>
        /// Gets the description emitted when the rule matches a suspicious download pattern.
        /// </summary>
        public string Description =>
            "Detected data download from suspicious endpoint (potential payload infiltration).";

        /// <summary>
        /// Gets the severity assigned to suspicious download patterns.
        /// </summary>
        public Severity Severity => Severity.High;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "DataInfiltrationRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => true;

        /// <summary>
        /// Gets developer guidance for legitimate update-check and resource-download scenarios.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "For update checking, use GitHub Releases API (api.github.com/repos/...) or raw.githubusercontent.com.",
            null,
            new[] { "HttpClient.GetStringAsync", "UnityWebRequest.Get" },
            true
        );

        /// <summary>
        /// Returns false because this rule is triggered by contextual instruction analysis.
        /// </summary>
        public bool IsSuspicious(MethodReference method)
        {
            // This rule analyzes contextual patterns around method calls
            return false;
        }

        /// <summary>
        /// Analyzes read-only network operations for suspicious download sources near the call site.
        /// </summary>
        /// <param name="method">The network-related method being analyzed.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="instructionIndex">The index of the call instruction being inspected.</param>
        /// <param name="methodSignals">Current method signal state used for correlation.</param>
        /// <returns>Findings describing suspicious payload delivery or benign allowlisted sources.</returns>
        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals)
        {
            if (method?.DeclaringType == null)
                yield break;

            string declaringTypeFullName = method.DeclaringType.FullName ?? string.Empty;
            string calledMethodName = method.Name ?? string.Empty;

            bool isNetworkCall =
                declaringTypeFullName.StartsWith("System.Net", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("UnityEngine.Networking.UnityWebRequest",
                    StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("HttpClient", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("WebClient", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("WebRequest", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("Sockets", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("TcpClient", StringComparison.OrdinalIgnoreCase) ||
                declaringTypeFullName.Contains("UdpClient", StringComparison.OrdinalIgnoreCase);

            if (!isNetworkCall)
                yield break;

            // Only analyze download/read operations (GET, DownloadString, etc.)
            bool isReadOnlyOperation =
                calledMethodName.Contains("GetStringAsync", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Contains("GetAsync", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Contains("GetByteArrayAsync", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Contains("GetResponse", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Contains("DownloadData", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Contains("DownloadFile", StringComparison.OrdinalIgnoreCase) ||
                calledMethodName.Equals("Get", StringComparison.OrdinalIgnoreCase);

            // Skip if this is not a download operation
            if (!isReadOnlyOperation)
                yield break;

            // Sweep nearby string literals for indicators
            int windowStart = Math.Max(0, instructionIndex - 25);
            int windowEnd = Math.Min(instructions.Count, instructionIndex + 26);
            var literals = UrlLiteralCollector.CollectCandidates(instructions, windowStart, windowEnd);

            if (literals.Count == 0)
                yield break;

            // Check for suspicious URL patterns
            bool hasRawPaste = literals.Any(s =>
                s.Contains("pastebin.com/raw", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("hastebin.com/raw", StringComparison.OrdinalIgnoreCase));
            bool hasBareIpUrl = literals.Any(s =>
                Regex.IsMatch(s, @"https?://\d{1,3}(?:\.\d{1,3}){3}", RegexOptions.IgnoreCase));
            bool mentionsNgrokOrTelegram = literals.Any(s =>
                s.Contains("ngrok", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("telegram", StringComparison.OrdinalIgnoreCase));

            // Check for legitimate sources (GitHub releases, mod hosting sites, common CDNs)
            bool isLegitimateSource = literals.Any(IsLegitimateSourceLiteral);

            // Detect specific legitimate source types for more detailed reporting
            bool isGitHubSource = literals.Any(IsGitHubSourceLiteral);

            bool isModHostingSource = literals.Any(IsModHostingSourceLiteral);

            bool isCDNSource = literals.Any(IsCdnSourceLiteral);

            // Extract URLs from literals
            var urls = new List<string>();
            foreach (var literal in literals)
            {
                if (literal.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    literal.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    var match = Regex.Match(literal, @"(https?://[^\s""'<>]+)", RegexOptions.IgnoreCase);
                    if (match.Success)
                    {
                        urls.Add(match.Groups[1].Value);
                    }
                }
                else if (Regex.IsMatch(literal, @"https?://", RegexOptions.IgnoreCase))
                {
                    var matches = Regex.Matches(literal, @"(https?://[^\s""'<>]+)", RegexOptions.IgnoreCase);
                    foreach (Match match in matches)
                    {
                        urls.Add(match.Groups[1].Value);
                    }
                }
            }

            urls = urls.Distinct().ToList();

            bool targetsKnownMaliciousDomain = urls.Any(IsKnownMaliciousDomain);
            bool targetsDirectPayload = urls.Any(IsDirectPayloadUrl);
            bool targetsCommonHostingPayload = urls.Any(IsCommonHostingPayloadUrl);
            bool targetsUrlShortener = urls.Any(IsUrlShortenerDomain);

            string urlList = urls.Count > 0
                ? $" URL(s): {string.Join(", ", urls)}"
                : string.Empty;

            // Build code snippet
            var snippetBuilder = new System.Text.StringBuilder();
            int contextLines = 2;
            for (int j = Math.Max(0, instructionIndex - contextLines);
                 j < Math.Min(instructions.Count, instructionIndex + contextLines + 1);
                 j++)
            {
                if (j == instructionIndex)
                    snippetBuilder.Append(">>> ");
                else
                    snippetBuilder.Append("    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            // For GET operations: legitimate sources get Low severity (always allowed)
            if (targetsCommonHostingPayload && isLegitimateSource)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only operation downloads executable or script payload from common hosting source.{urlList}",
                    Severity.Medium,
                    snippetBuilder.ToString().TrimEnd());
            }
            else if (isLegitimateSource)
            {
                string sourceType = isGitHubSource ? "GitHub" :
                    isModHostingSource ? "mod hosting site" :
                    isCDNSource ? "CDN" : "unknown source";

                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only network operation to {sourceType} (likely legitimate - version check or resource download).{urlList}",
                    Severity.Low,
                    snippetBuilder.ToString().TrimEnd());
            }
            else if (targetsKnownMaliciousDomain)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only operation to known malicious domain (confirmed payload delivery infrastructure).{urlList}",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd())
                {
                    BypassCompanionCheck = true
                };
            }
            else if (targetsUrlShortener)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only operation uses URL shortener for download endpoint (destination hidden from static scan).{urlList}",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd());
            }
            else if (targetsDirectPayload)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only operation downloads executable or script payload from non-allowlisted domain.{urlList}",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd())
                {
                    BypassCompanionCheck = true
                };
            }
            // Non-legitimate sources: High severity (requires companion finding to actually trigger due to RequiresCompanionFinding = true)
            else if (hasRawPaste || hasBareIpUrl || mentionsNgrokOrTelegram)
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType?.FullName ?? "Unknown"}.{method.Name}:{instructions[instructionIndex].Offset}",
                    $"Read-only operation to suspicious endpoint (potential payload download).{urlList}",
                    Severity.High,
                    snippetBuilder.ToString().TrimEnd());
            }
        }

        private static bool IsKnownMaliciousDomain(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host))
                return false;

            return KnownMaliciousDomains.Contains(uri.Host) ||
                   KnownMaliciousDomains.Any(domain => uri.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsUrlShortenerDomain(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host))
                return false;

            return UrlShortenerDomains.Contains(uri.Host);
        }

        private static bool IsLegitimateSourceLiteral(string literal)
        {
            return ExtractUrls(literal).Any(IsLegitimateSourceUrl);
        }

        private static bool IsGitHubSourceLiteral(string literal)
        {
            return ExtractUrls(literal).Any(url =>
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    return false;

                return IsGitHubSource(uri);
            });
        }

        private static bool IsModHostingSourceLiteral(string literal)
        {
            return ExtractUrls(literal).Any(url =>
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    return false;

                return HostMatches(uri.Host, "modrinth.com") ||
                       HostMatches(uri.Host, "curseforge.com") ||
                       HostMatches(uri.Host, "nexusmods.com");
            });
        }

        private static bool IsCdnSourceLiteral(string literal)
        {
            return ExtractUrls(literal).Any(url =>
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    return false;

                return IsCdnSource(uri);
            });
        }

        private static bool IsLegitimateSourceUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return false;

            if (HostMatches(uri.Host, "discord.com") || HostMatches(uri.Host, "discordapp.com"))
                return false;

            return IsGitHubSource(uri) ||
                   HostMatches(uri.Host, "modrinth.com") ||
                   HostMatches(uri.Host, "curseforge.com") ||
                   HostMatches(uri.Host, "nexusmods.com") ||
                   IsCdnSource(uri);
        }

        private static bool IsGitHubSource(Uri uri)
        {
            return (HostMatches(uri.Host, "github.com") &&
                    (uri.AbsolutePath.Contains("/releases", StringComparison.OrdinalIgnoreCase) ||
                     uri.AbsolutePath.Contains("/release", StringComparison.OrdinalIgnoreCase))) ||
                   (HostMatches(uri.Host, "api.github.com") &&
                    uri.AbsolutePath.StartsWith("/repos", StringComparison.OrdinalIgnoreCase)) ||
                   HostMatches(uri.Host, "raw.githubusercontent.com") ||
                   HostMatches(uri.Host, "githubusercontent.com") ||
                   HostMatches(uri.Host, "github.io");
        }

        private static bool IsCdnSource(Uri uri)
        {
            return HostMatches(uri.Host, "cdn.jsdelivr.net") ||
                   HostMatches(uri.Host, "unpkg.com") ||
                   HostMatches(uri.Host, "cdnjs.cloudflare.com") ||
                   HostMatches(uri.Host, "gstatic.com") ||
                   HostMatches(uri.Host, "googleapis.com");
        }

        private static bool HostMatches(string host, string domain)
        {
            return host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                   host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> ExtractUrls(string literal)
        {
            foreach (Match match in Regex.Matches(literal, @"(https?://[^\s""'<>]+)", RegexOptions.IgnoreCase))
            {
                yield return match.Groups[1].Value;
            }
        }

        private static bool IsDirectPayloadUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return false;

            if (IsKnownMaliciousDomain(url))
                return true;

            string path = uri.AbsolutePath;
            return SuspiciousPayloadExtensions.Any(ext =>
                path.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsCommonHostingPayloadUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return false;

            string path = uri.AbsolutePath;
            return CommonHostingPayloadExtensions.Any(ext =>
                path.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
        }
    }
}
