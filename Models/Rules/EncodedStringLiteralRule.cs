using System.Text.RegularExpressions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    public class EncodedStringLiteralRule : IScanRule
    {
        public string Description => "Detected numeric-encoded string literals (potential obfuscated payload).";
        public Severity Severity => Severity.High;
        public string RuleId => "EncodedStringLiteralRule";
        public bool RequiresCompanionFinding => false;

        private static readonly Regex DashSeparatedPattern =
            new Regex(@"^\d{2,3}(-\d{2,3}){10,}$", RegexOptions.Compiled);

        private static readonly Regex DotSeparatedPattern =
            new Regex(@"^\d{2,3}(\.\d{2,3}){10,}$", RegexOptions.Compiled);

        private static readonly Regex BacktickSeparatedPattern =
            new Regex(@"^\d{2,3}(`\d{2,3}){10,}$", RegexOptions.Compiled);

        private static readonly string[] SuspiciousKeywords =
        {
            "Process", "ProcessStartInfo", "powershell", "cmd.exe", "Start", "Execute", "Shell", ".ps1", ".bat",
            ".exe", "WindowStyle", "Hidden", "ExecutionPolicy", "Invoke-WebRequest", "DownloadFile",
            "FromBase64String", "Assembly.Load", "Reflection", "GetMethod", "CreateInstance", "Activator",
            "AppData", "Startup", "Registry", "RunOnce", "CurrentVersion\\Run"
        };

        public bool IsSuspicious(MethodReference method)
        {
            // This rule doesn't check methods directly - it's used by AssemblyScanner
            // to analyze string literals in IL code
            return false;
        }

        public IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method,
            int instructionIndex)
        {
            if (string.IsNullOrWhiteSpace(literal))
                yield break;

            var invisibleUnicodeAnalysis = InvisibleUnicodeAnalyzer.Analyze(literal);
            if (invisibleUnicodeAnalysis.HasVariationSelectorPayload &&
                !string.IsNullOrWhiteSpace(invisibleUnicodeAnalysis.DecodedText) &&
                ContainsSuspiciousContent(invisibleUnicodeAnalysis.DecodedText))
            {
                yield return new ScanFinding(
                    $"{method.DeclaringType.FullName}.{method.Name}:{instructionIndex}",
                    "Invisible Unicode payload string with suspicious decoded content detected. " +
                    $"Decoded: {invisibleUnicodeAnalysis.DecodedText}",
                    Severity.Critical,
                    $"Variation selectors: {invisibleUnicodeAnalysis.VariationSelectorCount}\n" +
                    $"Decoded: {invisibleUnicodeAnalysis.DecodedText}");
                yield break;
            }

            // Check single-level encoding first
            if (IsEncodedString(literal))
            {
                var decoded = DecodeNumericString(literal);
                if (decoded != null && ContainsSuspiciousContent(decoded))
                {
                    yield return new ScanFinding(
                        $"{method.DeclaringType.FullName}.{method.Name}:{instructionIndex}",
                        $"Numeric-encoded string with suspicious content detected. Decoded: {decoded}",
                        Severity.High,
                        $"Encoded: {literal}\nDecoded: {decoded}");
                    yield break;
                }
            }

            // Check multi-level encoding: primary separator splits into segments,
            // each segment uses a secondary separator for numeric values.
            // e.g., "83-116-97-114-116`80-114-111-99-101-115-115`99-109-100-46-101-120-101"
            var multiLevelResult = TryDecodeMultiLevelString(literal);
            if (multiLevelResult != null && ContainsSuspiciousContent(multiLevelResult))
            {
                string truncatedEncoded = literal.Length > 200
                    ? literal.Substring(0, 200) + "..."
                    : literal;
                string truncatedDecoded = multiLevelResult.Length > 500
                    ? multiLevelResult.Substring(0, 500) + "..."
                    : multiLevelResult;

                yield return new ScanFinding(
                    $"{method.DeclaringType.FullName}.{method.Name}:{instructionIndex}",
                    $"Multi-level numeric-encoded string with suspicious content detected. Decoded segments: {truncatedDecoded}",
                    Severity.Critical,
                    $"Encoded: {truncatedEncoded}\nDecoded: {truncatedDecoded}");
            }
        }

        public IEnumerable<ScanFinding> AnalyzeAssemblyMetadata(AssemblyDefinition assembly)
        {
            var findings = new List<ScanFinding>();

            try
            {
                foreach (var attr in assembly.CustomAttributes)
                {
                    if (attr.AttributeType.Name == "AssemblyMetadataAttribute" && attr.HasConstructorArguments)
                    {
                        foreach (var arg in attr.ConstructorArguments)
                        {
                            if (arg.Value is string strValue && !string.IsNullOrWhiteSpace(strValue))
                            {
                                var invisibleUnicodeAnalysis = InvisibleUnicodeAnalyzer.Analyze(strValue);
                                if (invisibleUnicodeAnalysis.HasVariationSelectorPayload &&
                                    !string.IsNullOrWhiteSpace(invisibleUnicodeAnalysis.DecodedText) &&
                                    ContainsSuspiciousContent(invisibleUnicodeAnalysis.DecodedText))
                                {
                                    findings.Add(new ScanFinding(
                                        $"Assembly Metadata: {attr.AttributeType.Name}",
                                        "Hidden invisible Unicode payload in assembly metadata. Decoded content: " +
                                        invisibleUnicodeAnalysis.DecodedText,
                                        Severity.Critical,
                                        $"Variation selectors: {invisibleUnicodeAnalysis.VariationSelectorCount}\n" +
                                        $"Decoded: {invisibleUnicodeAnalysis.DecodedText}"));
                                    continue;
                                }

                                // Check for numeric encoding patterns
                                if (IsEncodedString(strValue))
                                {
                                    var decoded = DecodeNumericString(strValue);
                                    if (decoded != null && ContainsSuspiciousContent(decoded))
                                    {
                                        findings.Add(new ScanFinding(
                                            $"Assembly Metadata: {attr.AttributeType.Name}",
                                            $"Hidden payload in assembly metadata attribute. Decoded content: {decoded}",
                                            Severity.Critical,
                                            $"Encoded: {strValue}\nDecoded: {decoded}"));
                                    }
                                }
                                // Also check for dot-separated encoding used in metadata
                                else if (strValue.Contains('.') && strValue.Split('.').Length >= 10)
                                {
                                    var decoded = DecodeNumericString(strValue);
                                    if (decoded != null && ContainsSuspiciousContent(decoded))
                                    {
                                        findings.Add(new ScanFinding(
                                            $"Assembly Metadata: {attr.AttributeType.Name}",
                                            $"Hidden payload in assembly metadata attribute. Decoded content: {decoded}",
                                            Severity.Critical,
                                            $"Encoded: {strValue}\nDecoded: {decoded}"));
                                    }
                                }
                                // Check for multi-level encoding in metadata
                                else
                                {
                                    var multiDecoded = TryDecodeMultiLevelString(strValue);
                                    if (multiDecoded != null && ContainsSuspiciousContent(multiDecoded))
                                    {
                                        string truncated = multiDecoded.Length > 500
                                            ? multiDecoded.Substring(0, 500) + "..."
                                            : multiDecoded;
                                        findings.Add(new ScanFinding(
                                            $"Assembly Metadata: {attr.AttributeType.Name}",
                                            $"Hidden multi-level encoded payload in assembly metadata. Decoded: {truncated}",
                                            Severity.Critical,
                                            $"Encoded length: {strValue.Length}\nDecoded: {truncated}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                // Skip metadata scanning if it fails
            }

            return findings;
        }

        public static bool IsEncodedString(string literal)
        {
            if (string.IsNullOrWhiteSpace(literal))
                return false;

            return DashSeparatedPattern.IsMatch(literal) ||
                   DotSeparatedPattern.IsMatch(literal) ||
                   BacktickSeparatedPattern.IsMatch(literal);
        }

        public static string DecodeNumericString(string encoded)
        {
            try
            {
                char delimiter = '-';
                if (encoded.Contains('.'))
                    delimiter = '.';
                else if (encoded.Contains('`'))
                    delimiter = '`';

                var parts = encoded.Split(delimiter);
                var decoded = new char[parts.Length];

                for (int i = 0; i < parts.Length; i++)
                {
                    if (int.TryParse(parts[i], out int charCode) && charCode >= 0 && charCode <= 127)
                    {
                        decoded[i] = (char)charCode;
                    }
                    else
                    {
                        return null; // Invalid encoding
                    }
                }

                return new string(decoded);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Attempts to decode multi-level encoded strings where a primary separator splits segments
        /// and each segment uses a secondary separator for numeric ASCII values.
        /// e.g., "83-116-97-114-116`80-114-111-99-101-115-115" → "Start Process"
        /// </summary>
        public static string? TryDecodeMultiLevelString(string literal)
        {
            if (string.IsNullOrWhiteSpace(literal) || literal.Length < 20)
                return null;

            // Primary separators that split segments
            char[] primarySeparators = { '`', '|', ';', '\n' };
            // Secondary separators that split numeric tokens within segments
            char[] secondarySeparators = { '-', '.', ',' };

            foreach (char primary in primarySeparators)
            {
                if (!literal.Contains(primary))
                    continue;

                string[] segments = literal.Split(primary);
                if (segments.Length < 2)
                    continue;

                foreach (char secondary in secondarySeparators)
                {
                    string? decoded = TryDecodeSegments(segments, secondary);
                    if (decoded != null)
                        return decoded;
                }
            }

            return null;
        }

        private static string? TryDecodeSegments(string[] segments, char secondary)
        {
            var decodedSegments = new List<string>();
            int successCount = 0;

            foreach (string segment in segments)
            {
                string trimmed = segment.Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                string[] tokens = trimmed.Split(secondary);
                if (tokens.Length < 2)
                {
                    // Single token segment: if it's a single numeric ASCII value, decode it
                    if (int.TryParse(trimmed, out int singleVal) && singleVal >= 32 && singleVal <= 126)
                    {
                        decodedSegments.Add(((char)singleVal).ToString());
                        successCount++;
                        continue;
                    }

                    return null; // Non-numeric single segment means this isn't the right pattern
                }

                var chars = new char[tokens.Length];
                bool allValid = true;

                for (int i = 0; i < tokens.Length; i++)
                {
                    if (int.TryParse(tokens[i].Trim(), out int charCode) && charCode >= 0 && charCode <= 127)
                    {
                        chars[i] = (char)charCode;
                    }
                    else
                    {
                        allValid = false;
                        break;
                    }
                }

                if (!allValid)
                    return null;

                decodedSegments.Add(new string(chars));
                successCount++;
            }

            // Need at least 2 successfully decoded segments
            if (successCount < 2)
                return null;

            return string.Join(" ", decodedSegments);
        }

        public static bool ContainsSuspiciousContent(string decodedText)
        {
            if (string.IsNullOrWhiteSpace(decodedText))
                return false;

            foreach (var keyword in SuspiciousKeywords)
            {
                if (decodedText.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
