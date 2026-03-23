using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects hexadecimal-encoded string literals and direct calls to the framework hex-string decode API.
    /// </summary>
    public class HexStringRule : IScanRule
    {
        /// <summary>
        /// Gets the description emitted when a hex-encoded literal is detected.
        /// </summary>
        public string Description => "Detected hexadecimal encoded string (potential obfuscated payload).";

        /// <summary>
        /// Gets the severity assigned to hex-encoded string patterns.
        /// </summary>
        public Severity Severity => Severity.Medium;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "HexStringRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Gets developer guidance for storing legitimate binary assets without hex encoding them in code.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "If storing assets, consider embedding them as an embedded resource file.",
            null,
            new[] { "Assembly.GetManifestResourceStream", "File.ReadAllBytes" },
            true
        );

        // Regex for continuous hex strings (even length, min 12 chars)
        // Lowered from 16 to catch shorter encoded strings like "Process" (50726f63657373 = 14 chars)
        private static readonly Regex HexPattern = new Regex(@"^[0-9A-Fa-f]{12,}$", RegexOptions.Compiled);

        /// <summary>
        /// Returns true when the supplied method is a direct hex-string decode API.
        /// </summary>
        /// <param name="method">The method reference to inspect.</param>
        /// <returns><see langword="true"/> when the method matches a tracked hex decode entry point.</returns>
        public bool IsSuspicious(MethodReference method)
        {
            // This rule focuses on string literals, but we could also look for Convert.FromHexString in the future.
            if (method?.DeclaringType == null)
                return false;

            if (method.Name == "FromHexString" && method.DeclaringType.Name == "Convert")
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Analyzes a string literal for hex encoding and emits a finding when the decoded payload looks suspicious.
        /// </summary>
        /// <param name="literal">The string literal being inspected.</param>
        /// <param name="method">The method containing the literal.</param>
        /// <param name="instructionIndex">The instruction index of the literal.</param>
        /// <returns>Findings describing suspicious hex-encoded content.</returns>
        public IEnumerable<ScanFinding> AnalyzeStringLiteral(string literal, MethodDefinition method,
            int instructionIndex)
        {
            if (string.IsNullOrWhiteSpace(literal))
                yield break;

            // Check if it looks like a hex string (must be even length for byte decoding)
            if (literal.Length % 2 == 0 && HexPattern.IsMatch(literal))
            {
                // Attempt to decode
                var decoded = DecodeHexString(literal);

                // Check if the decoded content is suspicious
                if (decoded != null && EncodedStringLiteralRule.ContainsSuspiciousContent(decoded))
                {
                    yield return new ScanFinding(
                        $"{method.DeclaringType.FullName}.{method.Name}:{instructionIndex}",
                        $"Hex-encoded string with suspicious content detected. Decoded: {decoded}",
                        Severity.High,
                        $"Encoded: {literal}\nDecoded: {decoded}");
                }
            }
        }

        /// <summary>
        /// Hex-string detection does not currently use contextual instruction analysis.
        /// </summary>
        /// <param name="calledMethod">The method being inspected.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="index">The instruction index.</param>
        /// <param name="signals">Current method signal state.</param>
        /// <returns>An empty sequence.</returns>
        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int index,
            MethodSignals signals)
        {
            // No specific contextual pattern analysis for now, relying on string literal analysis
            yield break;
        }

        private string DecodeHexString(string hex)
        {
            try
            {
                var bytes = new byte[hex.Length / 2];
                for (int i = 0; i < hex.Length; i += 2)
                {
                    bytes[i / 2] = byte.Parse(hex.Substring(i, 2), NumberStyles.HexNumber);
                }

                // Try UTF8 first, fallback to ASCII if needed, but for now let's stick to a safe encoding that won't throw easily
                // Using ASCII or UTF8 is fine.
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return null;
            }
        }
    }
}
