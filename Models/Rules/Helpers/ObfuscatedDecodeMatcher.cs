using Mono.Cecil;

namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Scores decode-oriented methods and string literals so higher-level rules can combine them into
    /// stronger obfuscation evidence.
    /// </summary>
    internal static class ObfuscatedDecodeMatcher
    {
        private static readonly char[] TokenSeparators = { '-', '`', ':', ',', '|', ' ' };

        /// <summary>
        /// Scores a method call that looks like a decode or reconstruction primitive.
        /// </summary>
        /// <param name="calledMethod">The referenced method.</param>
        /// <param name="typeName">The declaring type name.</param>
        /// <param name="methodName">The method name.</param>
        /// <param name="score">Receives the assigned decode score.</param>
        /// <param name="reason">Receives a short explanation for the score.</param>
        /// <param name="isStrongDecodePrimitive">Receives whether the call is considered a strong primitive.</param>
        /// <returns><see langword="true"/> when the method matches a known decode pattern.</returns>
        public static bool TryGetDecodeCallScore(
            MethodReference calledMethod,
            string typeName,
            string methodName,
            out int score,
            out string? reason,
            out bool isStrongDecodePrimitive)
        {
            score = 0;
            reason = null;
            isStrongDecodePrimitive = false;

            if (typeName == "System.Int32" && methodName == "Parse" &&
                calledMethod.Parameters.Count == 1 &&
                calledMethod.Parameters[0].ParameterType.FullName == "System.String")
            {
                score = 10;
                reason = "integer parsing transform";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Byte" && methodName == "Parse")
            {
                score = 10;
                reason = "byte parsing transform";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Convert" &&
                (methodName == "FromBase64String" || methodName == "FromHexString" || methodName == "ToInt32" ||
                 methodName == "ToByte"))
            {
                score = 11;
                reason = $"convert.{methodName} transform";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Text.Encoding" && methodName == "GetString")
            {
                score = 9;
                reason = "byte-to-string reconstruction";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Char" && methodName == "ConvertToUtf32")
            {
                score = 12;
                reason = "Unicode code-point extraction";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Char" && methodName == "IsSurrogatePair")
            {
                score = 6;
                reason = "surrogate-pair aware Unicode walking";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Linq.Enumerable" && methodName == "Select")
            {
                if (calledMethod is GenericInstanceMethod genericMethod &&
                    genericMethod.GenericArguments.Count == 2)
                {
                    string projectionTarget = genericMethod.GenericArguments[1].FullName;
                    if (projectionTarget == "System.Char" || projectionTarget == "System.Byte")
                    {
                        score = 10;
                        reason = "sequence remapping pipeline";
                        isStrongDecodePrimitive = true;
                        return true;
                    }
                }
            }

            // Array.ConvertAll<String,Char> - variant of Select<String,Char> used in some malware
            if (typeName == "System.Array" && methodName == "ConvertAll")
            {
                if (calledMethod is GenericInstanceMethod genericMethod &&
                    genericMethod.GenericArguments.Count == 2)
                {
                    string projectionTarget = genericMethod.GenericArguments[1].FullName;
                    if (projectionTarget == "System.Char" || projectionTarget == "System.Byte")
                    {
                        score = 10;
                        reason = "array conversion pipeline (ConvertAll)";
                        isStrongDecodePrimitive = true;
                        return true;
                    }
                }
            }

            if (typeName == "System.String" && methodName == "Split")
            {
                score = 5;
                reason = "string.Split pipeline step";
                return true;
            }

            if (typeName == "System.String" && methodName == "Concat" &&
                calledMethod is GenericInstanceMethod concatGenericMethod &&
                concatGenericMethod.GenericArguments.Count == 1 &&
                concatGenericMethod.GenericArguments[0].FullName == "System.Char")
            {
                score = 7;
                reason = "char concatenation reconstruction";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.String" && methodName == "Concat" &&
                calledMethod.Parameters.Count >= 3)
            {
                score = 6;
                reason = "multi-string concatenation chain";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (methodName.IndexOf("reverse", StringComparison.OrdinalIgnoreCase) >= 0 &&
                (calledMethod.ReturnType.FullName == "System.String" ||
                 calledMethod.ReturnType.FullName == "System.Char[]"))
            {
                score = 8;
                reason = "string reversal transform";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Array" && methodName == "Reverse")
            {
                score = 7;
                reason = "array reversal primitive";
                isStrongDecodePrimitive = true;
                return true;
            }

            if (typeName == "System.Linq.Enumerable" && methodName == "Reverse")
            {
                score = 7;
                reason = "sequence reversal primitive";
                isStrongDecodePrimitive = true;
                return true;
            }

            if ((methodName.IndexOf("decode", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 methodName.IndexOf("decrypt", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 methodName.IndexOf("deobfusc", StringComparison.OrdinalIgnoreCase) >= 0) &&
                (calledMethod.ReturnType.FullName == "System.String" ||
                 calledMethod.ReturnType.FullName == "System.Byte[]"))
            {
                score = 8;
                reason = $"custom {methodName} helper";
                isStrongDecodePrimitive = true;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Returns true when a string looks like tokenized numeric ASCII data.
        /// </summary>
        /// <param name="literal">The string to inspect.</param>
        /// <returns><see langword="true"/> when the literal resembles numeric tokenization.</returns>
        public static bool IsTokenizedNumericLiteral(string literal)
        {
            if (literal.Length < 12)
            {
                return false;
            }

            string[] tokens = literal.Split(TokenSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 4)
            {
                return false;
            }

            int numericTokens = 0;
            int plausibleAsciiTokens = 0;

            foreach (string token in tokens)
            {
                if (!int.TryParse(token, out int value))
                {
                    continue;
                }

                numericTokens++;
                if (value >= 32 && value <= 126)
                {
                    plausibleAsciiTokens++;
                }
            }

            if (numericTokens < 4)
            {
                return false;
            }

            double numericRatio = (double)numericTokens / tokens.Length;
            return numericRatio >= 0.7 && plausibleAsciiTokens >= 3;
        }

        /// <summary>
        /// Returns true when a string resembles a Base64 payload.
        /// </summary>
        /// <param name="literal">The string to inspect.</param>
        /// <returns><see langword="true"/> when the literal looks like Base64.</returns>
        public static bool IsBase64LikeLiteral(string literal)
        {
            if (literal.Length < 24 || literal.Length % 4 != 0)
            {
                return false;
            }

            int validChars = 0;
            foreach (char c in literal)
            {
                if ((c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') ||
                    c == '+' || c == '/' || c == '=')
                {
                    validChars++;
                }
            }

            return validChars >= literal.Length - 2;
        }

        /// <summary>
        /// Returns true when a string resembles a hexadecimal payload.
        /// </summary>
        /// <param name="literal">The string to inspect.</param>
        /// <returns><see langword="true"/> when the literal looks like hex-encoded data.</returns>
        public static bool IsHexLikeLiteral(string literal)
        {
            if (literal.Length < 12)
            {
                return false;
            }

            string normalized = literal.Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace(":", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal);

            if (normalized.Length < 12 || normalized.Length % 2 != 0)
            {
                return false;
            }

            foreach (char c in normalized)
            {
                bool isHex = (c >= '0' && c <= '9') ||
                             (c >= 'a' && c <= 'f') ||
                             (c >= 'A' && c <= 'F');
                if (!isHex)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Tries to extract a suspicious command, path, or protocol marker from a literal.
        /// </summary>
        /// <param name="literal">The string to inspect.</param>
        /// <param name="marker">Receives the matched marker or its reversed match.</param>
        /// <returns><see langword="true"/> when a suspicious marker is found.</returns>
        public static bool TryGetDangerLiteralMarker(string literal, out string marker)
        {
            string[] markers =
            {
                "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "http://",
                "https://", "%temp%", "\\temp\\", "appdata", "startup", "shell32.dll"
            };

            foreach (string candidate in markers)
            {
                if (literal.IndexOf(candidate, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    marker = candidate;
                    return true;
                }
            }

            string reversed = ReverseString(literal);
            foreach (string candidate in markers)
            {
                if (reversed.IndexOf(candidate, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    marker = $"{candidate} (reversed: {literal})";
                    return true;
                }
            }

            marker = string.Empty;
            return false;
        }

        /// <summary>
        /// Tries to describe an invisible-Unicode payload and whether its decoded content looks suspicious.
        /// </summary>
        /// <param name="literal">The string to inspect.</param>
        /// <param name="reason">Receives a short description of the suspicious payload.</param>
        /// <param name="hasSuspiciousDecodedContent">Receives whether the decoded payload contains suspicious content.</param>
        /// <returns><see langword="true"/> when the literal contains a variation-selector payload.</returns>
        public static bool TryGetInvisibleUnicodeLiteralReason(string literal, out string reason,
            out bool hasSuspiciousDecodedContent)
        {
            var analysis = InvisibleUnicodeAnalyzer.Analyze(literal);
            if (!analysis.HasVariationSelectorPayload)
            {
                reason = string.Empty;
                hasSuspiciousDecodedContent = false;
                return false;
            }

            hasSuspiciousDecodedContent = !string.IsNullOrWhiteSpace(analysis.DecodedText) &&
                                          EncodedStringLiteralRule.ContainsSuspiciousContent(analysis.DecodedText);

            if (hasSuspiciousDecodedContent)
            {
                reason = $"invisible Unicode payload decodes to '{analysis.DecodedText}'";
                return true;
            }

            reason = $"invisible Unicode payload ({analysis.VariationSelectorCount} variation selectors)";
            return true;
        }

        private static string ReverseString(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            var chars = input.ToCharArray();
            System.Array.Reverse(chars);
            return new string(chars);
        }
    }
}
