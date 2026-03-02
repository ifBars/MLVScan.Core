using Mono.Cecil;

namespace MLVScan.Models.Rules.Helpers
{
    internal static class ObfuscatedDecodeMatcher
    {
        private static readonly char[] TokenSeparators = { '-', '`', ':', ',', '|', ' ' };

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

        public static bool IsHexLikeLiteral(string literal)
        {
            if (literal.Length < 16)
            {
                return false;
            }

            string normalized = literal.Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace(":", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal);

            if (normalized.Length < 16 || normalized.Length % 2 != 0)
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

            marker = string.Empty;
            return false;
        }
    }
}
