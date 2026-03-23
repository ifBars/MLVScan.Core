using System.Text;

namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Analyzes strings that may hide payload bytes in Unicode variation selectors.
    /// </summary>
    internal static class InvisibleUnicodeAnalyzer
    {
        private const int VariationSelectorStart = 0xFE00;
        private const int VariationSelectorEnd = 0xFE0F;
        private const int SupplementaryVariationSelectorStart = 0xE0100;
        private const int SupplementaryVariationSelectorEnd = 0xE01EF;
        private const int MinimumVariationSelectorCount = 8;

        /// <summary>
        /// Scans a string for variation-selector payload bytes and attempts to decode them as UTF-8.
        /// </summary>
        /// <param name="literal">The string literal to inspect.</param>
        /// <returns>A structured analysis result describing the hidden payload characteristics.</returns>
        public static InvisibleUnicodeAnalysis Analyze(string literal)
        {
            if (string.IsNullOrEmpty(literal))
            {
                return InvisibleUnicodeAnalysis.Empty;
            }

            int variationSelectorCount = 0;
            int nonWhitespaceVisibleCount = 0;
            var decodedBytes = new List<byte>();

            for (int i = 0; i < literal.Length; i++)
            {
                int codePoint = char.ConvertToUtf32(literal, i);
                if (char.IsSurrogatePair(literal, i))
                {
                    i++;
                }

                if (TryDecodeVariationSelectorByte(codePoint, out byte decodedByte))
                {
                    variationSelectorCount++;
                    decodedBytes.Add(decodedByte);
                    continue;
                }

                if (codePoint <= char.MaxValue && !char.IsWhiteSpace((char)codePoint) &&
                    !char.IsControl((char)codePoint))
                {
                    nonWhitespaceVisibleCount++;
                }
            }

            if (variationSelectorCount < MinimumVariationSelectorCount)
            {
                return new InvisibleUnicodeAnalysis(false, variationSelectorCount, nonWhitespaceVisibleCount, null);
            }

            string? decodedText = TryDecodeUtf8(decodedBytes);
            return new InvisibleUnicodeAnalysis(true, variationSelectorCount, nonWhitespaceVisibleCount, decodedText);
        }

        /// <summary>
        /// Tries to decode a Unicode variation selector code point into the payload byte it represents.
        /// </summary>
        /// <param name="codePoint">The Unicode code point to inspect.</param>
        /// <param name="decodedByte">Receives the decoded byte when the code point is a supported selector.</param>
        /// <returns><see langword="true"/> when the code point maps to payload data.</returns>
        public static bool TryDecodeVariationSelectorByte(int codePoint, out byte decodedByte)
        {
            if (codePoint >= VariationSelectorStart && codePoint <= VariationSelectorEnd)
            {
                decodedByte = (byte)(codePoint - VariationSelectorStart);
                return true;
            }

            if (codePoint >= SupplementaryVariationSelectorStart &&
                codePoint <= SupplementaryVariationSelectorEnd)
            {
                decodedByte = (byte)(codePoint - SupplementaryVariationSelectorStart + 16);
                return true;
            }

            decodedByte = 0;
            return false;
        }

        private static string? TryDecodeUtf8(IReadOnlyList<byte> decodedBytes)
        {
            if (decodedBytes.Count == 0)
            {
                return null;
            }

            try
            {
                return new UTF8Encoding(false, true).GetString(decodedBytes.ToArray());
            }
            catch
            {
                return null;
            }
        }

        internal readonly struct InvisibleUnicodeAnalysis
        {
            /// <summary>
            /// Creates a new analysis result for a string that may contain variation-selector payload bytes.
            /// </summary>
            /// <param name="hasVariationSelectorPayload">Whether enough variation selectors were found to consider the string suspicious.</param>
            /// <param name="variationSelectorCount">The number of decoded variation selector bytes.</param>
            /// <param name="nonWhitespaceVisibleCount">The number of visible, non-whitespace code points encountered.</param>
            /// <param name="decodedText">The decoded UTF-8 payload, if decoding succeeded.</param>
            public InvisibleUnicodeAnalysis(bool hasVariationSelectorPayload, int variationSelectorCount,
                int nonWhitespaceVisibleCount, string? decodedText)
            {
                HasVariationSelectorPayload = hasVariationSelectorPayload;
                VariationSelectorCount = variationSelectorCount;
                NonWhitespaceVisibleCount = nonWhitespaceVisibleCount;
                DecodedText = decodedText;
            }

            /// <summary>
            /// Gets an empty analysis result.
            /// </summary>
            public static InvisibleUnicodeAnalysis Empty => new(false, 0, 0, null);

            /// <summary>
            /// Gets a value indicating whether the string appears to contain a payload encoded in variation selectors.
            /// </summary>
            public bool HasVariationSelectorPayload { get; }

            /// <summary>
            /// Gets the number of decoded variation selector bytes.
            /// </summary>
            public int VariationSelectorCount { get; }

            /// <summary>
            /// Gets the count of visible non-whitespace characters that accompanied the selectors.
            /// </summary>
            public int NonWhitespaceVisibleCount { get; }

            /// <summary>
            /// Gets the decoded UTF-8 payload, if decoding succeeded.
            /// </summary>
            public string? DecodedText { get; }
        }
    }
}
