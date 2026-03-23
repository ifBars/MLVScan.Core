using System.Text;

namespace MLVScan.Models.Rules.Helpers
{
    internal static class InvisibleUnicodeAnalyzer
    {
        private const int VariationSelectorStart = 0xFE00;
        private const int VariationSelectorEnd = 0xFE0F;
        private const int SupplementaryVariationSelectorStart = 0xE0100;
        private const int SupplementaryVariationSelectorEnd = 0xE01EF;
        private const int MinimumVariationSelectorCount = 8;

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
            public InvisibleUnicodeAnalysis(bool hasVariationSelectorPayload, int variationSelectorCount,
                int nonWhitespaceVisibleCount, string? decodedText)
            {
                HasVariationSelectorPayload = hasVariationSelectorPayload;
                VariationSelectorCount = variationSelectorCount;
                NonWhitespaceVisibleCount = nonWhitespaceVisibleCount;
                DecodedText = decodedText;
            }

            public static InvisibleUnicodeAnalysis Empty => new(false, 0, 0, null);

            public bool HasVariationSelectorPayload { get; }
            public int VariationSelectorCount { get; }
            public int NonWhitespaceVisibleCount { get; }
            public string? DecodedText { get; }
        }
    }
}
