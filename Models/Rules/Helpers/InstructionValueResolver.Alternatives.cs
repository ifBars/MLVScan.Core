namespace MLVScan.Models.Rules.Helpers;

internal static partial class InstructionValueResolver
{
    internal static bool TryResolveCallArgumentAlternatives(Mono.Cecil.MethodReference calledMethod,
        Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction> instructions, int callIndex,
        int argumentIndex, out IReadOnlyList<string> displays)
    {
        displays = Array.Empty<string>();
        var context = new ResolverContext(null);
        if (argumentIndex < 0 || argumentIndex >= calledMethod.Parameters.Count ||
            !TryResolveCallArguments(context, null, instructions, callIndex, calledMethod.Parameters.Count,
                null, 0, out var arguments)) return false;
        displays = EnumerateDisplays(arguments[argumentIndex]).Take(32).ToArray();
        return displays.Count > 0;
    }

    private static IEnumerable<string> EnumerateDisplays(ResolvedValue value) => value.Alternatives == null
        ? new[] { value.Display }
        : value.Alternatives.SelectMany(EnumerateDisplays);

    private sealed class ValueAlternatives(string source, ResolverContext? context = null)
    {
        private readonly List<ResolvedValue> _values = new();
        private int _textLength;
        private bool _truncated;

        public void AddUnknown(string reason) => Add(new ResolvedValue("<unknown: " + reason + ">", null, false));

        public void Add(ResolvedValue value)
        {
            if (_values.Any(existing => Equivalent(existing, value))) return;
            var renderedLength = (value.ByteSourceText ?? value.Display).Length;
            if (_values.Count >= (context?.Limits.Alternatives ?? 32) || _textLength + renderedLength > MaxResolvedTextLength)
            {
                _truncated = true;
                context?.ReportLimit();
                return;
            }
            _values.Add(value);
            _textLength += renderedLength;
        }

        public bool TryBuild(out ResolvedValue value, bool forceAmbiguous = false)
        {
            value = default;
            if (_values.Count == 0 && !_truncated) return false;
            if (_values.Count == 1 && !_truncated && !forceAmbiguous)
            {
                value = _values[0];
                return true;
            }
            var text = string.Join(" | ", _values.Select(v => v.ByteSourceText ?? v.Display));
            if (_truncated) text += " | <unknown: additional alternatives exceed recovery budget>";
            value = new ResolvedValue("<ambiguous " + source + "> [Possible values: " + text + "]", null, false)
            {
                Alternatives = _truncated
                    ? _values.Concat(new[] { new ResolvedValue("<unknown: truncated alternatives>", null, false) }).ToArray()
                    : _values.ToArray()
            };
            return true;
        }

        private static bool Equivalent(ResolvedValue left, ResolvedValue right) =>
            left.Display == right.Display && left.IsConcrete == right.IsConcrete &&
            ReferenceEquals(left.Alternatives, right.Alternatives) &&
            left.EncodingName == right.EncodingName && left.ByteSourceText == right.ByteSourceText &&
            (left.ByteContent == right.ByteContent || left.ByteContent != null && right.ByteContent != null &&
             left.ByteContent.SequenceEqual(right.ByteContent));
    }
}
