using System.Text;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers;

internal static partial class InstructionValueResolver
{
    private const int MaxResolvedTextLength = 8192;

    private static bool TryResolveBranchedLocal(ResolverContext context, MethodDefinition? owner,
        Mono.Collections.Generic.Collection<Instruction> instructions, int useIndex, int localIndex,
        Dictionary<int, ResolvedValue>? argumentMap, int depth, out ResolvedValue value)
    {
        value = default;
        var candidates = new ValueAlternatives("local", context);
        bool Capture(int definition, out string identity)
        {
            identity = "captured";
            if (TryResolveTopStackValue(context, owner, instructions, definition - 1,
                    argumentMap, depth + 1, out var candidate, out _)) candidates.Add(candidate);
            else candidates.AddUnknown("unresolved local assignment");
            return true;
        }

        if (!TryResolveEquivalentReachingDefinitions(instructions,
                owner?.Body?.ExceptionHandlers.ToArray() ?? Array.Empty<ExceptionHandler>(), useIndex,
                instruction => instruction.TryGetStoredLocalIndex(out var stored) && stored == localIndex,
                depth, out _, invalidatesDefinition: instruction =>
                    TryGetLoadedLocalAddressIndex(instruction, out var escaped) && escaped == localIndex,
                definitionIdentityResolver: Capture, trySpendWork: context.TrySpendWork))
            return false;

        return candidates.TryBuild(out value);
    }

    private static bool IsTextFrameworkMethod(MethodReference method, string type, string name) =>
        IsTrustedFrameworkMethod(method, type, name) ||
        method.DeclaringType.FullName == type && method.Name == name &&
        method.DeclaringType.Scope is AssemblyNameReference { Name: "System.Private.CoreLib" };

    private static bool TryResolveTextTransform(ResolverContext context, MethodDefinition? owner,
        Mono.Collections.Generic.Collection<Instruction> instructions, int index, MethodReference method,
        int depth, List<ResolvedValue> arguments, out ResolvedValue value)
    {
        value = default;
        if (!context.CheckDepth(depth) || !context.TrySpendWork()) return false;
        if (arguments.Count == 1 && arguments[0].Alternatives is { } alternatives &&
            (IsTextFrameworkMethod(method, "System.Convert", "FromBase64String") ||
             IsTextFrameworkMethod(method, "System.Convert", "ToBase64String") ||
             IsTextFrameworkMethod(method, "System.Text.Encoding", "GetBytes") ||
             IsTextFrameworkMethod(method, "System.Text.Encoding", "GetString")))
        {
            var transformed = new ValueAlternatives("transform", context);
            foreach (var alternative in alternatives)
            {
                if (TryResolveTextTransform(context, owner, instructions, index, method, depth + 1,
                        new List<ResolvedValue> { alternative }, out var candidate)) transformed.Add(candidate);
                else transformed.Add(new ResolvedValue("<unknown transform> " + alternative.Display, null, false));
            }
            return transformed.TryBuild(out value, forceAmbiguous: true);
        }
        foreach (var name in new[] { "Unicode", "UTF8", "ASCII" })
        {
            if (IsTextFrameworkMethod(method, "System.Text.Encoding", "get_" + name) && !method.HasThis && method.Parameters.Count == 0)
            {
                value = new ResolvedValue("<encoding " + name + ">", null, false) { EncodingName = name };
                return true;
            }
        }

        if (IsTextFrameworkMethod(method, "System.Convert", "FromBase64String") && !method.HasThis &&
            method.Parameters.Count == 1 && arguments.Count == 1 && arguments[0].IsConcrete &&
            arguments[0].Display.Length <= MaxResolvedTextLength)
        {
            try
            {
                value = new ResolvedValue("<decoded bytes>", null, true)
                {
                    ByteContent = Convert.FromBase64String(arguments[0].Display)
                };
                return true;
            }
            catch (FormatException) { return false; }
        }

        if (IsTextFrameworkMethod(method, "System.Convert", "ToBase64String") && !method.HasThis &&
            method.Parameters.Count == 1 && arguments.Count == 1 &&
            arguments[0] is { ByteSourceText: not null, EncodingName: not null } source && source.ByteSourceText.Length <= MaxResolvedTextLength)
        {
            if (source.IsConcrete)
            {
                value = ResolvedValue.FromLiteral(Convert.ToBase64String(GetTextEncoding(source.EncodingName).GetBytes(source.ByteSourceText)));
                value.ByteSourceText = source.ByteSourceText;
                value.EncodingName = source.EncodingName;
            }
            else
            {
                value = new ResolvedValue("<dynamic Base64> [Recovered " + source.EncodingName +
                    " source, partial: " + source.ByteSourceText + "]", null, false);
            }
            return true;
        }

        var isGetBytes = IsTextFrameworkMethod(method, "System.Text.Encoding", "GetBytes");
        var isGetString = IsTextFrameworkMethod(method, "System.Text.Encoding", "GetString");
        var isReplace = IsTextFrameworkMethod(method, "System.String", "Replace");
        if (!method.HasThis || !((isGetBytes || isGetString) && method.Parameters.Count == 1 || isReplace && method.Parameters.Count == 2) ||
            arguments.Count != method.Parameters.Count ||
            !GetCallArgumentProducerMap(instructions, owner?.Body?.ExceptionHandlers.ToArray() ?? Array.Empty<ExceptionHandler>()).TryGetReceiverProducer(index, out var receiverIndex) ||
            !TryResolveValueFromProducer(context, owner, instructions, receiverIndex, null, depth + 1, out var receiver))
            return false;

        var operands = new List<ResolvedValue> { receiver };
        operands.AddRange(arguments);
        if (isReplace && receiver.Display.Contains("<ambiguous", StringComparison.Ordinal))
        {
            // Diagnostic alternatives are not a runtime string. Never apply Replace to their formatting.
            value = new ResolvedValue("<ambiguous replacement> [Input evidence: " + receiver.Display + "]", null, false);
            return true;
        }
        if (isGetString && method.Parameters[0].ParameterType.FullName == "System.Byte[]" &&
            receiver.EncodingName is { } textEncoding && operands[1].ByteContent is { } bytes)
        {
            var text = GetTextEncoding(textEncoding).GetString(bytes);
            if (text.Length > MaxResolvedTextLength) return false;
            value = ResolvedValue.FromLiteral(text);
            return true;
        }
        if (isGetBytes && method.Parameters[0].ParameterType.FullName == "System.String" &&
            operands[0].EncodingName is { } encoding && operands[1].Display.Length <= MaxResolvedTextLength)
        {
            value = new ResolvedValue("<encoded bytes>", null, operands[1].IsConcrete)
            {
                EncodingName = encoding,
                ByteSourceText = operands[1].Display
            };
            return true;
        }

        if (isReplace && method.Parameters.All(p => p.ParameterType.FullName == "System.String") &&
            operands[1].IsConcrete && operands[2].IsConcrete && operands[1].Display.Length > 0 &&
            operands.All(a => a.Display.Length <= MaxResolvedTextLength) &&
            (long)operands[0].Display.Length * Math.Max(1, operands[2].Display.Length) <= MaxResolvedTextLength)
        {
            var text = operands[0].Display.Replace(operands[1].Display, operands[2].Display);
            value = new ResolvedValue(text, ExtractExecutableName(text), operands.All(a => a.IsConcrete));
            return true;
        }
        return false;
    }

    private static Encoding GetTextEncoding(string name) => name switch
    {
        "Unicode" => Encoding.Unicode,
        "UTF8" => Encoding.UTF8,
        _ => Encoding.ASCII
    };
}
