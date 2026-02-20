using System.Text;
using System.Text.RegularExpressions;
using MLVScan.Models;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DeepBehavior;

public sealed class StringDecodeFlowAnalyzer : DeepBehaviorAnalyzer
{
    public StringDecodeFlowAnalyzer(DeepBehaviorAnalysisConfig config, CodeSnippetBuilder snippetBuilder)
        : base(config, snippetBuilder)
    {
    }

    public override IEnumerable<ScanFinding> Analyze(DeepBehaviorContext context)
    {
        if (!Config.EnableStringDecodeFlow)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var hasEncodedPipeline = context.HasAnyRule(DeepBehaviorRuleSets.EncodedRuleIds);
        var hasRiskySink = context.HasAnyRule(DeepBehaviorRuleSets.RiskySinkRuleIds) ||
                           context.Signals.HasSuspiciousReflection ||
                           HasReflectionOrDynamicActivationEvidence(context);

        if (!hasEncodedPipeline || !hasRiskySink)
        {
            return Enumerable.Empty<ScanFinding>();
        }

        var allFindings = context.MethodFindings.Concat(context.TypeFindings).ToList();

        var sinkFindings = allFindings
            .Where(f => f.RuleId != null && DeepBehaviorRuleSets.RiskySinkRuleIds.Contains(f.RuleId))
            .ToList();

        var hasReflectionEvidence = context.Signals.HasSuspiciousReflection || HasReflectionOrDynamicActivationEvidence(context);

        if (sinkFindings.Count == 0 && hasReflectionEvidence)
        {
            sinkFindings.Add(new ScanFinding(context.Method.FullName, "Reflection/dynamic activation", Severity.High)
            {
                RuleId = "ReflectionRule"
            });
        }

        var sinkDescriptions = sinkFindings
            .Select(f => GetSinkDescription(f))
            .Distinct()
            .ToList();

        var sinkSummary = sinkDescriptions.Count > 0
            ? string.Join("; ", sinkDescriptions)
            : "risky execution or loading sink";

        var encodedStrings = ExtractEncodedStringsFromContext(context);
        var decodedInfo = "";
        var invocationTargets = AnalyzeReflectionInvocationTargets(context);

        if (encodedStrings.Count > 0)
        {
            var decoded = TryDecodeStrings(encodedStrings);
            if (!string.IsNullOrEmpty(decoded))
            {
                decodedInfo = $"\n   Decoded value: {decoded}";
            }
        }

        if (invocationTargets.Count > 0)
        {
            decodedInfo += $"\n   Invoked via reflection: {string.Join(", ", invocationTargets)}";
        }

        var sinkCount = sinkFindings.Count;
        var severity = sinkCount >= 2 ? Severity.Critical : Severity.High;

        var offset = context.FirstOffsetForRule("ProcessStartRule")
                     ?? context.FirstOffsetForRule("Shell32Rule")
                     ?? context.FirstOffsetForRule("AssemblyDynamicLoadRule")
                     ?? context.FirstOffset();

        var finding = CreateFinding(
            context,
            ruleId: "DeepStringDecodeFlowRule",
            description: $"Deep correlation: encoded/decode pipeline reaches {sinkSummary}.{decodedInfo}",
            severity: severity,
            offset: offset);

        return [finding];
    }

    private static List<string> ExtractEncodedStringsFromContext(DeepBehaviorContext context)
    {
        var strings = new List<string>();

        foreach (var instruction in context.Instructions)
        {
            if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string str)
            {
                if (IsLikelyEncodedString(str))
                {
                    strings.Add(str);
                }
            }
        }

        return strings;
    }

    private static bool IsLikelyEncodedString(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length < 10)
            return false;

        bool hasDigits = false;
        bool hasSeparator = false;
        int digitCount = 0;
        int separatorCount = 0;

        foreach (char c in s)
        {
            if (char.IsDigit(c))
            {
                digitCount++;
            }
            else if (c == '-' || c == '`' || c == ':' || c == ',' || c == ' ')
            {
                separatorCount++;
            }
            else if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            {
                hasDigits = true;
            }
        }

        if (separatorCount > 3 && digitCount > s.Length * 0.3)
            return true;

        if ((s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ||
             Regex.IsMatch(s, "^[0-9a-fA-F]{8,}$")) && s.Length >= 8)
            return true;

        return false;
    }

    private static string? TryDecodeStrings(List<string> encodedStrings)
    {
        foreach (var encoded in encodedStrings)
        {
            var decoded = TryDecodeString(encoded);
            if (!string.IsNullOrEmpty(decoded) && decoded.Length >= 3)
            {
                return decoded;
            }
        }
        return null;
    }

    private static string? TryDecodeString(string encoded)
    {
        var tryDashSeparated = DecodeDashSeparatedAscii(encoded);
        if (!string.IsNullOrEmpty(tryDashSeparated))
            return tryDashSeparated;

        var tryBacktickSeparated = DecodeBacktickSeparatedAscii(encoded);
        if (!string.IsNullOrEmpty(tryBacktickSeparated))
            return tryBacktickSeparated;

        var tryMixedSeparators = DecodeMixedSeparatorsAscii(encoded);
        if (!string.IsNullOrEmpty(tryMixedSeparators))
            return tryMixedSeparators;

        var tryHexString = DecodeHexString(encoded);
        if (!string.IsNullOrEmpty(tryHexString))
            return tryHexString;

        return null;
    }

    private static string? DecodeMixedSeparatorsAscii(string s)
    {
        try
        {
            var parts = s.Split(new[] { '-', '`' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                return null;

            bool allNumeric = parts.All(p => int.TryParse(p.Trim(), out _));
            if (!allNumeric)
                return null;

            var sb = new StringBuilder();
            foreach (var part in parts)
            {
                if (int.TryParse(part.Trim(), out int code))
                {
                    if (code >= 32 && code <= 126)
                        sb.Append((char)code);
                    else
                        return null;
                }
            }

            var result = sb.ToString();

            var cleaned = CleanDecodedString(result);
            return cleaned.Length >= 4 ? cleaned : null;
        }
        catch
        {
            return null;
        }
    }

    private static string CleanDecodedString(string s)
    {
        var result = s;

        if (result.Contains("http"))
        {
            var urlMatch = System.Text.RegularExpressions.Regex.Match(result, @"https?://[^\s\""']+");
            if (urlMatch.Success)
            {
                return $"[URL] {urlMatch.Value}";
            }
        }

        if (result.Length > 100)
        {
            return result.Substring(0, 100) + "...";
        }

        return result;
    }

    private static string? DecodeDashSeparatedAscii(string s)
    {
        try
        {
            var parts = s.Split(new[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                return null;

            bool allNumeric = parts.All(p => int.TryParse(p, out _));
            if (!allNumeric)
                return null;

            var sb = new StringBuilder();
            foreach (var part in parts)
            {
                if (int.TryParse(part, out int code))
                {
                    if (code >= 32 && code <= 126)
                        sb.Append((char)code);
                    else
                        return null;
                }
            }

            var result = sb.ToString();
            return result.Length >= 4 ? result : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? DecodeBacktickSeparatedAscii(string s)
    {
        try
        {
            var parts = s.Split('`');
            if (parts.Length < 4)
                return null;

            bool allNumeric = parts.All(p => int.TryParse(p, out _));
            if (!allNumeric)
                return null;

            var sb = new StringBuilder();
            foreach (var part in parts)
            {
                if (int.TryParse(part, out int code))
                {
                    if (code >= 32 && code <= 126)
                        sb.Append((char)code);
                    else
                        return null;
                }
            }

            var result = sb.ToString();
            return result.Length >= 4 ? result : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? DecodeHexString(string s)
    {
        try
        {
            string hex = s.Replace("0x", "").Replace(" ", "").Replace(":", "").Replace("-", "");

            if (hex.Length < 8 || hex.Length % 2 != 0)
                return null;

            bool allHex = hex.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
            if (!allHex)
                return null;

            if (hex.Length > 64)
                hex = hex.Substring(0, 64);

            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            var result = Encoding.UTF8.GetString(bytes);
            return result.Length >= 4 && result.All(c => char.IsLetterOrDigit(c) || char.IsPunctuation(c) || c == ' ') ? result : null;
        }
        catch
        {
            return null;
        }
    }

    private static string GetSinkDescription(ScanFinding finding)
    {
        if (finding == null || finding.RuleId == null)
            return "unknown sink";

        return finding.RuleId switch
        {
            "ProcessStartRule" => "process execution (Process.Start)",
            "Shell32Rule" => "shell command execution (Shell32)",
            "DllImportRule" => "native DLL import (P/Invoke)",
            "ReflectionRule" => "reflection-based invocation",
            "AssemblyDynamicLoadRule" => "dynamic assembly loading",
            "DataExfiltrationRule" => "data exfiltration (network send)",
            "DataInfiltrationRule" => "data infiltration (network receive)",
            "PersistenceRule" => "persistence mechanism (registry/file)",
            _ => finding.RuleId
        };
    }

    private static bool HasReflectionOrDynamicActivationEvidence(DeepBehaviorContext context)
    {
        if (context.ScopedFindings.Any(finding =>
                finding.Description.Contains("reflection invocation", StringComparison.OrdinalIgnoreCase) ||
                finding.Description.Contains("Activator::CreateInstance", StringComparison.OrdinalIgnoreCase) ||
                finding.Description.Contains("without determinable target", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        foreach (var instruction in context.Instructions)
        {
            if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                instruction.Operand is not MethodReference called)
            {
                continue;
            }

            var typeName = called.DeclaringType?.FullName ?? string.Empty;
            var methodName = called.Name;

            if (typeName == "System.Activator" && methodName == "CreateInstance")
            {
                return true;
            }

            if ((typeName == "System.Reflection.MethodInfo" || typeName == "System.Reflection.MethodBase") &&
                methodName == "Invoke")
            {
                return true;
            }

            if (typeName == "System.Reflection.Assembly" && (methodName == "Load" || methodName == "LoadFrom"))
            {
                return true;
            }
        }

        return false;
    }

    private static List<string> AnalyzeReflectionInvocationTargets(DeepBehaviorContext context)
    {
        var targets = new List<string>();
        var instructions = context.Instructions;

        for (int i = 0; i < instructions.Count; i++)
        {
            var instruction = instructions[i];

            if (instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt)
                continue;

            if (instruction.Operand is not MethodReference called)
                continue;

            var typeName = called.DeclaringType?.FullName ?? string.Empty;
            var methodName = called.Name;

            if (typeName == "System.Type" && methodName == "GetMethod")
            {
                var methodNameArg = TryGetStringArgument(instructions, i);
                if (!string.IsNullOrEmpty(methodNameArg))
                {
                    var decoded = TryDecodeString(methodNameArg);
                    if (!string.IsNullOrEmpty(decoded))
                    {
                        targets.Add($"GetMethod(\"{decoded}\")");
                    }
                    else
                    {
                        targets.Add($"GetMethod(\"{methodNameArg}\")");
                    }
                }
            }
            else if (typeName == "System.Type" && methodName == "GetProperty")
            {
                var propNameArg = TryGetStringArgument(instructions, i);
                if (!string.IsNullOrEmpty(propNameArg))
                {
                    var decoded = TryDecodeString(propNameArg);
                    if (!string.IsNullOrEmpty(decoded))
                    {
                        targets.Add($"GetProperty(\"{decoded}\")");
                    }
                    else
                    {
                        targets.Add($"GetProperty(\"{propNameArg}\")");
                    }
                }
            }
            else if (typeName == "System.Activator" && methodName == "CreateInstance")
            {
                var typeArg = TryGetTypeArgument(instructions, i);
                if (!string.IsNullOrEmpty(typeArg))
                {
                    targets.Add($"CreateInstance({typeArg})");
                }
            }
        }

        return targets;
    }

    private static string? TryGetStringArgument(Mono.Collections.Generic.Collection<Instruction> instructions, int callIndex)
    {
        var callInstruction = instructions[callIndex];

        for (int i = callIndex - 1; i >= 0 && i >= callIndex - 5; i--)
        {
            var instruction = instructions[i];

            if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string str)
            {
                return str;
            }
        }

        return null;
    }

    private static string? TryGetTypeArgument(Mono.Collections.Generic.Collection<Instruction> instructions, int callIndex)
    {
        for (int i = callIndex - 1; i >= 0 && i >= callIndex - 5; i--)
        {
            var instruction = instructions[i];

            if (instruction.OpCode == OpCodes.Ldtoken && instruction.Operand is TypeReference typeRef)
            {
                return typeRef.FullName;
            }

            if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string str)
            {
                return str;
            }
        }

        return null;
    }
}
