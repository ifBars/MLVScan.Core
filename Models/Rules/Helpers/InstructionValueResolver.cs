using System.Text.RegularExpressions;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    internal static class InstructionValueResolver
    {
        private const int MaxDepth = 16;

        private static readonly Regex ExecutableNameRegex =
            new Regex(@"([A-Za-z0-9._-]+\.(?:exe|bat|cmd|com|ps1|msi))",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private static readonly Regex FormatItemRegex =
            new Regex(@"\{(\d+)(?:[^}]*)\}", RegexOptions.CultureInvariant);

        public static bool TryResolveProcessTarget(
            MethodDefinition? containingMethod,
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out string target)
        {
            var context = new ResolverContext(containingMethod?.Module);

            if (TryResolveFromStartInfoSetter(context, containingMethod, instructions, processStartIndex,
                    out var resolved) ||
                TryResolveFromProcessStartArguments(context, containingMethod, calledMethod, instructions,
                    processStartIndex, out resolved))
            {
                target = BuildTargetDisplay(resolved);
                return true;
            }

            target = "<unknown/non-literal>";
            return false;
        }

        public static bool TryResolveProcessArguments(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out string arguments)
        {
            var context = new ResolverContext(containingMethod?.Module);

            if (TryResolveFromStartInfoArgumentsSetter(context, containingMethod, instructions, processStartIndex,
                    out var resolved))
            {
                arguments = resolved.Display;
                return true;
            }

            arguments = "<unknown/no-arguments>";
            return false;
        }

        public static bool TryResolveStackValueDisplay(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int beforeIndex,
            out string valueDisplay)
        {
            var context = new ResolverContext(containingMethod?.Module);

            if (TryResolveTopStackValue(context, containingMethod, instructions, beforeIndex, null, 0, out var resolved,
                    out _))
            {
                valueDisplay = resolved.Display;
                return true;
            }

            valueDisplay = "<unknown/non-literal>";
            return false;
        }

        public static bool TryResolveUseShellExecute(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out bool? useShellExecute)
        {
            useShellExecute = null;
            int searchStart = Math.Max(0, processStartIndex - 400);
            var context = new ResolverContext(containingMethod?.Module);

            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    methodRef.Name != "set_UseShellExecute")
                {
                    continue;
                }

                if (TryResolveTopStackValue(context, containingMethod, instructions, i - 1, null, 0, out var resolved,
                        out _))
                {
                    if (resolved.Display is "True" or "true" or "1")
                    {
                        useShellExecute = true;
                        return true;
                    }

                    if (resolved.Display is "False" or "false" or "0")
                    {
                        useShellExecute = false;
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool TryResolveCreateNoWindow(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out bool? createNoWindow)
        {
            createNoWindow = null;
            int searchStart = Math.Max(0, processStartIndex - 400);
            var context = new ResolverContext(containingMethod?.Module);

            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    methodRef.Name != "set_CreateNoWindow")
                {
                    continue;
                }

                if (TryResolveTopStackValue(context, containingMethod, instructions, i - 1, null, 0, out var resolved,
                        out _))
                {
                    if (resolved.Display is "True" or "true" or "1")
                    {
                        createNoWindow = true;
                        return true;
                    }

                    if (resolved.Display is "False" or "false" or "0")
                    {
                        createNoWindow = false;
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool TryResolveWindowStyle(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out int? windowStyle)
        {
            windowStyle = null;
            int searchStart = Math.Max(0, processStartIndex - 400);
            var context = new ResolverContext(containingMethod?.Module);

            // First, find the set_WindowStyle call
            int setWindowStyleIndex = -1;
            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    methodRef.Name != "set_WindowStyle")
                {
                    continue;
                }

                setWindowStyleIndex = i;
                break;
            }

            if (setWindowStyleIndex < 0)
                return false;

            // Now look backwards from the set_WindowStyle call to find the value (ldc.i4.X)
            for (int i = setWindowStyleIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];

                // Skip instructions that don't affect the value we're looking for
                if (instruction.OpCode == OpCodes.Call ||
                    instruction.OpCode == OpCodes.Callvirt ||
                    instruction.OpCode == OpCodes.Pop ||
                    instruction.OpCode == OpCodes.Stloc ||
                    instruction.OpCode == OpCodes.Stloc_0 ||
                    instruction.OpCode == OpCodes.Stloc_1 ||
                    instruction.OpCode == OpCodes.Stloc_2 ||
                    instruction.OpCode == OpCodes.Stloc_3 ||
                    instruction.OpCode == OpCodes.Stloc_S ||
                    instruction.OpCode == OpCodes.Stfld ||
                    instruction.OpCode == OpCodes.Stsfld ||
                    instruction.OpCode == OpCodes.Dup)
                {
                    continue;
                }

                // Try to resolve as int32 literal
                if (TryResolveInt32Literal(instruction, out int intVal))
                {
                    windowStyle = intVal;
                    return true;
                }

                // If we found a field load, try to resolve it
                if (instruction.OpCode == OpCodes.Ldfld || instruction.OpCode == OpCodes.Ldsfld)
                {
                    if (TryResolveTopStackValue(context, containingMethod, instructions, i, null, 0, out var resolved,
                            out _))
                    {
                        if (int.TryParse(resolved.Display, out int parsedVal))
                        {
                            windowStyle = parsedVal;
                            return true;
                        }
                    }
                }

                // Stop after finding the first non-skipped instruction
                break;
            }

            return false;
        }

        public static bool TryResolveWorkingDirectory(
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out string? workingDirectory)
        {
            workingDirectory = null;
            int searchStart = Math.Max(0, processStartIndex - 400);
            var context = new ResolverContext(containingMethod?.Module);

            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    methodRef.Name != "set_WorkingDirectory")
                {
                    continue;
                }

                if (TryResolveTopStackValue(context, containingMethod, instructions, i - 1, null, 0, out var resolved,
                        out _))
                {
                    workingDirectory = resolved.Display?.ToLowerInvariant();
                    return true;
                }
            }

            return false;
        }

        private static bool TryResolveFromStartInfoArgumentsSetter(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out ResolvedValue value)
        {
            value = default;
            int searchStart = Math.Max(0, processStartIndex - 400);

            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    methodRef.Name != "set_Arguments")
                {
                    continue;
                }

                return TryResolveTopStackValue(context, containingMethod, instructions, i - 1, null, 0, out value,
                    out _);
            }

            return false;
        }

        private static bool TryResolveFromStartInfoSetter(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out ResolvedValue value)
        {
            value = default;
            int searchStart = Math.Max(0, processStartIndex - 400);

            for (int i = processStartIndex - 1; i >= searchStart; i--)
            {
                var instruction = instructions[i];
                if ((instruction.OpCode != OpCodes.Call && instruction.OpCode != OpCodes.Callvirt) ||
                    instruction.Operand is not MethodReference methodRef)
                {
                    continue;
                }

                if (methodRef.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                    methodRef.Name != "set_FileName")
                {
                    continue;
                }

                return TryResolveTopStackValue(context, containingMethod, instructions, i - 1, null, 0, out value,
                    out _);
            }

            return false;
        }

        private static bool TryResolveFromProcessStartArguments(
            ResolverContext context,
            MethodDefinition? containingMethod,
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int processStartIndex,
            out ResolvedValue value)
        {
            value = default;

            if (!string.Equals(calledMethod.Name, "Start", StringComparison.Ordinal) ||
                calledMethod.Parameters.Count == 0)
                return false;

            if (!TryResolveCallArguments(context, containingMethod, instructions, processStartIndex,
                    calledMethod.Parameters.Count, null, 0, out var args))
                return false;

            if (args.Count == 0)
                return false;

            value = args[0];
            return true;
        }

        private static bool TryResolveCallArguments(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int parameterCount,
            Dictionary<int, ResolvedValue>? argumentMap,
            int depth,
            out List<ResolvedValue> arguments)
        {
            arguments = new List<ResolvedValue>(parameterCount);
            int cursor = callIndex - 1;

            for (int i = parameterCount - 1; i >= 0; i--)
            {
                if (!TryResolveTopStackValue(context, containingMethod, instructions, cursor, argumentMap, depth + 1,
                        out var value, out int producerIndex))
                    return false;

                arguments.Insert(0, value);
                cursor = producerIndex - 1;
            }

            return true;
        }

        private static bool TryResolveTopStackValue(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int beforeIndex,
            Dictionary<int, ResolvedValue>? argumentMap,
            int depth,
            out ResolvedValue value,
            out int producerIndex)
        {
            value = default;
            producerIndex = -1;

            if (depth > MaxDepth || beforeIndex < 0)
                return false;

            producerIndex = FindTopValueProducerIndex(instructions, beforeIndex);
            if (producerIndex < 0)
                return false;

            return TryResolveValueFromProducer(context, containingMethod, instructions, producerIndex, argumentMap,
                depth + 1, out value);
        }

        private static int FindTopValueProducerIndex(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int beforeIndex)
        {
            int needed = 1;

            for (int i = beforeIndex; i >= 0; i--)
            {
                var instruction = instructions[i];
                needed -= GetPushCount(instruction);
                if (needed <= 0)
                    return i;

                needed += GetPopCount(instruction);
            }

            return -1;
        }

        private static bool TryResolveValueFromProducer(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int producerIndex,
            Dictionary<int, ResolvedValue>? argumentMap,
            int depth,
            out ResolvedValue value)
        {
            value = default;

            if (depth > MaxDepth)
                return false;

            var instruction = instructions[producerIndex];

            if (instruction.OpCode == OpCodes.Ldstr && instruction.Operand is string literal)
            {
                value = ResolvedValue.FromLiteral(literal);
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldnull)
            {
                value = new ResolvedValue("<null>", null, false);
                return true;
            }

            if (TryResolveInt32Literal(instruction, out int intValue))
            {
                value = new ResolvedValue(intValue.ToString(), null, true);
                return true;
            }

            if (instruction.OpCode == OpCodes.Box)
            {
                if (TryResolveTopStackValue(context, containingMethod, instructions, producerIndex - 1, argumentMap,
                        depth + 1, out value, out _))
                    return true;

                value = new ResolvedValue("<boxed-value>", null, false);
                return true;
            }

            if (TryGetLocalIndex(instruction, out int localIndex))
            {
                if (TryResolveLocalValue(context, containingMethod, instructions, producerIndex - 1, localIndex,
                        argumentMap, depth + 1, out value))
                    return true;

                value = new ResolvedValue($"<local V_{localIndex}>", null, false);
                return true;
            }

            if (TryGetArgumentIndex(instruction, out int argumentIndex))
            {
                if (argumentMap != null && argumentMap.TryGetValue(argumentIndex, out var mapped))
                {
                    value = mapped;
                    return true;
                }

                value = new ResolvedValue($"<arg {argumentIndex}>", null, false);
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldfld && instruction.Operand is FieldReference fieldRef)
            {
                if (TryResolveFieldValueInMethod(context, containingMethod, instructions, producerIndex - 1, fieldRef,
                        false, depth + 1, out value) ||
                    TryResolveFieldValueAcrossModule(context, fieldRef, false, depth + 1, out value))
                {
                    return true;
                }

                value = new ResolvedValue($"<field {fieldRef.Name}>", null, false);
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldsfld && instruction.Operand is FieldReference staticFieldRef)
            {
                if (TryResolveFieldValueInMethod(context, containingMethod, instructions, producerIndex - 1,
                        staticFieldRef, true, depth + 1, out value) ||
                    TryResolveFieldValueAcrossModule(context, staticFieldRef, true, depth + 1, out value))
                {
                    return true;
                }

                value = new ResolvedValue($"<static-field {staticFieldRef.Name}>", null, false);
                return true;
            }

            if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt ||
                 instruction.OpCode == OpCodes.Newobj) &&
                instruction.Operand is MethodReference methodRef)
            {
                if (TryResolveMethodCallValue(context, containingMethod, instructions, producerIndex, methodRef,
                        depth + 1, out value))
                    return true;

                value = new ResolvedValue($"<dynamic via {methodRef.Name}>", null, false);
                return true;
            }

            value = new ResolvedValue($"<dynamic via {instruction.OpCode.Code}>", null, false);
            return true;
        }

        private static bool TryResolveLocalValue(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int beforeIndex,
            int localIndex,
            Dictionary<int, ResolvedValue>? argumentMap,
            int depth,
            out ResolvedValue value)
        {
            value = default;

            for (int i = beforeIndex; i >= 0; i--)
            {
                var instruction = instructions[i];
                if (!TryGetStoredLocalIndex(instruction, out int storedIndex) || storedIndex != localIndex)
                    continue;

                return TryResolveTopStackValue(context, containingMethod, instructions, i - 1, argumentMap, depth + 1,
                    out value, out _);
            }

            return false;
        }

        private static bool TryResolveFieldValueInMethod(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int beforeIndex,
            FieldReference field,
            bool isStatic,
            int depth,
            out ResolvedValue value)
        {
            value = default;

            for (int i = beforeIndex; i >= 0; i--)
            {
                var instruction = instructions[i];
                bool isStore = isStatic ? instruction.OpCode == OpCodes.Stsfld : instruction.OpCode == OpCodes.Stfld;
                if (!isStore || instruction.Operand is not FieldReference candidate)
                    continue;

                if (!string.Equals(candidate.FullName, field.FullName, StringComparison.Ordinal))
                    continue;

                return TryResolveTopStackValue(context, containingMethod, instructions, i - 1, null, depth + 1,
                    out value, out _);
            }

            return false;
        }

        private static bool TryResolveFieldValueAcrossModule(
            ResolverContext context,
            FieldReference field,
            bool isStatic,
            int depth,
            out ResolvedValue value)
        {
            value = default;

            if (context.Module == null || depth > MaxDepth)
                return false;

            string key = field.FullName + (isStatic ? "|S" : "|I");
            if (!context.VisitedFields.Add(key))
                return false;

            try
            {
                bool found = false;
                ResolvedValue best = default;

                foreach (var type in context.Module.GetTypes())
                {
                    foreach (var method in type.Methods)
                    {
                        if (!method.HasBody)
                            continue;

                        var methodInstructions = method.Body.Instructions;
                        for (int i = methodInstructions.Count - 1; i >= 0; i--)
                        {
                            var instruction = methodInstructions[i];
                            bool isStore = isStatic
                                ? instruction.OpCode == OpCodes.Stsfld
                                : instruction.OpCode == OpCodes.Stfld;
                            if (!isStore || instruction.Operand is not FieldReference candidate)
                                continue;

                            if (!string.Equals(candidate.FullName, field.FullName, StringComparison.Ordinal))
                                continue;

                            if (!TryResolveTopStackValue(context, method, methodInstructions, i - 1, null, depth + 1,
                                    out var resolved, out _))
                                continue;

                            if (!found || IsBetterCandidate(resolved, best))
                            {
                                best = resolved;
                                found = true;
                            }

                            if (HasHighConfidence(best))
                            {
                                value = best;
                                return true;
                            }
                        }
                    }
                }

                if (found)
                {
                    value = best;
                    return true;
                }

                return false;
            }
            finally
            {
                context.VisitedFields.Remove(key);
            }
        }

        private static bool TryResolveMethodCallValue(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int producerIndex,
            MethodReference method,
            int depth,
            out ResolvedValue value)
        {
            value = default;

            if (depth > MaxDepth)
                return false;

            int parameterCount = method.Parameters.Count;
            if (!TryResolveCallArguments(context, containingMethod, instructions, producerIndex, parameterCount, null,
                    depth + 1, out var callArgs))
                callArgs = new List<ResolvedValue>();

            string declaringType = method.DeclaringType?.FullName ?? string.Empty;

            if (declaringType == "System.IO.Path")
            {
                if (method.Name == "Combine" || method.Name == "Join" || method.Name == "GetFullPath" ||
                    method.Name == "GetFileName")
                {
                    string composed = callArgs.Count > 0
                        ? CombinePathLikeArguments(callArgs)
                        : $"<dynamic via Path.{method.Name}>";
                    bool isConcrete = callArgs.Count > 0 && callArgs.All(a => a.IsConcrete);
                    value = new ResolvedValue(composed, ExtractExecutableName(composed), isConcrete);
                    return true;
                }

                if (method.Name == "GetTempPath")
                {
                    value = new ResolvedValue("%TEMP%", null, true);
                    return true;
                }
            }

            if (declaringType == "System.Guid" && method.Name == "NewGuid")
            {
                value = new ResolvedValue("<guid>", null, true);
                return true;
            }

            if (declaringType == "System.String")
            {
                if (method.Name == "Concat")
                {
                    string composed = string.Concat(callArgs.Select(a => a.Display));
                    value = new ResolvedValue(composed, ExtractExecutableName(composed),
                        callArgs.All(a => a.IsConcrete));
                    return true;
                }

                if (method.Name == "Format")
                {
                    if (TryApplySimpleStringFormat(callArgs, out string formatted))
                    {
                        bool isConcrete = callArgs.Skip(1).All(a => a.IsConcrete);
                        value = new ResolvedValue(formatted, ExtractExecutableName(formatted), isConcrete);
                        return true;
                    }

                    string composed = string.Concat(callArgs.Select(a => a.Display));
                    value = new ResolvedValue(composed, ExtractExecutableName(composed), false);
                    return true;
                }
            }

            if (declaringType == "System.Diagnostics.ProcessStartInfo" && method.Name == ".ctor" && callArgs.Count > 0)
            {
                value = callArgs[0];
                return true;
            }

            var resolvedMethod = method.Resolve();
            if (resolvedMethod != null && resolvedMethod.HasBody && context.Module != null &&
                resolvedMethod.Module == context.Module)
            {
                if (TryResolveMethodReturnValue(context, resolvedMethod, callArgs, depth + 1, out value))
                    return true;
            }

            value = new ResolvedValue($"<dynamic via {method.Name}>", null, false);
            return true;
        }

        private static bool TryResolveMethodReturnValue(
            ResolverContext context,
            MethodDefinition method,
            IReadOnlyList<ResolvedValue> callArgs,
            int depth,
            out ResolvedValue value)
        {
            value = default;

            if (depth > MaxDepth)
                return false;

            if (!context.VisitedMethods.Add(method.FullName))
                return false;

            try
            {
                var argMap = new Dictionary<int, ResolvedValue>();
                if (method.HasThis)
                    argMap[0] = new ResolvedValue("<this>", null, false);

                for (int i = 0; i < callArgs.Count; i++)
                {
                    int ilIndex = method.HasThis ? i + 1 : i;
                    argMap[ilIndex] = callArgs[i];
                }

                var instructions = method.Body.Instructions;
                bool found = false;
                ResolvedValue best = default;

                for (int i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i].OpCode != OpCodes.Ret || i == 0)
                        continue;

                    if (!TryResolveTopStackValue(context, method, instructions, i - 1, argMap, depth + 1,
                            out var resolved, out _))
                        continue;

                    if (!found || IsBetterCandidate(resolved, best))
                    {
                        best = resolved;
                        found = true;
                    }

                    if (HasHighConfidence(best))
                        break;
                }

                if (found)
                {
                    value = best;
                    return true;
                }

                return false;
            }
            finally
            {
                context.VisitedMethods.Remove(method.FullName);
            }
        }

        private static bool IsBetterCandidate(ResolvedValue candidate, ResolvedValue currentBest)
        {
            return ScoreCandidate(candidate) > ScoreCandidate(currentBest);
        }

        private static bool TryApplySimpleStringFormat(
            IReadOnlyList<ResolvedValue> callArgs,
            out string formatted)
        {
            formatted = string.Empty;

            if (callArgs.Count == 0)
                return false;

            string template = callArgs[0].Display;
            if (string.IsNullOrWhiteSpace(template) || template.StartsWith("<", StringComparison.Ordinal))
                return false;

            var formatArgs = callArgs.Skip(1).Select(a => a.Display).ToList();
            bool replacedAny = false;

            formatted = FormatItemRegex.Replace(template, match =>
            {
                if (!int.TryParse(match.Groups[1].Value, out int argIndex))
                    return match.Value;

                if (argIndex < 0 || argIndex >= formatArgs.Count)
                    return match.Value;

                replacedAny = true;
                return formatArgs[argIndex];
            });

            if (replacedAny)
            {
                formatted = formatted.Replace("{{", "{").Replace("}}", "}");
                return true;
            }

            return false;
        }

        private static string CombinePathLikeArguments(IReadOnlyList<ResolvedValue> callArgs)
        {
            var parts = callArgs
                .Select(arg => arg.Display)
                .Where(display => !string.IsNullOrWhiteSpace(display))
                .ToList();

            if (parts.Count == 0)
                return "<dynamic via Path.Combine>";

            string combined = parts[0];
            for (int i = 1; i < parts.Count; i++)
            {
                var left = combined.TrimEnd('/', '\\');
                var right = parts[i].TrimStart('/', '\\');
                combined = string.IsNullOrEmpty(left) ? right : $"{left}/{right}";
            }

            return combined;
        }

        private static int ScoreCandidate(ResolvedValue value)
        {
            int score = 0;
            if (!string.IsNullOrEmpty(value.ExecutableName))
                score += 6;
            if (value.IsConcrete)
                score += 2;
            if (!value.Display.StartsWith("<", StringComparison.Ordinal))
                score += 1;

            return score;
        }

        private static bool HasHighConfidence(ResolvedValue value)
        {
            return !string.IsNullOrEmpty(value.ExecutableName) && value.IsConcrete;
        }

        private static string BuildTargetDisplay(ResolvedValue value)
        {
            if (!string.IsNullOrEmpty(value.ExecutableName))
                return Quote(value.ExecutableName!);

            if (value.IsConcrete && IsLikelyProcessTargetLiteral(value.Display))
                return Quote(value.Display);

            if (value.Display.StartsWith("<", StringComparison.Ordinal))
                return value.Display;

            string? extracted = ExtractExecutableName(value.Display);
            if (!string.IsNullOrEmpty(extracted))
                return Quote(extracted);

            return "<unknown/non-literal>";
        }

        private static string Quote(string value)
        {
            return $"\"{value}\"";
        }

        private static string? ExtractExecutableName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            var match = ExecutableNameRegex.Match(value);
            if (!match.Success)
                return null;

            return match.Groups[1].Value;
        }

        private static bool IsLikelyProcessTargetLiteral(string literal)
        {
            if (string.IsNullOrWhiteSpace(literal))
                return false;

            string normalized = literal.Trim();
            return normalized.Contains(".exe", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains(".bat", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains(".cmd", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains(".ps1", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains(".msi", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Contains("\\") ||
                   normalized.Contains("/");
        }

        private static int GetPushCount(Instruction instruction)
        {
            if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                instruction.Operand is MethodReference method)
                return method.ReturnType?.FullName == "System.Void" ? 0 : 1;

            if (instruction.OpCode == OpCodes.Newobj)
                return 1;

            return instruction.OpCode.StackBehaviourPush switch
            {
                StackBehaviour.Push0 => 0,
                StackBehaviour.Push1 => 1,
                StackBehaviour.Pushi => 1,
                StackBehaviour.Pushi8 => 1,
                StackBehaviour.Pushr4 => 1,
                StackBehaviour.Pushr8 => 1,
                StackBehaviour.Pushref => 1,
                StackBehaviour.Push1_push1 => 2,
                _ => 0
            };
        }

        private static bool TryResolveInt32Literal(Instruction instruction, out int value)
        {
            value = instruction.OpCode.Code switch
            {
                Code.Ldc_I4_M1 => -1,
                Code.Ldc_I4_0 => 0,
                Code.Ldc_I4_1 => 1,
                Code.Ldc_I4_2 => 2,
                Code.Ldc_I4_3 => 3,
                Code.Ldc_I4_4 => 4,
                Code.Ldc_I4_5 => 5,
                Code.Ldc_I4_6 => 6,
                Code.Ldc_I4_7 => 7,
                Code.Ldc_I4_8 => 8,
                _ => int.MinValue
            };

            if (value != int.MinValue)
                return true;

            if (instruction.OpCode == OpCodes.Ldc_I4 && instruction.Operand is int intOperand)
            {
                value = intOperand;
                return true;
            }

            if (instruction.OpCode == OpCodes.Ldc_I4_S && instruction.Operand is sbyte shortOperand)
            {
                value = shortOperand;
                return true;
            }

            value = 0;
            return false;
        }

        private static int GetPopCount(Instruction instruction)
        {
            if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt) &&
                instruction.Operand is MethodReference method)
            {
                int count = method.Parameters.Count;
                if (method.HasThis)
                    count++;

                return count;
            }

            if (instruction.OpCode == OpCodes.Newobj && instruction.Operand is MethodReference ctor)
                return ctor.Parameters.Count;

            return instruction.OpCode.StackBehaviourPop switch
            {
                StackBehaviour.Pop0 => 0,
                StackBehaviour.Pop1 => 1,
                StackBehaviour.Popi => 1,
                StackBehaviour.Popref => 1,
                StackBehaviour.Pop1_pop1 => 2,
                StackBehaviour.Popi_pop1 => 2,
                StackBehaviour.Popi_popi => 2,
                StackBehaviour.Popi_popi8 => 2,
                StackBehaviour.Popi_popr4 => 2,
                StackBehaviour.Popi_popr8 => 2,
                StackBehaviour.Popi_popi_popi => 3,
                _ => 0
            };
        }

        private static bool TryGetLocalIndex(Instruction instruction, out int index)
        {
            index = instruction.OpCode.Code switch
            {
                Code.Ldloc_0 => 0,
                Code.Ldloc_1 => 1,
                Code.Ldloc_2 => 2,
                Code.Ldloc_3 => 3,
                _ => -1
            };

            if (index >= 0)
                return true;

            if (instruction.OpCode.Code == Code.Ldloc_S && instruction.Operand is VariableDefinition localS)
            {
                index = localS.Index;
                return true;
            }

            if (instruction.OpCode.Code == Code.Ldloc && instruction.Operand is VariableDefinition local)
            {
                index = local.Index;
                return true;
            }

            return false;
        }

        private static bool TryGetStoredLocalIndex(Instruction instruction, out int index)
        {
            index = instruction.OpCode.Code switch
            {
                Code.Stloc_0 => 0,
                Code.Stloc_1 => 1,
                Code.Stloc_2 => 2,
                Code.Stloc_3 => 3,
                _ => -1
            };

            if (index >= 0)
                return true;

            if (instruction.OpCode.Code == Code.Stloc_S && instruction.Operand is VariableDefinition localS)
            {
                index = localS.Index;
                return true;
            }

            if (instruction.OpCode.Code == Code.Stloc && instruction.Operand is VariableDefinition local)
            {
                index = local.Index;
                return true;
            }

            return false;
        }

        private static bool TryGetArgumentIndex(Instruction instruction, out int index)
        {
            index = instruction.OpCode.Code switch
            {
                Code.Ldarg_0 => 0,
                Code.Ldarg_1 => 1,
                Code.Ldarg_2 => 2,
                Code.Ldarg_3 => 3,
                _ => -1
            };

            if (index >= 0)
                return true;

            if (instruction.OpCode.Code == Code.Ldarg_S && instruction.Operand is ParameterDefinition parameterS)
            {
                index = parameterS.Index;
                return true;
            }

            if (instruction.OpCode.Code == Code.Ldarg && instruction.Operand is ParameterDefinition parameter)
            {
                index = parameter.Index;
                return true;
            }

            return false;
        }

        private sealed class ResolverContext
        {
            public ResolverContext(ModuleDefinition? module)
            {
                Module = module;
            }

            public ModuleDefinition? Module { get; }
            public HashSet<string> VisitedFields { get; } = new HashSet<string>(StringComparer.Ordinal);
            public HashSet<string> VisitedMethods { get; } = new HashSet<string>(StringComparer.Ordinal);
        }

        private struct ResolvedValue
        {
            public ResolvedValue(string display, string? executableName, bool isConcrete)
            {
                Display = display;
                ExecutableName = executableName;
                IsConcrete = isConcrete;
            }

            public string Display { get; }
            public string? ExecutableName { get; }
            public bool IsConcrete { get; }

            public static ResolvedValue FromLiteral(string literal)
            {
                return new ResolvedValue(literal, ExtractExecutableName(literal), true);
            }
        }
    }
}
