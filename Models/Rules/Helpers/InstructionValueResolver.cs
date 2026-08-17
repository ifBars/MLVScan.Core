using System.Text.RegularExpressions;
using System.Runtime.CompilerServices;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    /// <summary>
    /// Resolves literal and simple computed values from IL so rules can report concrete process targets,
    /// arguments, and related metadata instead of placeholder stack values.
    /// </summary>
    internal static class InstructionValueResolver
    {
        private const int MaxDepth = 16;
        private const int MaxTrackedCallArguments = 32;

        private static readonly ConditionalWeakTable<
            Mono.Collections.Generic.Collection<Instruction>, CallArgumentProducerMapCache> CallArgumentProducerMaps = new();

        private static readonly ConditionalWeakTable<
            Mono.Collections.Generic.Collection<Instruction>, Dictionary<Instruction, int>> InstructionIndexMaps = new();

        private static readonly ConditionalWeakTable<
            Mono.Collections.Generic.Collection<Instruction>, ExceptionalTargetCache> ExceptionalTargetCaches = new();

        private static readonly Regex ExecutableNameRegex =
            new Regex(@"([A-Za-z0-9._-]+\.(?:exe|bat|cmd|com|ps1|msi))",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private static readonly Regex FormatItemRegex =
            new Regex(@"\{(\d+)(?:[^}]*)\}", RegexOptions.CultureInvariant);

        private static readonly HashSet<string> TrustedFrameworkAssemblyNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "mscorlib",
            "netstandard",
            "System",
            "System.Diagnostics.Process",
            "System.Runtime"
        };

        internal static bool IsTrustedFrameworkMethod(
            MethodReference method,
            string declaringType,
            string methodName,
            bool allowDetachedReference = false)
        {
            if (method.DeclaringType?.FullName != declaringType || method.Name != methodName)
                return false;

            var scope = method.DeclaringType.Scope;
            if (scope is AssemblyNameReference assemblyReference)
                return TrustedFrameworkAssemblyNames.Contains(assemblyReference.Name);

            // Unit tests construct detached Cecil references without a module or resolution scope.
            // Production references must identify a known framework assembly explicitly.
            return allowDetachedReference && scope == null && method.Module == null;
        }

        /// <summary>
        /// Tries to resolve the executable or command target passed to a process-launching call.
        /// </summary>
        /// <param name="containingMethod">The method containing the call site.</param>
        /// <param name="calledMethod">The method being invoked.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="processStartIndex">The call instruction index.</param>
        /// <param name="target">Receives a display string for the resolved target.</param>
        /// <returns><see langword="true"/> when a concrete target could be reconstructed.</returns>
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

        /// <summary>
        /// Tries to resolve the argument string passed to a process-launching call.
        /// </summary>
        /// <param name="containingMethod">The method containing the call site.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="processStartIndex">The call instruction index.</param>
        /// <param name="arguments">Receives the resolved argument display string.</param>
        /// <returns><see langword="true"/> when the arguments could be reconstructed.</returns>
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

        /// <summary>
        /// Tries to resolve the top-of-stack value immediately before a call site for display purposes.
        /// </summary>
        /// <param name="containingMethod">The method containing the instruction sequence.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="beforeIndex">The instruction index immediately before the value is consumed.</param>
        /// <param name="valueDisplay">Receives a human-readable representation of the resolved value.</param>
        /// <returns><see langword="true"/> when a literal or simple computed value could be reconstructed.</returns>
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

        /// <summary>
        /// Tries to resolve one argument passed to a call site. This is used by data-flow analysis to
        /// compare file-write destinations with later process targets without relying on nearby calls.
        /// </summary>
        public static bool TryResolveCallArgumentDisplay(
            MethodDefinition? containingMethod,
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int argumentIndex,
            out string valueDisplay)
        {
            return TryResolveCallArgumentDisplay(containingMethod, calledMethod, instructions, callIndex,
                argumentIndex, Array.Empty<ExceptionHandler>(), out valueDisplay);
        }

        public static bool TryResolveCallArgumentDisplay(
            MethodDefinition? containingMethod,
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int argumentIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out string valueDisplay)
        {
            valueDisplay = "<unknown/non-literal>";
            if (argumentIndex < 0 || argumentIndex >= calledMethod.Parameters.Count)
            {
                return false;
            }

            var context = new ResolverContext(containingMethod?.Module);
            if (TryResolveCallArgumentFromBasicBlock(context, containingMethod, instructions, callIndex,
                    calledMethod.Parameters.Count, argumentIndex, exceptionHandlers, out valueDisplay))
            {
                return true;
            }

            if (!TryResolveCallArguments(context, containingMethod, instructions, callIndex,
                    calledMethod.Parameters.Count, null, 0, out var arguments))
            {
                return false;
            }

            valueDisplay = arguments[argumentIndex].Display;
            return true;
        }

        /// <summary>
        /// Tries to identify the receiver consumed by an instance call.
        /// </summary>
        public static bool TryResolveCallReceiverIdentity(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            out string identity)
        {
            return TryResolveCallReceiverIdentity(
                instructions, callIndex, Array.Empty<ExceptionHandler>(), out identity);
        }

        public static bool TryResolveCallReceiverIdentity(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out string identity)
        {
            identity = string.Empty;
            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            return producerMap.TryGetReceiverProducer(callIndex, out int producerIndex) &&
                   TryBuildProducerIdentity(instructions, producerIndex, exceptionHandlers, out identity);
        }

        /// <summary>
        /// Tries to identify one argument consumed by a call.
        /// </summary>
        public static bool TryResolveCallArgumentIdentity(
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int argumentIndex,
            out string identity)
        {
            return TryResolveCallArgumentIdentity(calledMethod, instructions, callIndex, argumentIndex,
                Array.Empty<ExceptionHandler>(), out identity);
        }

        public static bool TryResolveCallArgumentIdentity(
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int argumentIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out string identity)
        {
            identity = string.Empty;
            if (argumentIndex < 0 || argumentIndex >= calledMethod.Parameters.Count)
                return false;

            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            return producerMap.TryGetProducer(callIndex, calledMethod.Parameters.Count, argumentIndex,
                       out int producerIndex) &&
                   TryBuildProducerIdentity(instructions, producerIndex, exceptionHandlers, out identity);
        }

        public static bool IsGuaranteedToExecuteBefore(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int instructionIndex,
            int useIndex)
        {
            if (instructions == null || instructionIndex < 0 || useIndex < 0 ||
                instructionIndex >= instructions.Count || useIndex >= instructions.Count)
            {
                return false;
            }

            if (HasRelevantUnsupportedHandler(instructions, exceptionHandlers, instructionIndex, useIndex))
                return false;

            if (!TryBuildExceptionalTargets(instructions, exceptionHandlers, out var exceptionTargets))
                return false;

            var instructionIndexes = InstructionIndexMaps.GetValue(instructions, BuildInstructionIndexMap);

            var pending = new Queue<(int Index, bool Executed)>();
            var visited = new HashSet<(int Index, bool Executed)>();
            pending.Enqueue((0, false));
            foreach (var handler in exceptionHandlers)
            {
                int handlerEndIndex = instructions.Count;
                if (handler.HandlerType == ExceptionHandlerType.Catch ||
                    !instructionIndexes.TryGetValue(handler.HandlerStart, out int handlerStartIndex) ||
                    (handler.HandlerEnd != null &&
                     !instructionIndexes.TryGetValue(handler.HandlerEnd, out handlerEndIndex)))
                {
                    continue;
                }

                if (instructionIndex >= handlerStartIndex && instructionIndex < handlerEndIndex &&
                    useIndex >= handlerStartIndex && useIndex < handlerEndIndex)
                {
                    pending.Enqueue((handlerStartIndex, false));
                }
            }
            bool reachedUse = false;

            while (pending.Count > 0)
            {
                var current = pending.Dequeue();
                if (current.Index < 0 || current.Index >= instructions.Count || !visited.Add(current))
                    continue;

                if (current.Index == useIndex)
                {
                    reachedUse = true;
                    if (!current.Executed)
                        return false;

                    continue;
                }

                bool executed = current.Executed || current.Index == instructionIndex;
                var instruction = instructions[current.Index];

                if (exceptionTargets.TryGetValue(current.Index, out var handlerTargets))
                {
                    foreach (var handlerTarget in handlerTargets)
                    {
                        // A protected instruction may transfer to the handler before completing.
                        pending.Enqueue((handlerTarget, current.Executed));
                    }
                }

                if (instruction.Operand is Instruction target)
                {
                    if (!instructionIndexes.TryGetValue(target, out int targetIndex))
                        return false;

                    pending.Enqueue((targetIndex, executed));
                }
                else if (instruction.Operand is Instruction[] targets)
                {
                    foreach (var switchTarget in targets)
                    {
                        if (!instructionIndexes.TryGetValue(switchTarget, out int targetIndex))
                            return false;

                        pending.Enqueue((targetIndex, executed));
                    }
                }

                var flowControl = instruction.OpCode.FlowControl;
                if (flowControl is not FlowControl.Branch and not FlowControl.Return and not FlowControl.Throw)
                    pending.Enqueue((current.Index + 1, executed));
            }

            return reachedUse;
        }

        public static bool CanExecuteBetween(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int startIndex,
            int candidateIndex,
            int useIndex)
        {
            if (instructions == null || startIndex < 0 || candidateIndex < 0 || useIndex < 0 ||
                startIndex >= instructions.Count || candidateIndex >= instructions.Count || useIndex >= instructions.Count ||
                HasRelevantUnsupportedHandler(instructions, exceptionHandlers, startIndex, useIndex) ||
                !TryBuildExceptionalTargets(instructions, exceptionHandlers, out var exceptionTargets))
            {
                return true;
            }

            var instructionIndexes = InstructionIndexMaps.GetValue(instructions, BuildInstructionIndexMap);
            var pending = new Queue<(int Index, bool CandidateSeen)>();
            var visited = new HashSet<(int Index, bool CandidateSeen)>();
            pending.Enqueue((startIndex, startIndex == candidateIndex));

            while (pending.Count > 0)
            {
                var current = pending.Dequeue();
                if (current.Index < 0 || current.Index >= instructions.Count || !visited.Add(current))
                    continue;

                if (current.Index == useIndex)
                {
                    if (current.CandidateSeen)
                        return true;
                }

                var instruction = instructions[current.Index];
                bool candidateSeen = current.CandidateSeen || current.Index == candidateIndex;

                if (exceptionTargets.TryGetValue(current.Index, out var handlerTargets))
                {
                    foreach (var handlerTarget in handlerTargets)
                        pending.Enqueue((handlerTarget, current.CandidateSeen));
                }

                if (instruction.Operand is Instruction target)
                {
                    if (!instructionIndexes.TryGetValue(target, out int targetIndex))
                        return true;

                    pending.Enqueue((targetIndex, candidateSeen));
                }
                else if (instruction.Operand is Instruction[] targets)
                {
                    foreach (var switchTarget in targets)
                    {
                        if (!instructionIndexes.TryGetValue(switchTarget, out int targetIndex))
                            return true;

                        pending.Enqueue((targetIndex, candidateSeen));
                    }
                }

                var flowControl = instruction.OpCode.FlowControl;
                if (flowControl is not FlowControl.Branch and not FlowControl.Return and not FlowControl.Throw)
                    pending.Enqueue((current.Index + 1, candidateSeen));
            }

            return false;
        }

        private static bool TryBuildExceptionalTargets(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out Dictionary<int, List<int>> exceptionTargets)
        {
            var cache = ExceptionalTargetCaches.GetValue(instructions, static _ => new ExceptionalTargetCache());
            lock (cache.Gate)
            {
                if (cache.Matches(exceptionHandlers))
                {
                    exceptionTargets = cache.Targets;
                    return cache.IsValid;
                }

                const int maxExceptionalEdges = 4096;
                var instructionIndexes = InstructionIndexMaps.GetValue(instructions, BuildInstructionIndexMap);
                var targetsByInstruction = new Dictionary<int, List<int>>();
                int exceptionalEdgeCount = 0;
                bool isValid = true;
                foreach (var handler in exceptionHandlers)
                {
                    if (!instructionIndexes.TryGetValue(handler.TryStart, out int tryStartIndex) ||
                        (handler.TryEnd != null && !instructionIndexes.TryGetValue(handler.TryEnd, out _)) ||
                        !instructionIndexes.TryGetValue(handler.HandlerStart, out int handlerStartIndex))
                    {
                        isValid = false;
                        break;
                    }

                    int tryEndIndex = handler.TryEnd == null
                        ? instructions.Count
                        : instructionIndexes[handler.TryEnd];
                    if (tryEndIndex < tryStartIndex)
                    {
                        isValid = false;
                        break;
                    }

                    // Non-catch handlers require query-specific treatment. They are rejected by
                    // HasRelevantUnsupportedHandler only when they can run between the value's
                    // definition and use; otherwise they cannot affect the resolved value.
                    if (handler.HandlerType != ExceptionHandlerType.Catch)
                        continue;

                    for (int i = tryStartIndex; i < tryEndIndex; i++)
                    {
                        if (++exceptionalEdgeCount > maxExceptionalEdges)
                        {
                            isValid = false;
                            break;
                        }

                        if (!targetsByInstruction.TryGetValue(i, out var targets))
                        {
                            targets = new List<int>();
                            targetsByInstruction[i] = targets;
                        }

                        targets.Add(handlerStartIndex);
                    }

                    if (!isValid)
                        break;
                }

                cache.Update(exceptionHandlers, targetsByInstruction, isValid);
                exceptionTargets = cache.Targets;
                return cache.IsValid;
            }
        }

        private static bool HasRelevantUnsupportedHandler(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int startIndex,
            int useIndex)
        {
            var instructionIndexes = InstructionIndexMaps.GetValue(instructions, BuildInstructionIndexMap);
            foreach (var handler in exceptionHandlers)
            {
                if (handler.HandlerType == ExceptionHandlerType.Catch)
                    continue;

                int tryEndIndex = instructions.Count;
                int handlerEndIndex = instructions.Count;
                if (!instructionIndexes.TryGetValue(handler.TryStart, out int tryStartIndex) ||
                    !instructionIndexes.TryGetValue(handler.HandlerStart, out int handlerStartIndex) ||
                    (handler.TryEnd != null && !instructionIndexes.TryGetValue(handler.TryEnd, out tryEndIndex)) ||
                    (handler.HandlerEnd != null &&
                     !instructionIndexes.TryGetValue(handler.HandlerEnd, out handlerEndIndex)))
                {
                    return true;
                }

                if (tryEndIndex < tryStartIndex || handlerEndIndex < handlerStartIndex)
                    return true;

                // A use inside the protected region happens before its finally/fault handler.
                // A definition and use inside the same handler do not cross that handler. A handler
                // wholly before the definition or after the use is likewise unrelated.
                if ((useIndex >= tryStartIndex && useIndex < tryEndIndex) ||
                    (startIndex >= handlerStartIndex && startIndex < handlerEndIndex &&
                     useIndex >= handlerStartIndex && useIndex < handlerEndIndex) ||
                    useIndex < tryStartIndex ||
                    startIndex >= handlerEndIndex)
                {
                    continue;
                }

                return true;
            }

            return false;
        }

        private static Dictionary<Instruction, int> BuildInstructionIndexMap(
            Mono.Collections.Generic.Collection<Instruction> instructions)
        {
            var indexes = new Dictionary<Instruction, int>(instructions.Count);
            for (int i = 0; i < instructions.Count; i++)
                indexes[instructions[i]] = i;

            return indexes;
        }

        public static bool TryResolveCallArgumentProducerIndex(
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int argumentIndex,
            out int producerIndex)
        {
            return TryResolveCallArgumentProducerIndex(calledMethod, instructions, callIndex, argumentIndex,
                Array.Empty<ExceptionHandler>(), out producerIndex);
        }

        public static bool TryResolveCallArgumentProducerIndex(
            MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int argumentIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out int producerIndex)
        {
            producerIndex = -1;
            if (argumentIndex < 0 || argumentIndex >= calledMethod.Parameters.Count)
                return false;

            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            return producerMap.TryGetProducer(callIndex, calledMethod.Parameters.Count, argumentIndex,
                out producerIndex);
        }

        public static bool TryResolveStoredValueIdentity(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int storeIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out string identity)
        {
            identity = string.Empty;
            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            return producerMap.TryGetStoredValueProducer(storeIndex, out int producerIndex) &&
                   TryBuildProducerIdentity(instructions, producerIndex, exceptionHandlers, out identity);
        }

        private static bool TryBuildProducerIdentity(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int producerIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out string identity)
        {
            return TryBuildProducerIdentity(instructions, producerIndex, exceptionHandlers, 0, out identity);
        }

        private static bool TryBuildProducerIdentity(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int producerIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int depth,
            out string identity)
        {
            identity = string.Empty;
            if (producerIndex < 0 || producerIndex >= instructions.Count || depth > MaxDepth)
                return false;

            var producer = instructions[producerIndex];
            if (TryGetLoadedLocalIndex(producer, out int localIndex))
            {
                return TryResolveEquivalentReachingDefinitions(instructions, exceptionHandlers, producerIndex,
                    instruction => TryGetStoredLocalIndex(instruction, out int storedIndex) &&
                                   storedIndex == localIndex,
                    depth, out identity, invalidatesDefinition: instruction =>
                        TryGetLoadedLocalAddressIndex(instruction, out int escapedLocalIndex) &&
                        escapedLocalIndex == localIndex);
            }

            if (TryGetLoadedArgumentIndex(producer, out int argumentIndex))
            {
                bool hasArgumentStore = false;
                for (int i = 0; i < instructions.Count; i++)
                {
                    if (TryGetLoadedArgumentAddressIndex(instructions[i], out int escapedArgumentIndex) &&
                        escapedArgumentIndex == argumentIndex)
                    {
                        return false;
                    }

                    if (TryGetStoredArgumentIndex(instructions[i], out int storedArgumentIndex) &&
                        storedArgumentIndex == argumentIndex)
                    {
                        hasArgumentStore = true;
                    }
                }

                if (hasArgumentStore)
                    return TryResolveEquivalentReachingDefinitions(instructions, exceptionHandlers, producerIndex,
                        instruction => TryGetStoredArgumentIndex(instruction, out int storedIndex) &&
                                       storedIndex == argumentIndex,
                        depth, out identity, invalidatesDefinition: instruction =>
                            TryGetLoadedArgumentAddressIndex(instruction, out int escapedIndex) &&
                            escapedIndex == argumentIndex);
            }

            if (producer.Operand is FieldReference loadedField &&
                producer.OpCode.Code is Code.Ldfld or Code.Ldsfld)
            {
                var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
                string receiverIdentity = string.Empty;
                if (producer.OpCode.Code == Code.Ldfld &&
                    (!producerMap.TryGetFieldReceiverProducer(producerIndex, out int receiverProducer) ||
                     !TryBuildProducerIdentity(instructions, receiverProducer, exceptionHandlers,
                         depth + 1, out receiverIdentity)))
                {
                    return false;
                }

                return TryResolveEquivalentReachingDefinitions(instructions, exceptionHandlers, producerIndex,
                    instruction => IsMatchingFieldStore(instruction, loadedField,
                        producer.OpCode.Code == Code.Ldsfld), depth, out identity,
                    receiverIdentity, instruction => IsPotentialFieldMutation(instruction, loadedField.FieldType));
            }

            identity = producer.OpCode.Code switch
            {
                Code.Ldarg_0 => "argument:0",
                Code.Ldarg_1 => "argument:1",
                Code.Ldarg_2 => "argument:2",
                Code.Ldarg_3 => "argument:3",
                Code.Ldarg or Code.Ldarg_S when producer.Operand is ParameterDefinition parameter =>
                    $"argument:{parameter.Index + (parameter.Method?.HasThis == true ? 1 : 0)}",
                Code.Ldstr => $"literal:{producerIndex}",
                Code.Newobj => $"new:{producerIndex}",
                Code.Call or Code.Callvirt => $"call:{producerIndex}",
                _ => string.Empty
            };

            return identity.Length > 0;
        }

        private static bool IsMatchingFieldStore(Instruction instruction, FieldReference loadedField, bool isStatic)
        {
            return instruction.Operand is FieldReference storedField &&
                   storedField.FullName == loadedField.FullName &&
                   instruction.OpCode.Code == (isStatic ? Code.Stsfld : Code.Stfld);
        }

        private static bool IsPotentialFieldMutation(Instruction instruction, TypeReference fieldType)
        {
            if (fieldType.FullName == "System.Diagnostics.ProcessStartInfo" &&
                instruction.Operand is MethodReference method &&
                ((method.DeclaringType?.FullName, method.Name) is
                    ("System.Diagnostics.Process", "GetCurrentProcess") or
                    ("System.Diagnostics.Process", "get_MainModule") or
                    ("System.Diagnostics.ProcessModule", "get_FileName") ||
                 method.DeclaringType?.FullName == "System.Diagnostics.ProcessStartInfo"))
            {
                return false;
            }

            return instruction.OpCode.Code is
                Code.Call or Code.Callvirt or Code.Calli or Code.Newobj or
                Code.Ldflda or Code.Ldsflda or
                Code.Stind_I or Code.Stind_I1 or Code.Stind_I2 or Code.Stind_I4 or Code.Stind_I8 or
                Code.Stind_R4 or Code.Stind_R8 or Code.Stind_Ref;
        }

        private static bool TryGetLoadedLocalIndex(Instruction instruction, out int localIndex)
        {
            localIndex = instruction.OpCode.Code switch
            {
                Code.Ldloc_0 => 0,
                Code.Ldloc_1 => 1,
                Code.Ldloc_2 => 2,
                Code.Ldloc_3 => 3,
                Code.Ldloc or Code.Ldloc_S when instruction.Operand is VariableDefinition variable => variable.Index,
                _ => -1
            };

            return localIndex >= 0;
        }

        private static bool TryGetLoadedLocalAddressIndex(Instruction instruction, out int localIndex)
        {
            localIndex = (instruction.OpCode.Code is Code.Ldloca or Code.Ldloca_S) &&
                         instruction.Operand is VariableDefinition variable
                ? variable.Index
                : -1;
            return localIndex >= 0;
        }

        private static bool TryGetLoadedArgumentAddressIndex(Instruction instruction, out int argumentIndex)
        {
            argumentIndex = (instruction.OpCode.Code is Code.Ldarga or Code.Ldarga_S) &&
                            instruction.Operand is ParameterDefinition parameter
                ? parameter.Index + (parameter.Method?.HasThis == true ? 1 : 0)
                : -1;
            return argumentIndex >= 0;
        }

        private static bool HasUnambiguousReachingDefinition(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int definitionIndex,
            int useIndex,
            Func<Instruction, bool> isCompetingStore)
        {
            const byte unresolved = 0;
            const byte expectedDefinition = 1;
            const byte overwritten = 2;

            var pending = new Queue<(int Index, byte State)>();
            var visited = new HashSet<(int Index, byte State)>();
            if (HasRelevantUnsupportedHandler(instructions, exceptionHandlers, definitionIndex, useIndex))
                return false;

            if (!TryBuildExceptionalTargets(instructions, exceptionHandlers, out var exceptionTargets))
                return false;

            var instructionIndexes = InstructionIndexMaps.GetValue(instructions, BuildInstructionIndexMap);

            pending.Enqueue((0, unresolved));
            bool reachedUse = false;

            while (pending.Count > 0)
            {
                var current = pending.Dequeue();
                if (current.Index < 0 || current.Index >= instructions.Count || !visited.Add(current))
                    continue;

                if (current.Index == useIndex)
                {
                    reachedUse = true;
                    if (current.State != expectedDefinition)
                        return false;

                    continue;
                }

                var instruction = instructions[current.Index];
                byte nextState = current.State;
                if (current.Index == definitionIndex)
                {
                    nextState = expectedDefinition;
                }
                else if (isCompetingStore(instruction))
                {
                    nextState = overwritten;
                }

                if (exceptionTargets.TryGetValue(current.Index, out var handlerTargets))
                {
                    foreach (var handlerTarget in handlerTargets)
                        pending.Enqueue((handlerTarget, current.State));
                }

                if (instruction.Operand is Instruction target)
                {
                    if (!instructionIndexes.TryGetValue(target, out int targetIndex))
                        return false;

                    pending.Enqueue((targetIndex, nextState));
                }
                else if (instruction.Operand is Instruction[] targets)
                {
                    foreach (var switchTarget in targets)
                    {
                        if (!instructionIndexes.TryGetValue(switchTarget, out int targetIndex))
                            return false;

                        pending.Enqueue((targetIndex, nextState));
                    }
                }

                var flowControl = instruction.OpCode.FlowControl;
                if (flowControl is not FlowControl.Branch and not FlowControl.Return and not FlowControl.Throw)
                    pending.Enqueue((current.Index + 1, nextState));
            }

            return reachedUse;
        }

        public static bool TryResolveEquivalentCallArgumentReachingDefinitions(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int useIndex,
            Func<Instruction, bool> isDefinition,
            int argumentIndex,
            out string identity)
        {
            return TryResolveEquivalentReachingDefinitions(
                instructions, exceptionHandlers, useIndex, isDefinition, 0, out identity,
                definitionIdentityResolver: (int definitionIndex, out string definitionIdentity) =>
                {
                    definitionIdentity = string.Empty;
                    return instructions[definitionIndex].Operand is MethodReference method &&
                           argumentIndex >= 0 && argumentIndex < method.Parameters.Count &&
                           TryResolveCallArgumentIdentity(method, instructions, definitionIndex, argumentIndex,
                               exceptionHandlers, out definitionIdentity);
                });
        }

        private static bool TryResolveEquivalentReachingDefinitions(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int useIndex,
            Func<Instruction, bool> isDefinition,
            int depth,
            out string identity,
            string requiredReceiverIdentity = "",
            Func<Instruction, bool>? invalidatesDefinition = null,
            TryResolveDefinitionIdentity? definitionIdentityResolver = null)
        {
            identity = string.Empty;
            if (!TryBuildExceptionalTargets(instructions, exceptionHandlers, out var exceptionTargets))
                return false;

            const int maxReachingDefinitions = 64;
            const int maxWorkUnits = 65_536;
            var instructionIndexes = InstructionIndexMaps.GetValue(instructions, BuildInstructionIndexMap);
            var pending = new Queue<(int Index, int DefinitionIndex)>();
            var visited = new HashSet<(int Index, int DefinitionIndex)>();
            var reachingDefinitions = new HashSet<int>();
            pending.Enqueue((0, -1));
            foreach (var handler in exceptionHandlers)
            {
                int handlerEndIndex = instructions.Count;
                if (handler.HandlerType == ExceptionHandlerType.Catch ||
                    !instructionIndexes.TryGetValue(handler.HandlerStart, out int handlerStartIndex) ||
                    (handler.HandlerEnd != null &&
                     !instructionIndexes.TryGetValue(handler.HandlerEnd, out handlerEndIndex)))
                {
                    continue;
                }

                if (useIndex >= handlerStartIndex && useIndex < handlerEndIndex)
                    pending.Enqueue((handlerStartIndex, -1));
            }
            int workUnits = 0;

            while (pending.Count > 0)
            {
                if (++workUnits > maxWorkUnits)
                    return false;

                var current = pending.Dequeue();
                if (current.Index < 0 || current.Index >= instructions.Count || !visited.Add(current))
                    continue;

                if (current.Index == useIndex)
                {
                    if (current.DefinitionIndex < 0 ||
                        reachingDefinitions.Count >= maxReachingDefinitions &&
                        !reachingDefinitions.Contains(current.DefinitionIndex))
                    {
                        return false;
                    }

                    reachingDefinitions.Add(current.DefinitionIndex);
                    continue;
                }

                var instruction = instructions[current.Index];
                int nextDefinition = isDefinition(instruction)
                    ? current.Index
                    : invalidatesDefinition?.Invoke(instruction) == true
                        ? -2
                        : current.DefinitionIndex;

                if (exceptionTargets.TryGetValue(current.Index, out var handlerTargets))
                {
                    int exceptionalDefinition = invalidatesDefinition?.Invoke(instruction) == true
                        ? -2
                        : current.DefinitionIndex;
                    foreach (var handlerTarget in handlerTargets)
                        pending.Enqueue((handlerTarget, exceptionalDefinition));
                }

                if (instruction.Operand is Instruction target)
                {
                    if (!instructionIndexes.TryGetValue(target, out int targetIndex))
                        return false;

                    pending.Enqueue((targetIndex, nextDefinition));
                }
                else if (instruction.Operand is Instruction[] targets)
                {
                    foreach (var switchTarget in targets)
                    {
                        if (!instructionIndexes.TryGetValue(switchTarget, out int targetIndex))
                            return false;

                        pending.Enqueue((targetIndex, nextDefinition));
                    }
                }

                var flowControl = instruction.OpCode.FlowControl;
                if (flowControl is not FlowControl.Branch and not FlowControl.Return and not FlowControl.Throw)
                    pending.Enqueue((current.Index + 1, nextDefinition));
            }

            if (reachingDefinitions.Count == 0)
                return false;

            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            foreach (int definitionIndex in reachingDefinitions)
            {
                if (HasRelevantUnsupportedHandler(instructions, exceptionHandlers, definitionIndex, useIndex))
                    return false;

                if (requiredReceiverIdentity.Length > 0)
                {
                    if (!producerMap.TryGetFieldReceiverProducer(definitionIndex, out int receiverProducer) ||
                        !TryBuildProducerIdentity(instructions, receiverProducer, exceptionHandlers,
                            depth + 1, out var receiverIdentity) ||
                        !receiverIdentity.Equals(requiredReceiverIdentity, StringComparison.Ordinal))
                    {
                        return false;
                    }
                }

                string definitionIdentity;
                if (definitionIdentityResolver != null)
                {
                    if (!definitionIdentityResolver(definitionIndex, out definitionIdentity))
                        return false;
                }
                else if (!producerMap.TryGetStoredValueProducer(definitionIndex, out int storedValueProducer) ||
                         !TryBuildProducerIdentity(instructions, storedValueProducer, exceptionHandlers,
                             depth + 1, out definitionIdentity))
                {
                    return false;
                }

                if (identity.Length == 0)
                    identity = definitionIdentity;
                else if (!AreEquivalentProducerIdentities(instructions, exceptionHandlers,
                             identity, definitionIdentity))
                    return false;
            }

            return identity.Length > 0;
        }

        private delegate bool TryResolveDefinitionIdentity(int definitionIndex, out string identity);

        private static bool AreEquivalentProducerIdentities(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            string left,
            string right)
        {
            if (left.Equals(right, StringComparison.Ordinal))
                return true;

            if (TryGetLiteralIdentityIndex(left, out int leftLiteralIndex) &&
                TryGetLiteralIdentityIndex(right, out int rightLiteralIndex) &&
                leftLiteralIndex >= 0 && leftLiteralIndex < instructions.Count &&
                rightLiteralIndex >= 0 && rightLiteralIndex < instructions.Count &&
                instructions[leftLiteralIndex].OpCode.Code == Code.Ldstr &&
                instructions[rightLiteralIndex].OpCode.Code == Code.Ldstr &&
                instructions[leftLiteralIndex].Operand is string leftLiteral &&
                instructions[rightLiteralIndex].Operand is string rightLiteral)
            {
                return leftLiteral.Equals(rightLiteral, StringComparison.Ordinal);
            }

            return TryGetCallIdentityIndex(left, out int leftIndex) &&
                   TryGetCallIdentityIndex(right, out int rightIndex) &&
                   IsCurrentProcessFileNameCall(instructions, exceptionHandlers, leftIndex) &&
                   IsCurrentProcessFileNameCall(instructions, exceptionHandlers, rightIndex);
        }

        private static bool TryGetCallIdentityIndex(string identity, out int index)
        {
            const string prefix = "call:";
            index = -1;
            return identity.StartsWith(prefix, StringComparison.Ordinal) &&
                   int.TryParse(identity.AsSpan(prefix.Length), out index);
        }

        private static bool TryGetLiteralIdentityIndex(string identity, out int index)
        {
            const string prefix = "literal:";
            index = -1;
            return identity.StartsWith(prefix, StringComparison.Ordinal) &&
                   int.TryParse(identity.AsSpan(prefix.Length), out index);
        }

        private static bool IsCurrentProcessFileNameCall(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            int fileNameIndex)
        {
            if (fileNameIndex < 0 || fileNameIndex >= instructions.Count ||
                instructions[fileNameIndex].Operand is not MethodReference fileName ||
                !IsTrustedFrameworkMethod(fileName,
                    "System.Diagnostics.ProcessModule", "get_FileName", allowDetachedReference: true))
            {
                return false;
            }

            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            return producerMap.TryGetReceiverProducer(fileNameIndex, out int mainModuleIndex) &&
                   mainModuleIndex >= 0 && mainModuleIndex < instructions.Count &&
                   instructions[mainModuleIndex].Operand is MethodReference mainModule &&
                   IsTrustedFrameworkMethod(mainModule,
                       "System.Diagnostics.Process", "get_MainModule", allowDetachedReference: true) &&
                   producerMap.TryGetReceiverProducer(mainModuleIndex, out int currentProcessIndex) &&
                   currentProcessIndex >= 0 && currentProcessIndex < instructions.Count &&
                   instructions[currentProcessIndex].Operand is MethodReference currentProcess &&
                   IsTrustedFrameworkMethod(currentProcess,
                       "System.Diagnostics.Process", "GetCurrentProcess", allowDetachedReference: true);
        }

        private sealed class ExceptionalTargetCache
        {
            public object Gate { get; } = new();

            public ExceptionHandler[] Handlers { get; private set; } = Array.Empty<ExceptionHandler>();

            public Dictionary<int, List<int>> Targets { get; private set; } = new();

            public bool IsValid { get; private set; } = true;

            public bool Matches(IReadOnlyList<ExceptionHandler> handlers)
            {
                if (Handlers.Length != handlers.Count)
                    return false;

                for (int i = 0; i < Handlers.Length; i++)
                {
                    if (!ReferenceEquals(Handlers[i], handlers[i]))
                        return false;
                }

                return true;
            }

            public void Update(
                IReadOnlyList<ExceptionHandler> handlers,
                Dictionary<int, List<int>> targets,
                bool isValid)
            {
                Handlers = handlers.ToArray();
                Targets = targets;
                IsValid = isValid;
            }
        }

        private static bool TryGetLoadedArgumentIndex(Instruction instruction, out int argumentIndex)
        {
            argumentIndex = instruction.OpCode.Code switch
            {
                Code.Ldarg_0 => 0,
                Code.Ldarg_1 => 1,
                Code.Ldarg_2 => 2,
                Code.Ldarg_3 => 3,
                Code.Ldarg or Code.Ldarg_S when instruction.Operand is ParameterDefinition parameter =>
                    parameter.Index + (parameter.Method?.HasThis == true ? 1 : 0),
                _ => -1
            };

            return argumentIndex >= 0;
        }

        private static bool TryGetStoredArgumentIndex(Instruction instruction, out int argumentIndex)
        {
            argumentIndex = instruction.OpCode.Code switch
            {
                Code.Starg or Code.Starg_S when instruction.Operand is ParameterDefinition parameter =>
                    parameter.Index + (parameter.Method?.HasThis == true ? 1 : 0),
                _ => -1
            };

            return argumentIndex >= 0;
        }

        private static bool TryGetStoredLocalIndex(Instruction instruction, out int localIndex)
        {
            localIndex = instruction.OpCode.Code switch
            {
                Code.Stloc_0 => 0,
                Code.Stloc_1 => 1,
                Code.Stloc_2 => 2,
                Code.Stloc_3 => 3,
                Code.Stloc or Code.Stloc_S when instruction.Operand is VariableDefinition variable => variable.Index,
                _ => -1
            };

            return localIndex >= 0;
        }

        private static bool TryResolveCallArgumentFromBasicBlock(
            ResolverContext context,
            MethodDefinition? containingMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int callIndex,
            int parameterCount,
            int argumentIndex,
            IReadOnlyList<ExceptionHandler> exceptionHandlers,
            out string valueDisplay)
        {
            valueDisplay = "<unknown/non-literal>";
            var producerMap = GetCallArgumentProducerMap(instructions, exceptionHandlers);
            if (!producerMap.TryGetProducer(callIndex, parameterCount, argumentIndex, out int producerIndex))
                return false;

            if (!TryResolveValueFromProducer(context, containingMethod, instructions, producerIndex, null, 1,
                    out var resolved))
            {
                return false;
            }

            valueDisplay = resolved.Display;
            return true;
        }

        private static CallArgumentProducerMap GetCallArgumentProducerMap(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers)
        {
            var cache = CallArgumentProducerMaps.GetValue(instructions, static _ => new CallArgumentProducerMapCache());
            lock (cache.Gate)
            {
                if (!cache.Matches(exceptionHandlers))
                    cache.Update(exceptionHandlers, BuildCallArgumentProducerMap(instructions, exceptionHandlers));

                return cache.Map;
            }
        }

        private static CallArgumentProducerMap BuildCallArgumentProducerMap(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyList<ExceptionHandler> exceptionHandlers)
        {
            var instructionIndices = new Dictionary<Instruction, int>(instructions.Count);
            for (int i = 0; i < instructions.Count; i++)
                instructionIndices[instructions[i]] = i;

            var producersByCallIndex = new Dictionary<int, CallProducers>();
            var producersByStoreIndex = new Dictionary<int, int>();
            var fieldReceiversByInstructionIndex = new Dictionary<int, int>();
            var incomingStacks = new Dictionary<int, int[]>();
            var pending = new Queue<int>();

            void EnqueueState(int index, IReadOnlyList<int> state)
            {
                if (index < 0 || index >= instructions.Count)
                    return;

                var candidate = state.ToArray();
                if (!incomingStacks.TryGetValue(index, out var existing))
                {
                    incomingStacks[index] = candidate;
                    pending.Enqueue(index);
                    return;
                }

                int[] merged;
                if (existing.Length != candidate.Length)
                {
                    merged = Array.Empty<int>();
                }
                else
                {
                    merged = new int[existing.Length];
                    for (int slot = 0; slot < existing.Length; slot++)
                    {
                        merged[slot] = MergeStackProducerIndexes(instructions, producersByCallIndex,
                            existing[slot], candidate[slot]);
                    }
                }

                if (!existing.SequenceEqual(merged))
                {
                    incomingStacks[index] = merged;
                    pending.Enqueue(index);
                }
            }

            if (instructions.Count > 0)
                EnqueueState(0, Array.Empty<int>());

            foreach (var handler in exceptionHandlers)
            {
                if (!instructionIndices.TryGetValue(handler.HandlerStart, out int handlerStartIndex))
                    return CallArgumentProducerMap.Empty;

                EnqueueState(handlerStartIndex,
                    handler.HandlerType is ExceptionHandlerType.Catch or ExceptionHandlerType.Filter
                        ? new[] { -1 }
                        : Array.Empty<int>());

                if (handler.FilterStart != null)
                {
                    if (!instructionIndices.TryGetValue(handler.FilterStart, out int filterStartIndex))
                        return CallArgumentProducerMap.Empty;

                    EnqueueState(filterStartIndex, new[] { -1 });
                }
            }

            const int maxWorkUnits = 65_536;
            int workUnits = 0;
            while (pending.Count > 0)
            {
                if (++workUnits > maxWorkUnits)
                    return CallArgumentProducerMap.Empty;

                int i = pending.Dequeue();
                var stack = new List<int>(incomingStacks[i]);
                var instruction = instructions[i];
                if ((TryGetStoredLocalIndex(instruction, out _) ||
                     TryGetStoredArgumentIndex(instruction, out _) ||
                     instruction.OpCode.Code is Code.Stfld or Code.Stsfld ||
                     IsArrayElementStore(instruction)) && stack.Count > 0)
                {
                    int producer = stack[^1];
                    producersByStoreIndex[i] = producersByStoreIndex.TryGetValue(i, out int existingProducer)
                        ? MergeStackProducerIndexes(instructions, producersByCallIndex, existingProducer, producer)
                        : producer;
                }

                if (instruction.OpCode.Code == Code.Ldfld && stack.Count >= 1)
                {
                    int receiver = stack[^1];
                    fieldReceiversByInstructionIndex[i] =
                        fieldReceiversByInstructionIndex.TryGetValue(i, out int existingReceiver)
                            ? MergeStackProducerIndexes(instructions, producersByCallIndex, existingReceiver, receiver)
                            : receiver;
                }
                else if (instruction.OpCode.Code == Code.Stfld && stack.Count >= 2)
                {
                    int receiver = stack[^2];
                    fieldReceiversByInstructionIndex[i] =
                        fieldReceiversByInstructionIndex.TryGetValue(i, out int existingReceiver)
                            ? MergeStackProducerIndexes(instructions, producersByCallIndex, existingReceiver, receiver)
                            : receiver;
                }

                if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt ||
                     instruction.OpCode == OpCodes.Newobj) &&
                    instruction.Operand is MethodReference calledMethod &&
                    calledMethod.Parameters.Count <= MaxTrackedCallArguments)
                {
                    int parameterCount = calledMethod.Parameters.Count;
                    int receiverCount = instruction.OpCode == OpCodes.Newobj ? 0 : calledMethod.HasThis ? 1 : 0;
                    int consumedCount = parameterCount + receiverCount;
                    if (stack.Count >= consumedCount)
                    {
                        int firstConsumedIndex = stack.Count - consumedCount;
                        int receiverProducer = receiverCount == 1 ? stack[firstConsumedIndex] : -1;
                        int firstArgumentIndex = stack.Count - parameterCount;
                        var argumentProducers = new int[parameterCount];
                        for (int argumentIndex = 0; argumentIndex < parameterCount; argumentIndex++)
                            argumentProducers[argumentIndex] = stack[firstArgumentIndex + argumentIndex];

                        if (producersByCallIndex.TryGetValue(i, out var existingCallProducers))
                        {
                            for (int argumentIndex = 0; argumentIndex < argumentProducers.Length; argumentIndex++)
                            {
                                argumentProducers[argumentIndex] = MergeStackProducerIndexes(
                                    instructions, producersByCallIndex,
                                    existingCallProducers.Arguments[argumentIndex], argumentProducers[argumentIndex]);
                            }

                            receiverProducer = MergeStackProducerIndexes(instructions, producersByCallIndex,
                                existingCallProducers.Receiver, receiverProducer);
                        }

                        producersByCallIndex[i] = new CallProducers(argumentProducers, receiverProducer);
                    }
                }

                if (instruction.OpCode == OpCodes.Dup)
                {
                    if (stack.Count == 0)
                        continue;

                    stack.Add(stack[^1]);
                }
                else
                {
                    if (instruction.OpCode == OpCodes.Calli)
                        continue;

                    int popCount = IsArrayElementStore(instruction) ? 3 : instruction.GetPopCount();
                    if (popCount > stack.Count)
                        continue;

                    if (popCount > 0)
                        stack.RemoveRange(stack.Count - popCount, popCount);

                    int pushCount = instruction.GetPushCount();
                    for (int push = 0; push < pushCount; push++)
                        stack.Add(i);
                }

                IReadOnlyList<int> successorStack =
                    instruction.OpCode.Code is Code.Leave or Code.Leave_S
                        ? Array.Empty<int>()
                        : stack;

                if (instruction.Operand is Instruction target)
                {
                    if (!instructionIndices.TryGetValue(target, out int targetIndex))
                        return CallArgumentProducerMap.Empty;

                    EnqueueState(targetIndex, successorStack);
                }
                else if (instruction.Operand is Instruction[] targets)
                {
                    foreach (var switchTarget in targets)
                    {
                        if (!instructionIndices.TryGetValue(switchTarget, out int targetIndex))
                            return CallArgumentProducerMap.Empty;

                        EnqueueState(targetIndex, successorStack);
                    }
                }

                var flowControl = instruction.OpCode.FlowControl;
                if (flowControl is not FlowControl.Branch and not FlowControl.Return and not FlowControl.Throw &&
                    i + 1 < instructions.Count)
                {
                    EnqueueState(i + 1, successorStack);
                }
            }

            return new CallArgumentProducerMap(producersByCallIndex, producersByStoreIndex,
                fieldReceiversByInstructionIndex);
        }

        private static int MergeStackProducerIndexes(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyDictionary<int, CallProducers> producersByCallIndex,
            int left,
            int right)
        {
            if (left == right)
                return left;

            if (left < 0 || right < 0 || left >= instructions.Count || right >= instructions.Count)
                return -1;

            if (instructions[left].OpCode.Code == Code.Ldstr &&
                instructions[right].OpCode.Code == Code.Ldstr &&
                instructions[left].Operand is string leftLiteral &&
                instructions[right].Operand is string rightLiteral &&
                leftLiteral.Equals(rightLiteral, StringComparison.Ordinal))
            {
                return left;
            }

            return AreEquivalentCurrentProcessFileNameProducers(
                instructions, producersByCallIndex, left, right)
                ? left
                : -1;
        }

        private static bool AreEquivalentCurrentProcessFileNameProducers(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            IReadOnlyDictionary<int, CallProducers> producersByCallIndex,
            int left,
            int right)
        {
            return IsMethodCall(instructions, left, "System.Diagnostics.ProcessModule", "get_FileName") &&
                   IsMethodCall(instructions, right, "System.Diagnostics.ProcessModule", "get_FileName") &&
                   producersByCallIndex.TryGetValue(left, out var leftFileName) &&
                   producersByCallIndex.TryGetValue(right, out var rightFileName) &&
                   IsMethodCall(instructions, leftFileName.Receiver,
                       "System.Diagnostics.Process", "get_MainModule") &&
                   IsMethodCall(instructions, rightFileName.Receiver,
                       "System.Diagnostics.Process", "get_MainModule") &&
                   producersByCallIndex.TryGetValue(leftFileName.Receiver, out var leftMainModule) &&
                   producersByCallIndex.TryGetValue(rightFileName.Receiver, out var rightMainModule) &&
                   IsMethodCall(instructions, leftMainModule.Receiver,
                       "System.Diagnostics.Process", "GetCurrentProcess") &&
                   IsMethodCall(instructions, rightMainModule.Receiver,
                       "System.Diagnostics.Process", "GetCurrentProcess");
        }

        private static bool IsMethodCall(
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int index,
            string declaringType,
            string methodName)
        {
            return index >= 0 && index < instructions.Count &&
                   instructions[index].Operand is MethodReference method &&
                   IsTrustedFrameworkMethod(method, declaringType, methodName, allowDetachedReference: true);
        }

        private static bool IsArrayElementStore(Instruction instruction)
        {
            return instruction.OpCode.Code is
                Code.Stelem_Any or Code.Stelem_I or Code.Stelem_I1 or Code.Stelem_I2 or Code.Stelem_I4 or
                Code.Stelem_I8 or Code.Stelem_R4 or Code.Stelem_R8 or Code.Stelem_Ref;
        }

        private sealed class CallArgumentProducerMap
        {
            public static CallArgumentProducerMap Empty { get; } =
                new(new Dictionary<int, CallProducers>(), new Dictionary<int, int>(),
                    new Dictionary<int, int>());

            private readonly Dictionary<int, CallProducers> _producersByCallIndex;
            private readonly Dictionary<int, int> _producersByStoreIndex;
            private readonly Dictionary<int, int> _fieldReceiversByInstructionIndex;

            public CallArgumentProducerMap(
                Dictionary<int, CallProducers> producersByCallIndex,
                Dictionary<int, int> producersByStoreIndex,
                Dictionary<int, int> fieldReceiversByInstructionIndex)
            {
                _producersByCallIndex = producersByCallIndex;
                _producersByStoreIndex = producersByStoreIndex;
                _fieldReceiversByInstructionIndex = fieldReceiversByInstructionIndex;
            }

            public bool TryGetProducer(int callIndex, int parameterCount, int argumentIndex, out int producerIndex)
            {
                producerIndex = -1;
                if (!_producersByCallIndex.TryGetValue(callIndex, out var producers) ||
                    producers.Arguments.Length != parameterCount || argumentIndex < 0 ||
                    argumentIndex >= producers.Arguments.Length)
                {
                    return false;
                }

                producerIndex = producers.Arguments[argumentIndex];
                return true;
            }

            public bool TryGetReceiverProducer(int callIndex, out int producerIndex)
            {
                producerIndex = -1;
                return _producersByCallIndex.TryGetValue(callIndex, out var producers) &&
                       (producerIndex = producers.Receiver) >= 0;
            }

            public bool TryGetStoredValueProducer(int storeIndex, out int producerIndex)
            {
                return _producersByStoreIndex.TryGetValue(storeIndex, out producerIndex);
            }

            public bool TryGetFieldReceiverProducer(int instructionIndex, out int producerIndex)
            {
                return _fieldReceiversByInstructionIndex.TryGetValue(instructionIndex, out producerIndex);
            }
        }

        private sealed class CallArgumentProducerMapCache
        {
            public object Gate { get; } = new();
            public ExceptionHandler[] Handlers { get; private set; } = Array.Empty<ExceptionHandler>();
            public CallArgumentProducerMap Map { get; private set; } = CallArgumentProducerMap.Empty;
            private bool IsInitialized { get; set; }

            public bool Matches(IReadOnlyList<ExceptionHandler> handlers)
            {
                if (!IsInitialized)
                    return false;

                if (Handlers.Length != handlers.Count)
                    return false;

                for (int i = 0; i < Handlers.Length; i++)
                {
                    if (!ReferenceEquals(Handlers[i], handlers[i]))
                        return false;
                }

                return true;
            }

            public void Update(IReadOnlyList<ExceptionHandler> handlers, CallArgumentProducerMap map)
            {
                Handlers = handlers.ToArray();
                Map = map;
                IsInitialized = true;
            }
        }

        private readonly struct CallProducers
        {
            public CallProducers(int[] arguments, int receiver)
            {
                Arguments = arguments;
                Receiver = receiver;
            }

            public int[] Arguments { get; }
            public int Receiver { get; }
        }

        /// <summary>
        /// Tries to recover a constant value assigned to <c>ProcessStartInfo.UseShellExecute</c>.
        /// </summary>
        /// <param name="containingMethod">The method containing the process launch.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="processStartIndex">The call instruction index.</param>
        /// <param name="useShellExecute">Receives the resolved boolean value when available.</param>
        /// <returns><see langword="true"/> when a definite value could be reconstructed.</returns>
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

        /// <summary>
        /// Tries to recover a constant value assigned to <c>ProcessStartInfo.CreateNoWindow</c>.
        /// </summary>
        /// <param name="containingMethod">The method containing the process launch.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="processStartIndex">The call instruction index.</param>
        /// <param name="createNoWindow">Receives the resolved boolean value when available.</param>
        /// <returns><see langword="true"/> when a definite value could be reconstructed.</returns>
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

        /// <summary>
        /// Tries to recover a constant value assigned to <c>ProcessStartInfo.WindowStyle</c>.
        /// </summary>
        /// <param name="containingMethod">The method containing the process launch.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="processStartIndex">The call instruction index.</param>
        /// <param name="windowStyle">Receives the resolved window-style value when available.</param>
        /// <returns><see langword="true"/> when a definite value could be reconstructed.</returns>
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
                if (instruction.TryResolveInt32Literal(out int intVal))
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

        /// <summary>
        /// Tries to recover a constant value assigned to <c>ProcessStartInfo.WorkingDirectory</c>.
        /// </summary>
        /// <param name="containingMethod">The method containing the process launch.</param>
        /// <param name="instructions">The method body instructions.</param>
        /// <param name="processStartIndex">The call instruction index.</param>
        /// <param name="workingDirectory">Receives the resolved working-directory string.</param>
        /// <returns><see langword="true"/> when a definite value could be reconstructed.</returns>
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
                needed -= instruction.GetPushCount();
                if (needed <= 0)
                    return i;

                needed += instruction.GetPopCount();
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

            if (instruction.TryResolveInt32Literal(out int intValue))
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

            if (instruction.TryGetLocalIndex(out int localIndex))
            {
                if (TryResolveLocalValue(context, containingMethod, instructions, producerIndex - 1, localIndex,
                        argumentMap, depth + 1, out value))
                    return true;

                value = new ResolvedValue($"<local V_{localIndex}>", null, false);
                return true;
            }

            if (instruction.TryGetArgumentIndex(out int argumentIndex))
            {
                if (instruction.Operand is ParameterDefinition parameter && parameter.Method?.HasThis == true)
                {
                    argumentIndex++;
                }

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
                if (!instruction.TryGetStoredLocalIndex(out int storedIndex) || storedIndex != localIndex)
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

            MethodDefinition? resolvedMethod;
            try
            {
                resolvedMethod = method.Resolve();
            }
            catch (Exception)
            {
                // References originate in untrusted assemblies. Resolution is best-effort; an
                // unavailable or malformed dependency must not abort the enclosing rule.
                resolvedMethod = null;
            }
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
