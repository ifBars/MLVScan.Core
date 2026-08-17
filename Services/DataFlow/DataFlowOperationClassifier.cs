using MLVScan.Models;
using MLVScan.Models.DataFlow;
using MLVScan.Models.Rules.Helpers;
using MLVScan.Services.Helpers;
using Mono.Collections.Generic;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Services.DataFlow
{
    internal sealed class DataFlowOperationClassifier
    {
        private readonly DataFlowInstructionHelper _instructionHelper;

        public DataFlowOperationClassifier(Collection<Instruction> instructions)
            : this(new DataFlowInstructionHelper(instructions))
        {
        }

        public DataFlowOperationClassifier(DataFlowInstructionHelper instructionHelper)
        {
            _instructionHelper = instructionHelper ?? throw new ArgumentNullException(nameof(instructionHelper));
        }

        public List<DataFlowInterestingOperation> IdentifyInterestingOperations(
            MethodDefinition method,
            Collection<Instruction> instructions)
        {
            var operations = new List<DataFlowInterestingOperation>();

            for (var index = 0; index < instructions.Count; index++)
            {
                var instruction = instructions[index];

                if (instruction.Operand is not MethodReference calledMethod)
                {
                    continue;
                }

                var isFileStreamConstructor = instruction.OpCode == OpCodes.Newobj &&
                    IsFileStreamSink(calledMethod.DeclaringType?.FullName ?? string.Empty, calledMethod.Name);
                if (!instruction.IsCallOrCallvirt() && !isFileStreamConstructor)
                {
                    continue;
                }

                if (isFileStreamConstructor &&
                    !IsWritableFileStreamConstructor(method, instructions, index, calledMethod))
                {
                    continue;
                }

                var operationInfo = ClassifyOperation(calledMethod);
                if (operationInfo != null)
                {
                    var payloadPathIdentities = TryGetPayloadPathIdentities(
                        method,
                        instructions,
                        index,
                        calledMethod,
                        operationInfo.Value.Operation,
                        operationInfo.Value.NodeType);
                    operations.Add(new DataFlowInterestingOperation
                    {
                        Instruction = instruction,
                        InstructionIndex = index,
                        MethodReference = calledMethod,
                        NodeType = operationInfo.Value.NodeType,
                        Operation = operationInfo.Value.Operation,
                        DataDescription = BuildDataDescription(
                            method,
                            instructions,
                            index,
                            calledMethod,
                            operationInfo.Value.NodeType,
                            operationInfo.Value.DataDescription),
                        LocalVariableIndex = _instructionHelper.TryGetTargetLocalVariable(instructions, index),
                        PayloadPathIdentities = payloadPathIdentities
                    });
                }

                if (!IsDirectDownloadToDisk(calledMethod.DeclaringType?.FullName ?? string.Empty, calledMethod.Name))
                {
                    continue;
                }

                operations.Add(new DataFlowInterestingOperation
                {
                    Instruction = instruction,
                    InstructionIndex = index,
                    MethodReference = calledMethod,
                    NodeType = DataFlowNodeType.Sink,
                    Operation = $"{calledMethod.DeclaringType?.Name}.{calledMethod.Name}",
                    DataDescription = "Writes downloaded data to file"
                });
            }

            return operations;
        }

        private static string BuildDataDescription(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            DataFlowNodeType nodeType,
            string baseDescription)
        {
            if (nodeType != DataFlowNodeType.Source)
            {
                return baseDescription;
            }

            var declaringType = calledMethod.DeclaringType?.FullName ?? string.Empty;
            int[] sourceArgumentIndexes = IsFileSource(declaringType, calledMethod.Name)
                ? new[] { 0 }
                : IsRegistrySource(declaringType, calledMethod.Name)
                    ? new[] { 0, 1 }
                    : Array.Empty<int>();

            var resolvedArguments = sourceArgumentIndexes
                .Where(argumentIndex => argumentIndex < calledMethod.Parameters.Count)
                .Select(argumentIndex => InstructionValueResolver.TryResolveCallArgumentDisplay(
                    method,
                    calledMethod,
                    instructions,
                    callIndex,
                    argumentIndex,
                    out var display)
                        ? display
                        : string.Empty)
                .Where(IsConcreteResolvedPath)
                .Select(static display => display.Length <= 256 ? display : display[..256])
                .ToList();

            return resolvedArguments.Count == 0
                ? baseDescription
                : $"{baseDescription}; source argument(s): {string.Join(", ", resolvedArguments)}";
        }

        private HashSet<string> TryGetPayloadPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            string operation,
            DataFlowNodeType nodeType)
        {
            if (nodeType != DataFlowNodeType.Sink)
            {
                return EmptyIdentities();
            }

            if (IsFilePathSink(operation))
            {
                return TryGetCallArgumentIdentities(method, instructions, callIndex, calledMethod, 0);
            }

            if (operation.Equals("Process.Start", StringComparison.OrdinalIgnoreCase))
            {
                return TryGetProcessStartPathIdentities(method, instructions, callIndex, calledMethod);
            }

            return TryGetNativeExecutionPathIdentities(method, instructions, callIndex, calledMethod, operation);
        }

        private static bool IsFilePathSink(string operation)
        {
            return operation.Contains("File.", StringComparison.OrdinalIgnoreCase) ||
                   operation.Contains("FileStream", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsWritableFileStreamConstructor(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int constructorIndex,
            MethodReference constructor)
        {
            var accessParameterIndex = constructor.Parameters
                .Select((parameter, index) => (parameter, index))
                .Where(static entry => entry.parameter.ParameterType.FullName == "System.IO.FileAccess")
                .Select(static entry => (int?)entry.index)
                .FirstOrDefault();
            if (!accessParameterIndex.HasValue)
            {
                return true;
            }

            return !InstructionValueResolver.TryResolveCallArgumentDisplay(
                       method,
                       constructor,
                       instructions,
                       constructorIndex,
                       accessParameterIndex.Value,
                       out var accessDisplay) ||
                   !int.TryParse(accessDisplay, out var accessValue) ||
                   accessValue != 1;
        }

        private HashSet<string> TryGetProcessStartPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int processStartIndex,
            MethodReference processStartMethod)
        {
            int? startInfoLocal = null;
            int? processLocal = null;
            int? processReceiverLoadIndex = null;

            if (!processStartMethod.HasThis &&
                processStartMethod.Parameters.Count == 1 &&
                processStartMethod.Parameters[0].ParameterType.FullName == "System.Diagnostics.ProcessStartInfo")
            {
                if (_instructionHelper.TryGetCallArgumentLocalVariable(
                        instructions, processStartIndex, processStartMethod, 0, out var resolvedStartInfoLocal))
                {
                    startInfoLocal = resolvedStartInfoLocal;
                }
                else if (_instructionHelper.TryGetCallArgumentProducerIndex(
                             instructions, processStartIndex, processStartMethod, 0, out var producerIndex))
                {
                    return TryGetStartInfoProducerIdentities(
                        method, instructions, producerIndex, processStartIndex);
                }
                else
                {
                    return EmptyIdentities();
                }
            }
            else if (processStartMethod.HasThis)
            {
                if (!_instructionHelper.TryGetCallReceiverProducerIndex(
                        instructions, processStartIndex, processStartMethod, out var receiverLoadIndex) ||
                    !instructions[receiverLoadIndex].TryGetLocalIndex(out var resolvedProcessLocal))
                {
                    return EmptyIdentities();
                }

                processLocal = resolvedProcessLocal;
                processReceiverLoadIndex = receiverLoadIndex;
            }
            else if (processStartMethod.Parameters.Count > 0)
            {
                return TryGetCallArgumentIdentities(method, instructions, processStartIndex, processStartMethod, 0);
            }

            IReadOnlyCollection<int> startInfoDefinitionIndexes = Array.Empty<int>();
            IReadOnlyCollection<int> processDefinitionIndexes = Array.Empty<int>();
            if (startInfoLocal.HasValue &&
                _instructionHelper.TryGetCallArgumentProducerIndex(
                    instructions, processStartIndex, processStartMethod, 0, out var startInfoLoadIndex))
            {
                startInfoDefinitionIndexes = _instructionHelper.GetReachingLocalStoreIndexes(
                    instructions, startInfoLoadIndex, startInfoLocal.Value);
            }
            else if (processLocal.HasValue && processReceiverLoadIndex.HasValue)
            {
                processDefinitionIndexes = _instructionHelper.GetReachingLocalStoreIndexes(
                    instructions, processReceiverLoadIndex.Value, processLocal.Value);
            }

            var setterIndexes = _instructionHelper.GetReachingInstructionIndexes(
                instructions,
                processStartIndex,
                index => TryGetStartInfoFileNameSetter(instructions[index], out var setter) &&
                         StartInfoSetterBelongsToStartedProcess(
                             instructions,
                             index,
                             setter,
                             startInfoLocal,
                             processLocal,
                             startInfoDefinitionIndexes,
                             processDefinitionIndexes));
            var identities = EmptyIdentities();
            foreach (var definitionIndex in startInfoDefinitionIndexes)
            {
                identities.UnionWith(TryGetStoredStartInfoConstructorIdentities(
                    method, instructions, definitionIndex));
            }

            foreach (var setterIndex in setterIndexes)
            {
                var setter = (MethodReference)instructions[setterIndex].Operand;
                identities.UnionWith(
                    TryGetCallArgumentIdentities(method, instructions, setterIndex, setter, 0));
            }

            if (processLocal.HasValue)
            {
                var startInfoAssignmentIndexes = _instructionHelper.GetReachingInstructionIndexes(
                    instructions,
                    processStartIndex,
                    index => TryGetProcessStartInfoSetter(instructions[index], out var setter) &&
                             ProcessReceiverMatchesStartedProcess(
                                 instructions,
                                 index,
                                 setter,
                                 processLocal.Value,
                                 processDefinitionIndexes));
                foreach (var assignmentIndex in startInfoAssignmentIndexes)
                {
                    var setter = (MethodReference)instructions[assignmentIndex].Operand;
                    identities.UnionWith(TryGetAssignedStartInfoIdentities(
                        method, instructions, assignmentIndex, setter));
                }
            }

            return identities;
        }

        private HashSet<string> TryGetAssignedStartInfoIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int setterIndex,
            MethodReference setter)
        {
            if (!_instructionHelper.TryGetCallArgumentProducerIndex(
                    instructions, setterIndex, setter, 0, out var producerIndex))
            {
                return EmptyIdentities();
            }

            var producerIdentities = TryGetStartInfoProducerIdentities(
                method, instructions, producerIndex, setterIndex);
            if (producerIdentities.Count > 0)
            {
                return producerIdentities;
            }

            if (!instructions[producerIndex].TryGetLocalIndex(out var startInfoLocal))
            {
                return EmptyIdentities();
            }

            var definitions = _instructionHelper.GetReachingLocalStoreIndexes(
                instructions, producerIndex, startInfoLocal);
            var identities = EmptyIdentities();
            foreach (var definitionIndex in definitions)
            {
                identities.UnionWith(TryGetStoredStartInfoConstructorIdentities(
                    method, instructions, definitionIndex));
            }

            var fileNameSetterIndexes = _instructionHelper.GetReachingInstructionIndexes(
                instructions,
                setterIndex,
                index => TryGetStartInfoFileNameSetter(instructions[index], out var fileNameSetter) &&
                         StartInfoSetterBelongsToStartedProcess(
                             instructions,
                             index,
                             fileNameSetter,
                             startInfoLocal,
                             null,
                             definitions,
                             Array.Empty<int>()));
            foreach (var fileNameSetterIndex in fileNameSetterIndexes)
            {
                var fileNameSetter = (MethodReference)instructions[fileNameSetterIndex].Operand;
                identities.UnionWith(TryGetCallArgumentIdentities(
                    method, instructions, fileNameSetterIndex, fileNameSetter, 0));
            }

            return identities;
        }

        private HashSet<string> TryGetStartInfoProducerIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int producerIndex,
            int consumerIndex)
        {
            var initializerStartIndex = producerIndex;
            var constructorIndex = producerIndex;
            if (instructions[producerIndex].OpCode == OpCodes.Dup)
            {
                if (!_instructionHelper.TryGetConsumedValueProducerIndex(
                        instructions, producerIndex, out constructorIndex))
                {
                    return EmptyIdentities();
                }
            }

            if (instructions[constructorIndex].OpCode != OpCodes.Newobj ||
                instructions[constructorIndex].Operand is not MethodReference constructor ||
                constructor.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo")
            {
                return EmptyIdentities();
            }

            var identities = constructor.Parameters.Count > 0
                ? TryGetCallArgumentIdentities(method, instructions, constructorIndex, constructor, 0)
                : EmptyIdentities();
            if (instructions[producerIndex].OpCode != OpCodes.Dup)
            {
                return identities;
            }

            for (var index = initializerStartIndex + 1; index < consumerIndex; index++)
            {
                if (!TryGetStartInfoFileNameSetter(instructions[index], out var fileNameSetter) ||
                    !_instructionHelper.TryGetCallReceiverProducerIndex(
                        instructions, index, fileNameSetter, out var receiverProducerIndex) ||
                    receiverProducerIndex != initializerStartIndex)
                {
                    continue;
                }

                identities.UnionWith(TryGetCallArgumentIdentities(
                    method, instructions, index, fileNameSetter, 0));
            }

            return identities;
        }

        private HashSet<string> TryGetStoredStartInfoConstructorIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int storeIndex)
        {
            if (!_instructionHelper.TryGetConsumedValueProducerIndex(
                    instructions, storeIndex, out var producerIndex))
            {
                return EmptyIdentities();
            }

            return TryGetStartInfoProducerIdentities(method, instructions, producerIndex, storeIndex);
        }

        private bool TryGetStartInfoFileNameSetter(
            Instruction instruction,
            out MethodReference setter)
        {
            setter = null!;
            if (!instruction.IsCallOrCallvirt() ||
                instruction.Operand is not MethodReference candidate ||
                candidate.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                candidate.Name != "set_FileName")
            {
                return false;
            }

            setter = candidate;
            return true;
        }

        private bool TryGetProcessStartInfoSetter(
            Instruction instruction,
            out MethodReference setter)
        {
            setter = null!;
            if (!instruction.IsCallOrCallvirt() ||
                instruction.Operand is not MethodReference candidate ||
                candidate.DeclaringType?.FullName != "System.Diagnostics.Process" ||
                candidate.Name != "set_StartInfo")
            {
                return false;
            }

            setter = candidate;
            return true;
        }

        private bool StartInfoSetterBelongsToStartedProcess(
            Collection<Instruction> instructions,
            int setterIndex,
            MethodReference setter,
            int? startInfoLocal,
            int? processLocal,
            IReadOnlyCollection<int> startedStartInfoDefinitions,
            IReadOnlyCollection<int> startedProcessDefinitions)
        {
            if (startInfoLocal.HasValue)
            {
                if (!_instructionHelper.TryGetCallReceiverProducerIndex(
                        instructions, setterIndex, setter, out var receiverProducerIndex) ||
                    !instructions[receiverProducerIndex].TryGetLocalIndex(out var setterStartInfoLocal) ||
                    setterStartInfoLocal != startInfoLocal.Value)
                {
                    return false;
                }

                if (startedStartInfoDefinitions.Count == 0)
                {
                    return true;
                }

                var setterStartInfoDefinitions = _instructionHelper.GetReachingLocalStoreIndexes(
                    instructions, receiverProducerIndex, setterStartInfoLocal);
                return setterStartInfoDefinitions.Intersect(startedStartInfoDefinitions).Any();
            }

            if (!processLocal.HasValue ||
                !_instructionHelper.TryGetCallReceiverProducerIndex(
                    instructions, setterIndex, setter, out var setterReceiverProducerIndex))
            {
                return false;
            }

            var setterReceiverProducer = instructions[setterReceiverProducerIndex];
            if (!setterReceiverProducer.IsCallOrCallvirt() ||
                setterReceiverProducer.Operand is not MethodReference getter ||
                getter.DeclaringType?.FullName != "System.Diagnostics.Process" ||
                getter.Name != "get_StartInfo")
            {
                return false;
            }

            return ProcessReceiverMatchesStartedProcess(
                instructions,
                setterReceiverProducerIndex,
                getter,
                processLocal.Value,
                startedProcessDefinitions);
        }

        private bool ProcessReceiverMatchesStartedProcess(
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            int processLocal,
            IReadOnlyCollection<int> startedProcessDefinitions)
        {
            if (!_instructionHelper.TryGetCallReceiverProducerIndex(
                    instructions, callIndex, calledMethod, out var receiverProducerIndex) ||
                !instructions[receiverProducerIndex].TryGetLocalIndex(out var receiverProcessLocal) ||
                receiverProcessLocal != processLocal)
            {
                return false;
            }

            if (startedProcessDefinitions.Count == 0)
            {
                return true;
            }

            var receiverDefinitions = _instructionHelper.GetReachingLocalStoreIndexes(
                instructions, receiverProducerIndex, receiverProcessLocal);
            return receiverDefinitions.Intersect(startedProcessDefinitions).Any();
        }

        private HashSet<string> TryGetNativeExecutionPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            string operation)
        {
            if (operation.Contains("ShellExecuteEx", StringComparison.OrdinalIgnoreCase))
            {
                return TryGetShellExecuteExFileIdentities(method, instructions, callIndex, calledMethod);
            }

            if (operation.Contains("CreateProcess", StringComparison.OrdinalIgnoreCase))
            {
                return TryGetCreateProcessPathIdentities(method, instructions, callIndex, calledMethod, operation);
            }

            var argumentIndex = operation switch
            {
                var value when value.Contains("WinExec", StringComparison.OrdinalIgnoreCase) => 0,
                var value when value.Contains("ShellExecute", StringComparison.OrdinalIgnoreCase) &&
                                   !value.Contains("ShellExecuteEx", StringComparison.OrdinalIgnoreCase) => 2,
                _ => -1
            };

            return argumentIndex >= 0
                ? TryGetCallArgumentIdentities(method, instructions, callIndex, calledMethod, argumentIndex)
                : EmptyIdentities();
        }

        private HashSet<string> TryGetCreateProcessPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            string operation)
        {
            var (applicationNameIndex, commandLineIndex) = operation switch
            {
                var value when value.Contains("CreateProcessWithLogon", StringComparison.OrdinalIgnoreCase) => (4, 5),
                var value when value.Contains("CreateProcessWithToken", StringComparison.OrdinalIgnoreCase) => (2, 3),
                var value when value.Contains("CreateProcessAsUser", StringComparison.OrdinalIgnoreCase) => (1, 2),
                _ => (0, 1)
            };

            var applicationIdentities = TryGetCallArgumentIdentities(
                method, instructions, callIndex, calledMethod, applicationNameIndex);
            if (applicationIdentities.Count > 0)
            {
                return applicationIdentities;
            }

            var commandLineIdentities = TryGetCallArgumentIdentities(
                method, instructions, callIndex, calledMethod, commandLineIndex);
            if (InstructionValueResolver.TryResolveCallArgumentDisplay(
                    method,
                    calledMethod,
                    instructions,
                    callIndex,
                    commandLineIndex,
                    out var commandLine) &&
                IsConcreteResolvedPath(commandLine) &&
                TryExtractCommandExecutable(commandLine, out var executable))
            {
                commandLineIdentities.Add(NormalizeResolvedPathIdentity(executable));
            }

            return commandLineIdentities;
        }

        private static bool TryExtractCommandExecutable(string commandLine, out string executable)
        {
            executable = string.Empty;
            var trimmed = commandLine.Trim();
            if (trimmed.Length == 0)
            {
                return false;
            }

            if (trimmed[0] == '"')
            {
                var closingQuote = trimmed.IndexOf('"', 1);
                if (closingQuote <= 1)
                {
                    return false;
                }

                executable = trimmed[1..closingQuote];
                return true;
            }

            var separatorIndex = trimmed.IndexOfAny(new[] { ' ', '\t', '\r', '\n' });
            executable = separatorIndex < 0 ? trimmed : trimmed[..separatorIndex];
            return executable.Length > 0;
        }

        private HashSet<string> TryGetShellExecuteExFileIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod)
        {
            if (!_instructionHelper.TryGetCallArgumentLocalVariable(
                    instructions, callIndex, calledMethod, 0, out var shellExecuteInfoLocal))
            {
                return EmptyIdentities();
            }

            var fieldStoreIndexes = _instructionHelper.GetReachingInstructionIndexes(
                instructions,
                callIndex,
                index => IsShellExecuteFileStoreForLocal(
                    instructions, index, shellExecuteInfoLocal));
            var identities = EmptyIdentities();
            foreach (var index in fieldStoreIndexes)
            {
                if (!_instructionHelper.TryGetConsumedValueProducerIndex(
                        instructions, index, out var valueProducerIndex))
                {
                    continue;
                }

                if (instructions[valueProducerIndex].TryGetLocalIndex(out var localIndex))
                {
                    identities.UnionWith(
                        BuildLocalPathIdentities(method, instructions, valueProducerIndex, localIndex));
                    continue;
                }

                if (InstructionValueResolver.TryResolveStackValueDisplay(
                        method, instructions, index - 1, out var display) &&
                    IsConcreteResolvedPath(display))
                {
                    identities.Add(NormalizeResolvedPathIdentity(display));
                }
            }

            return identities;
        }

        private bool IsShellExecuteFileStoreForLocal(
            Collection<Instruction> instructions,
            int index,
            int shellExecuteInfoLocal)
        {
            return instructions[index].OpCode == OpCodes.Stfld &&
                   instructions[index].Operand is FieldReference field &&
                   field.Name.Equals("lpFile", StringComparison.OrdinalIgnoreCase) &&
                   _instructionHelper.TryGetFieldStoreReceiverLocalVariable(
                       instructions, index, out var fieldReceiverLocal) &&
                   fieldReceiverLocal == shellExecuteInfoLocal;
        }

        private HashSet<string> TryGetCallArgumentIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod,
            int argumentIndex)
        {
            var resolved = InstructionValueResolver.TryResolveCallArgumentDisplay(
                method, calledMethod, instructions, callIndex, argumentIndex, out var display);
            if (resolved && display.Contains("<null>", StringComparison.OrdinalIgnoreCase))
            {
                return EmptyIdentities();
            }

            var identities = EmptyIdentities();
            if (_instructionHelper.TryGetCallArgumentLocalVariable(
                    instructions, callIndex, calledMethod, argumentIndex, out var localIndex, out var producerIndex))
            {
                identities.UnionWith(BuildLocalPathIdentities(method, instructions, producerIndex, localIndex));
            }
            else if (_instructionHelper.TryGetCallArgumentProducerIndex(
                         instructions, callIndex, calledMethod, argumentIndex, out producerIndex) &&
                     _instructionHelper.TryGetMethodParameterIndex(
                         method, instructions[producerIndex], out var parameterIndex))
            {
                identities.Add(BuildArgumentPathIdentity(method, parameterIndex));
            }

            if (resolved && IsConcreteResolvedPath(display))
            {
                identities.Add(NormalizeResolvedPathIdentity(display));
            }

            return identities;
        }

        private static string BuildArgumentPathIdentity(MethodDefinition method, int parameterIndex)
        {
            return $"{method.GetMethodKey()}::argument:{parameterIndex}";
        }

        private static bool IsConcreteResolvedPath(string display)
        {
            return !string.IsNullOrWhiteSpace(display) &&
                   !display.Contains('<') &&
                   !display.Contains('>');
        }

        private HashSet<string> BuildLocalPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int localLoadIndex,
            int localIndex)
        {
            return BuildLocalPathIdentities(
                method,
                instructions,
                localLoadIndex,
                localIndex,
                new HashSet<(int LoadIndex, int LocalIndex)>());
        }

        private HashSet<string> BuildLocalPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int localLoadIndex,
            int localIndex,
            HashSet<(int LoadIndex, int LocalIndex)> visited)
        {
            if (!visited.Add((localLoadIndex, localIndex)))
            {
                return EmptyIdentities();
            }

            var storeIndexes = _instructionHelper.GetReachingLocalStoreIndexes(
                instructions, localLoadIndex, localIndex);
            if (storeIndexes.Count == 0)
            {
                return SingleIdentity($"{method.GetMethodKey()}::local:{localIndex}@parameter");
            }

            var identities = storeIndexes
                .Select(index => $"{method.GetMethodKey()}::local:{localIndex}@instruction:{index}")
                .ToHashSet(StringComparer.Ordinal);
            foreach (var storeIndex in storeIndexes)
            {
                if (!_instructionHelper.TryGetConsumedValueProducerIndex(
                        instructions, storeIndex, out var producerIndex))
                {
                    continue;
                }

                if (_instructionHelper.TryGetMethodParameterIndex(
                        method, instructions[producerIndex], out var parameterIndex))
                {
                    identities.Add(BuildArgumentPathIdentity(method, parameterIndex));
                }
                else if (instructions[producerIndex].TryGetLocalIndex(out var sourceLocalIndex))
                {
                    identities.UnionWith(BuildLocalPathIdentities(
                        method,
                        instructions,
                        producerIndex,
                        sourceLocalIndex,
                        visited));
                }
            }

            return identities;
        }

        private static HashSet<string> EmptyIdentities() => new(StringComparer.Ordinal);

        private static HashSet<string> SingleIdentity(string identity) =>
            new(StringComparer.Ordinal) { identity };

        private static string NormalizeResolvedPathIdentity(string display)
        {
            return $"value:{display.Trim().Trim('"').Replace('\\', '/').ToUpperInvariant()}";
        }

        private (DataFlowNodeType NodeType, string Operation, string DataDescription)? ClassifyOperation(MethodReference method)
        {
            var declaringType = method.DeclaringType?.FullName ?? string.Empty;
            var methodName = method.Name;
            var operationName = $"{method.DeclaringType?.Name}.{methodName}";

            if (IsNetworkSource(declaringType, methodName))
            {
                return (DataFlowNodeType.Source, operationName, "byte[]/string (network data)");
            }

            if (IsFileSource(declaringType, methodName))
            {
                return (DataFlowNodeType.Source, operationName, "byte[]/string (file data)");
            }

            if (IsRegistrySource(declaringType, methodName))
            {
                return (DataFlowNodeType.Source, operationName, "string (registry data)");
            }

            if (IsResourceSource(declaringType, methodName))
            {
                return (DataFlowNodeType.Source, operationName, "stream/byte[] (embedded resource)");
            }

            if (IsBase64Decode(declaringType, methodName))
            {
                return (DataFlowNodeType.Transform, "Convert.FromBase64String", "byte[] (decoded)");
            }

            if (IsEncoding(declaringType, methodName))
            {
                return (DataFlowNodeType.Transform, operationName, "byte[]/string (encoded)");
            }

            if (IsCryptoOperation(declaringType, methodName))
            {
                return (DataFlowNodeType.Transform, operationName, "byte[] (crypto operation)");
            }

            if (IsCompressionOperation(declaringType, methodName))
            {
                return (DataFlowNodeType.Transform, operationName, "byte[]/stream (decompressed)");
            }

            if (IsStreamMaterialization(declaringType, methodName))
            {
                return (DataFlowNodeType.Transform, operationName, "byte[] (materialized from stream)");
            }

            if (IsAssemblyLoad(declaringType, methodName))
            {
                return (DataFlowNodeType.Sink, operationName, "Assembly (dynamic code loaded)");
            }

            if (IsNativeExecutionSink(method))
            {
                return (DataFlowNodeType.Sink, GetNativeExecutionOperationName(method), "Executes native shell/process");
            }

            if (IsProcessStart(declaringType, methodName))
            {
                return (DataFlowNodeType.Sink, "Process.Start", "Executes process");
            }

            if (IsFileSink(declaringType, methodName) || IsFileStreamSink(declaringType, methodName))
            {
                return (DataFlowNodeType.Sink, operationName, "Writes to file");
            }

            if (IsNetworkSink(declaringType, methodName))
            {
                return (DataFlowNodeType.Sink, operationName, "Sends to network");
            }

            if (IsRegistrySink(declaringType, methodName))
            {
                return (DataFlowNodeType.Sink, operationName, "Writes to registry");
            }

            return null;
        }

        private static bool IsNetworkSource(string declaringType, string methodName)
        {
            return (declaringType.StartsWith("System.Net", StringComparison.Ordinal) ||
                    declaringType.Contains("HttpClient", StringComparison.Ordinal) ||
                    declaringType.Contains("WebClient", StringComparison.Ordinal) ||
                    declaringType.Contains("UnityWebRequest", StringComparison.Ordinal)) &&
                   (methodName.Contains("Get", StringComparison.Ordinal) ||
                    methodName.Contains("Download", StringComparison.Ordinal) ||
                    methodName.Contains("Read", StringComparison.Ordinal) ||
                    methodName.Contains("Receive", StringComparison.Ordinal));
        }

        private static bool IsDirectDownloadToDisk(string declaringType, string methodName)
        {
            return (declaringType.StartsWith("System.Net", StringComparison.Ordinal) ||
                    declaringType.Contains("WebClient", StringComparison.Ordinal) ||
                    declaringType.Contains("UnityWebRequest", StringComparison.Ordinal)) &&
                   (methodName.Equals("DownloadFile", StringComparison.OrdinalIgnoreCase) ||
                    methodName.Equals("DownloadFileTaskAsync", StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsFileSource(string declaringType, string methodName)
        {
            return declaringType.StartsWith("System.IO.File", StringComparison.Ordinal) &&
                   (methodName.Contains("Read", StringComparison.Ordinal) ||
                    methodName == "ReadAllBytes" ||
                    methodName == "ReadAllText");
        }

        private static bool IsRegistrySource(string declaringType, string methodName)
        {
            return declaringType.Contains("Microsoft.Win32.Registry", StringComparison.Ordinal) &&
                   methodName.Contains("GetValue", StringComparison.Ordinal);
        }

        private static bool IsResourceSource(string declaringType, string methodName)
        {
            return (declaringType == "System.Reflection.Assembly" && methodName == "GetManifestResourceStream") ||
                   (declaringType.Contains("ResourceManager", StringComparison.Ordinal) &&
                    (methodName == "GetObject" || methodName == "GetStream"));
        }

        private static bool IsBase64Decode(string declaringType, string methodName)
        {
            return declaringType == "System.Convert" && methodName == "FromBase64String";
        }

        private static bool IsEncoding(string declaringType, string methodName)
        {
            return declaringType.Contains("System.Text.Encoding", StringComparison.Ordinal) ||
                   (declaringType == "System.Convert" && methodName == "ToBase64String");
        }

        private static bool IsCryptoOperation(string declaringType, string methodName)
        {
            return (declaringType.Contains("System.Security.Cryptography", StringComparison.Ordinal) &&
                    (methodName == "Create" ||
                     methodName == "CreateDecryptor" ||
                     methodName == "CreateEncryptor" ||
                     methodName == "TransformFinalBlock" ||
                     methodName == "TransformBlock")) ||
                   (declaringType == "System.Security.Cryptography.CryptoStream" && methodName == ".ctor") ||
                   (declaringType.Contains("RijndaelManaged", StringComparison.Ordinal) && methodName == ".ctor") ||
                   (declaringType.Contains("DESCryptoServiceProvider", StringComparison.Ordinal) && methodName == ".ctor") ||
                   (declaringType.Contains("TripleDESCryptoServiceProvider", StringComparison.Ordinal) && methodName == ".ctor") ||
                   (declaringType.Contains("RC2CryptoServiceProvider", StringComparison.Ordinal) && methodName == ".ctor");
        }

        private static bool IsCompressionOperation(string declaringType, string methodName)
        {
            return (declaringType == "System.IO.Compression.GZipStream" && methodName == ".ctor") ||
                   (declaringType == "System.IO.Compression.DeflateStream" && methodName == ".ctor") ||
                   (declaringType == "System.IO.Compression.BrotliStream" && methodName == ".ctor") ||
                   (declaringType.Contains("System.IO.Compression", StringComparison.Ordinal) && methodName == "CopyTo");
        }

        private static bool IsStreamMaterialization(string declaringType, string methodName)
        {
            return (declaringType == "System.IO.MemoryStream" && methodName == "ToArray") ||
                   (declaringType == "System.IO.MemoryStream" && methodName == "GetBuffer") ||
                   (declaringType == "System.IO.Stream" && methodName == "CopyTo");
        }

        private static bool IsAssemblyLoad(string declaringType, string methodName)
        {
            return (declaringType == "System.Reflection.Assembly" &&
                    (methodName == "Load" || methodName == "LoadFrom" || methodName == "LoadFile")) ||
                   (declaringType.Contains("AssemblyLoadContext", StringComparison.Ordinal) &&
                    (methodName == "LoadFromStream" || methodName == "LoadFromAssemblyPath"));
        }

        private static bool IsProcessStart(string declaringType, string methodName)
        {
            return declaringType.Contains("System.Diagnostics.Process", StringComparison.Ordinal) &&
                   methodName == "Start";
        }

        private static bool IsNativeExecutionSink(MethodReference method)
        {
            return DllImportInvocationContextExtractor.IsNativeExecutionPInvoke(method);
        }

        private static string GetNativeExecutionOperationName(MethodReference method)
        {
            try
            {
                if (method.Resolve() is not { } methodDefinition || methodDefinition.PInvokeInfo == null)
                {
                    return $"PInvoke.{method.Name}";
                }

                var entryPoint = methodDefinition.PInvokeInfo.EntryPoint ?? method.Name;
                return $"PInvoke.{entryPoint}";
            }
            catch
            {
                return $"PInvoke.{method.Name}";
            }
        }

        private static bool IsFileSink(string declaringType, string methodName)
        {
            return declaringType.StartsWith("System.IO.File", StringComparison.Ordinal) &&
                   (methodName.Contains("Write", StringComparison.Ordinal) ||
                    methodName.Contains("Create", StringComparison.Ordinal));
        }

        private static bool IsFileStreamSink(string declaringType, string methodName)
        {
            return declaringType == "System.IO.FileStream" && methodName == ".ctor";
        }

        private static bool IsNetworkSink(string declaringType, string methodName)
        {
            return (declaringType.StartsWith("System.Net", StringComparison.Ordinal) ||
                    declaringType.Contains("HttpClient", StringComparison.Ordinal) ||
                    declaringType.Contains("WebClient", StringComparison.Ordinal)) &&
                   (methodName.Contains("Post", StringComparison.Ordinal) ||
                    methodName.Contains("Send", StringComparison.Ordinal) ||
                    methodName.Contains("Upload", StringComparison.Ordinal));
        }

        private static bool IsRegistrySink(string declaringType, string methodName)
        {
            return declaringType.Contains("Microsoft.Win32.Registry", StringComparison.Ordinal) &&
                   (methodName.Contains("SetValue", StringComparison.Ordinal) ||
                    methodName.Contains("CreateSubKey", StringComparison.Ordinal));
        }
    }
}
