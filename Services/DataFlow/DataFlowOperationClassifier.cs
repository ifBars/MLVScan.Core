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
                        DataDescription = operationInfo.Value.DataDescription,
                        LocalVariableIndex = DataFlowInstructionHelper.TryGetTargetLocalVariable(instructions, index),
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

        private static HashSet<string> TryGetPayloadPathIdentities(
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

        private static bool IsWritableFileStreamConstructor(
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

        private static HashSet<string> TryGetProcessStartPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int processStartIndex,
            MethodReference processStartMethod)
        {
            int? startInfoLocal = null;
            int? processLocal = null;

            if (!processStartMethod.HasThis &&
                processStartMethod.Parameters.Count == 1 &&
                processStartMethod.Parameters[0].ParameterType.FullName == "System.Diagnostics.ProcessStartInfo")
            {
                if (DataFlowInstructionHelper.TryGetCallArgumentLocalVariable(
                        instructions, processStartIndex, processStartMethod, 0, out var resolvedStartInfoLocal))
                {
                    startInfoLocal = resolvedStartInfoLocal;
                }
                else if (DataFlowInstructionHelper.TryGetCallArgumentProducerIndex(
                             instructions, processStartIndex, processStartMethod, 0, out var producerIndex) &&
                         instructions[producerIndex].OpCode == OpCodes.Newobj &&
                         instructions[producerIndex].Operand is MethodReference constructor &&
                         constructor.DeclaringType?.FullName == "System.Diagnostics.ProcessStartInfo" &&
                         constructor.Parameters.Count > 0)
                {
                    return TryGetCallArgumentIdentities(method, instructions, producerIndex, constructor, 0);
                }
                else
                {
                    return EmptyIdentities();
                }
            }
            else if (processStartMethod.HasThis)
            {
                if (!DataFlowInstructionHelper.TryGetCallReceiverLocalVariable(
                        instructions, processStartIndex, processStartMethod, out var resolvedProcessLocal))
                {
                    return EmptyIdentities();
                }

                processLocal = resolvedProcessLocal;
            }
            else if (processStartMethod.Parameters.Count > 0)
            {
                return TryGetCallArgumentIdentities(method, instructions, processStartIndex, processStartMethod, 0);
            }

            IReadOnlyCollection<int> startInfoDefinitionIndexes = Array.Empty<int>();
            if (startInfoLocal.HasValue &&
                DataFlowInstructionHelper.TryGetCallArgumentProducerIndex(
                    instructions, processStartIndex, processStartMethod, 0, out var startInfoLoadIndex))
            {
                startInfoDefinitionIndexes = DataFlowInstructionHelper.GetReachingLocalStoreIndexes(
                    instructions, startInfoLoadIndex, startInfoLocal.Value);
            }

            var setterIndexes = DataFlowInstructionHelper.GetReachingInstructionIndexes(
                instructions,
                processStartIndex,
                index => TryGetStartInfoFileNameSetter(instructions[index], out var setter) &&
                         StartInfoSetterBelongsToStartedProcess(
                             instructions,
                             index,
                             setter,
                             startInfoLocal,
                             processLocal,
                             startInfoDefinitionIndexes));
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

            return identities;
        }

        private static HashSet<string> TryGetStoredStartInfoConstructorIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int storeIndex)
        {
            if (!DataFlowInstructionHelper.TryGetConsumedValueProducerIndex(
                    instructions, storeIndex, out var producerIndex) ||
                instructions[producerIndex].OpCode != OpCodes.Newobj ||
                instructions[producerIndex].Operand is not MethodReference constructor ||
                constructor.DeclaringType?.FullName != "System.Diagnostics.ProcessStartInfo" ||
                constructor.Parameters.Count == 0)
            {
                return EmptyIdentities();
            }

            return TryGetCallArgumentIdentities(method, instructions, producerIndex, constructor, 0);
        }

        private static bool TryGetStartInfoFileNameSetter(
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

        private static bool StartInfoSetterBelongsToStartedProcess(
            Collection<Instruction> instructions,
            int setterIndex,
            MethodReference setter,
            int? startInfoLocal,
            int? processLocal,
            IReadOnlyCollection<int> startedStartInfoDefinitions)
        {
            if (startInfoLocal.HasValue)
            {
                if (!DataFlowInstructionHelper.TryGetCallReceiverProducerIndex(
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

                var setterStartInfoDefinitions = DataFlowInstructionHelper.GetReachingLocalStoreIndexes(
                    instructions, receiverProducerIndex, setterStartInfoLocal);
                return setterStartInfoDefinitions.Intersect(startedStartInfoDefinitions).Any();
            }

            if (!processLocal.HasValue ||
                !DataFlowInstructionHelper.TryGetCallReceiverProducerIndex(
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

            return DataFlowInstructionHelper.TryGetCallReceiverLocalVariable(
                       instructions, setterReceiverProducerIndex, getter, out var setterProcessLocal) &&
                   setterProcessLocal == processLocal.Value;
        }

        private static HashSet<string> TryGetNativeExecutionPathIdentities(
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

        private static HashSet<string> TryGetCreateProcessPathIdentities(
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

        private static HashSet<string> TryGetShellExecuteExFileIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int callIndex,
            MethodReference calledMethod)
        {
            if (!DataFlowInstructionHelper.TryGetCallArgumentLocalVariable(
                    instructions, callIndex, calledMethod, 0, out var shellExecuteInfoLocal))
            {
                return EmptyIdentities();
            }

            var searchStart = Math.Max(0, callIndex - 400);
            for (var index = callIndex - 1; index >= searchStart; index--)
            {
                if (instructions[index].OpCode != OpCodes.Stfld ||
                    instructions[index].Operand is not FieldReference field ||
                    !field.Name.Equals("lpFile", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!DataFlowInstructionHelper.TryGetFieldStoreReceiverLocalVariable(
                        instructions, index, out var fieldReceiverLocal) ||
                    fieldReceiverLocal != shellExecuteInfoLocal)
                {
                    continue;
                }

                if (index > 0 && instructions[index - 1].TryGetLocalIndex(out var localIndex))
                {
                    return BuildLocalPathIdentities(method, instructions, index - 1, localIndex);
                }

                if (InstructionValueResolver.TryResolveStackValueDisplay(
                        method, instructions, index - 1, out var display) &&
                    IsConcreteResolvedPath(display))
                {
                    return SingleIdentity(NormalizeResolvedPathIdentity(display));
                }
            }

            return EmptyIdentities();
        }

        private static HashSet<string> TryGetCallArgumentIdentities(
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
            if (DataFlowInstructionHelper.TryGetCallArgumentLocalVariable(
                    instructions, callIndex, calledMethod, argumentIndex, out var localIndex, out var producerIndex))
            {
                identities.UnionWith(BuildLocalPathIdentities(method, instructions, producerIndex, localIndex));
            }
            else if (DataFlowInstructionHelper.TryGetCallArgumentProducerIndex(
                         instructions, callIndex, calledMethod, argumentIndex, out producerIndex) &&
                     TryGetMethodParameterIndex(method, instructions[producerIndex], out var parameterIndex))
            {
                identities.Add(BuildArgumentPathIdentity(method, parameterIndex));
            }

            if (resolved && IsConcreteResolvedPath(display))
            {
                identities.Add(NormalizeResolvedPathIdentity(display));
            }

            return identities;
        }

        private static bool TryGetMethodParameterIndex(
            MethodDefinition method,
            Instruction instruction,
            out int parameterIndex)
        {
            parameterIndex = -1;
            if (!instruction.TryGetArgumentIndex(out var rawIndex))
            {
                return false;
            }

            parameterIndex = instruction.Operand is ParameterDefinition parameter
                ? parameter.Index
                : rawIndex - (method.HasThis ? 1 : 0);
            return parameterIndex >= 0 && parameterIndex < method.Parameters.Count;
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

        private static HashSet<string> BuildLocalPathIdentities(
            MethodDefinition method,
            Collection<Instruction> instructions,
            int localLoadIndex,
            int localIndex)
        {
            var storeIndexes = DataFlowInstructionHelper.GetReachingLocalStoreIndexes(
                instructions, localLoadIndex, localIndex);
            if (storeIndexes.Count == 0)
            {
                return SingleIdentity($"{method.GetMethodKey()}::local:{localIndex}@parameter");
            }

            return storeIndexes
                .Select(index => $"{method.GetMethodKey()}::local:{localIndex}@instruction:{index}")
                .ToHashSet(StringComparer.Ordinal);
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
