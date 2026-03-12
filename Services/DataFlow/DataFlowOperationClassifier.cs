using MLVScan.Models;
using MLVScan.Models.DataFlow;
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

                if (!instruction.IsCallOrCallvirt() ||
                    instruction.Operand is not MethodReference calledMethod)
                {
                    continue;
                }

                var operationInfo = ClassifyOperation(calledMethod);
                if (operationInfo != null)
                {
                    operations.Add(new DataFlowInterestingOperation
                    {
                        Instruction = instruction,
                        InstructionIndex = index,
                        MethodReference = calledMethod,
                        NodeType = operationInfo.Value.NodeType,
                        Operation = operationInfo.Value.Operation,
                        DataDescription = operationInfo.Value.DataDescription,
                        LocalVariableIndex = DataFlowInstructionHelper.TryGetTargetLocalVariable(instructions, index)
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
