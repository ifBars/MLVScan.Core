using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers
{
    internal static class ObfuscatedSinkMatcher
    {
        public static bool IsReflectionInvokeSink(string typeName, string methodName)
        {
            return ((typeName == "System.Reflection.MethodInfo" || typeName == "System.Reflection.MethodBase") &&
                    methodName == "Invoke") ||
                   (typeName == "System.Delegate" && methodName == "DynamicInvoke");
        }

        public static bool IsAssemblyLoadSink(string typeName, string methodName)
        {
            if (typeName == "System.Reflection.Assembly" &&
                (methodName == "Load" || methodName == "LoadFrom" || methodName == "LoadFile" ||
                 methodName == "UnsafeLoadFrom"))
            {
                return true;
            }

            if (typeName == "System.AppDomain" && methodName == "Load")
            {
                return true;
            }

            return typeName.Contains("AssemblyLoadContext", StringComparison.Ordinal) &&
                   (methodName == "LoadFromAssemblyPath" || methodName == "LoadFromStream");
        }

        public static bool IsProcessSink(string typeName, string methodName)
        {
            return typeName == "System.Diagnostics.Process" && methodName == "Start";
        }

        public static bool IsPotentialNativeExecutionSink(MethodReference calledMethod, string typeName,
            string methodName)
        {
            if (methodName.IndexOf("ShellExecute", StringComparison.OrdinalIgnoreCase) >= 0 ||
                methodName.IndexOf("CreateProcess", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            try
            {
                MethodDefinition? resolved = calledMethod.Resolve();
                if (resolved != null && resolved.IsPInvokeImpl)
                {
                    return true;
                }
            }
            catch
            {
                // Ignore unresolved method references.
            }

            return typeName == "System.Runtime.InteropServices.Marshal" &&
                   (methodName == "GetDelegateForFunctionPointer" || methodName == "GetFunctionPointerForDelegate");
        }

        public static bool IsDynamicTargetResolution(string typeName, string methodName)
        {
            if (typeName == "System.Type" &&
                (methodName == "GetType" || methodName == "GetMethod" || methodName == "GetProperty" ||
                 methodName == "GetField" || methodName == "InvokeMember"))
            {
                return true;
            }

            if (typeName == "System.Reflection.Assembly" && (methodName == "GetType" || methodName == "CreateInstance"))
            {
                return true;
            }

            return typeName == "System.Activator" && methodName == "CreateInstance";
        }

        public static bool IsNetworkCall(string typeName, string methodName)
        {
            if (typeName == "System.Net.WebClient" &&
                (methodName.StartsWith("Download", StringComparison.Ordinal) ||
                 methodName.StartsWith("Upload", StringComparison.Ordinal) ||
                 methodName == "OpenRead"))
            {
                return true;
            }

            if (typeName == "System.Net.Http.HttpClient" &&
                (methodName.StartsWith("Get", StringComparison.Ordinal) ||
                 methodName.StartsWith("Post", StringComparison.Ordinal) ||
                 methodName == "SendAsync"))
            {
                return true;
            }

            if (typeName == "System.Net.WebRequest" &&
                (methodName == "Create" || methodName == "GetRequestStream" || methodName == "GetResponse"))
            {
                return true;
            }

            return typeName == "System.Net.Sockets.Socket" && methodName == "Connect";
        }

        public static bool IsFileWriteCall(string typeName, string methodName)
        {
            if (typeName == "System.IO.File" &&
                (methodName.StartsWith("Write", StringComparison.Ordinal) ||
                 methodName.StartsWith("Append", StringComparison.Ordinal) ||
                 methodName == "Create"))
            {
                return true;
            }

            if (typeName == "System.IO.FileStream" && methodName == "Write")
            {
                return true;
            }

            if (typeName == "System.IO.StreamWriter" && methodName.StartsWith("Write", StringComparison.Ordinal))
            {
                return true;
            }

            return typeName == "System.IO.BinaryWriter" && methodName.StartsWith("Write", StringComparison.Ordinal);
        }

        public static int? ExtractFolderPathArgument(Mono.Collections.Generic.Collection<Instruction> instructions,
            int currentIndex)
        {
            int start = Math.Max(0, currentIndex - 5);
            for (int i = currentIndex - 1; i >= start; i--)
            {
                Instruction instruction = instructions[i];
                if (instruction.OpCode == OpCodes.Ldc_I4)
                {
                    return (int)instruction.Operand;
                }

                if (instruction.OpCode == OpCodes.Ldc_I4_S)
                {
                    return (sbyte)instruction.Operand;
                }

                if (instruction.OpCode == OpCodes.Ldc_I4_0) return 0;
                if (instruction.OpCode == OpCodes.Ldc_I4_1) return 1;
                if (instruction.OpCode == OpCodes.Ldc_I4_2) return 2;
                if (instruction.OpCode == OpCodes.Ldc_I4_3) return 3;
                if (instruction.OpCode == OpCodes.Ldc_I4_4) return 4;
                if (instruction.OpCode == OpCodes.Ldc_I4_5) return 5;
                if (instruction.OpCode == OpCodes.Ldc_I4_6) return 6;
                if (instruction.OpCode == OpCodes.Ldc_I4_7) return 7;
                if (instruction.OpCode == OpCodes.Ldc_I4_8) return 8;
            }

            return null;
        }
    }
}
