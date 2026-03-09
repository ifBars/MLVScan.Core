using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    public class DllImportRule : IScanRule
    {
        private Severity _severity = Severity.Medium;
        private string _description = "Detected DLL import";

        public string Description => _description;
        public Severity Severity => _severity;
        public string RuleId => "DllImportRule";
        public bool RequiresCompanionFinding => false;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "Native DLL imports are flagged as high risk. If essential for your mod's functionality, clearly document the purpose and consider using managed alternatives where possible.",
            null,
            null,
            false
        );

        // DLLs that are commonly abused for execution, persistence, and networking.
        // Imports from these remain high risk unless function-level logic overrides.
        private static readonly string[] ElevatedRiskDlls =
        [
            "advapi32.dll",
            "wininet.dll",
            "urlmon.dll",
            "winsock.dll",
            "ws2_32.dll",
            "shell32.dll"
        ];

        // Native runtime/diagnostic DLLs are common in legitimate mods and tooling.
        // They are still tracked, but should not be treated as high risk by default.
        private static readonly string[] CommonNativeRuntimeDlls =
        [
            "kernel32.dll",
            "user32.dll",
            "ntdll.dll",
            "psapi.dll",
            "dbghelp.dll"
        ];

        // List of DLLs that are less commonly used for malicious purposes but worth noting
        private static readonly string[] MediumRiskDlls =
        [
            "gdi32.dll",
            "ole32.dll",
            "oleaut32.dll",
            "comctl32.dll",
            "comdlg32.dll",
            "version.dll",
            "winmm.dll"
        ];

        // Audio and media DLLs commonly used in legitimate mods for sound playback.
        // These are low risk unless they import suspicious functions (checked separately).
        private static readonly string[] LowRiskAudioMediaDlls =
        [
            "avrt.dll",
            "bass.dll",
            "bass_fx.dll",
            "bassenc.dll",
            "bassmix.dll",
            "basswasapi.dll",
            "bassasio.dll",
            "basscd.dll",
            "bassflac.dll",
            "bassmidi.dll",
            "bassopus.dll",
            "basswma.dll",
            "basswv.dll",
            "bassape.dll",
            "fmod.dll",
            "fmodex.dll",
            "fmodex64.dll",
            "fmodstudio.dll",
            "fmodstudio64.dll",
            "xaudio2_9.dll",
            "xaudio2_8.dll",
            "xaudio2_7.dll",
            "dsound.dll",
            "msacm32.dll",
            "winmm.dll",
            "mci.dll"
        ];

        // Strong indicators of execution, injection, or covert network activity.
        private static readonly string[] CriticalFunctions =
        [
            "createprocess",
            "virtualallocex",
            "writeprocessmemory",
            "readprocessmemory",
            "createremotethread",
            "internetopen",
            "internetconnect",
            "internetreadfile",
            "httpopen",
            "urldownload",
            "inject",
            "shellexecute"
        ];

        // Elevated process/thread/memory manipulation APIs that are suspicious on their own,
        // but less definitive than the critical indicators above.
        private static readonly string[] HighRiskFunctions =
        [
            "virtualalloc",
            "virtualprotect",
            "openprocess",
            "createthread",
            "openthread",
            "suspendthread",
            "resumethread"
        ];

        // Native execution entry points that can directly launch payloads.
        private static readonly string[] NativeExecutionFunctions =
        [
            "shellexecute",
            "createprocess",
            "winexec"
        ];

        // Common native interop APIs that appear in diagnostics/crash tooling.
        private static readonly string[] DiagnosticFunctions =
        [
            "getmodulehandle",
            "getcurrentprocess",
            "getcurrentprocessid",
            "getcurrentthreadid",
            "closehandle",
            "createtoolhelp32snapshot",
            "process32first",
            "process32next",
            "rtlgetversion",
            "ntqueryinformationprocess",
            "minidumpwritedump"
        ];

        // Specific UI-only imports that are common in legitimate software and do not
        // meaningfully expand attack capability on their own.
        private static readonly string[] BenignUserInteractionFunctions =
        [
            "messagebox"
        ];

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            if (method.Resolve() is not { } methodDef)
                return false;

            // Check if this is a PInvoke method
            if ((methodDef.Attributes & MethodAttributes.PInvokeImpl) == 0)
                return false;

            // Get PInvoke information
            if (methodDef.PInvokeInfo == null)
                return false;

            var dllName = methodDef.PInvokeInfo.Module.Name;
            var entryPoint = methodDef.PInvokeInfo.EntryPoint ?? method.Name;

            if (IsKnownIl2CppInteropBridge(methodDef, dllName, entryPoint))
                return false;

            var lowerDllName = dllName.ToLower();
            var entryPointLower = entryPoint.ToLower();

            if (MatchesKnownApi(entryPointLower, DiagnosticFunctions))
            {
                _severity = Severity.Low;
                _description = $"Detected diagnostic DllImport of {dllName} ({entryPoint})";
                return true;
            }

            if (IsNativeExecutionEntryPoint(entryPointLower))
            {
                _severity = Severity.Critical;
                _description = $"Detected high-risk native execution function {entryPoint} in DllImport from {dllName}";
                return true;
            }

            if (CriticalFunctions.Any(func => entryPointLower.Contains(func)))
            {
                _severity = Severity.Critical;
                _description = $"Detected high-risk function {entryPoint} in DllImport from {dllName}";
                return true;
            }

            if (HighRiskFunctions.Any(func => entryPointLower.Contains(func)))
            {
                _severity = Severity.High;
                _description = $"Detected elevated-risk function {entryPoint} in DllImport from {dllName}";
                return true;
            }

            if (IsBenignUserInteractionApi(methodDef, lowerDllName, entryPointLower))
            {
                return false;
            }

            // Low-risk audio/media DLLs are allowed unless they import suspicious functions (checked above)
            if (IsLowRiskAudioMediaDll(lowerDllName))
            {
                return false;
            }

            // Check for elevated-risk DLLs
            if (ElevatedRiskDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
            {
                _severity = Severity.High;
                _description = $"Detected high-risk DllImport of {dllName}";
                return true;
            }

            if (CommonNativeRuntimeDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
            {
                _severity = Severity.Medium;
                _description = $"Detected native runtime DllImport of {dllName} ({entryPoint})";
                return true;
            }

            // Check for medium-risk DLLs
            if (MediumRiskDlls.Any(dll => lowerDllName.Contains(dll.ToLower())))
            {
                _severity = Severity.Medium;
                _description = $"Detected medium-risk DllImport of {dllName}";
                return true;
            }

            // Any other DLL import is considered Medium risk
            _severity = Severity.Medium;
            _description = $"Detected DllImport of {dllName}";
            return true;
        }

        private static bool MatchesKnownApi(string entryPointLower, IEnumerable<string> knownApis)
        {
            foreach (var api in knownApis)
            {
                if (entryPointLower.Equals(api, StringComparison.OrdinalIgnoreCase) ||
                    entryPointLower.Equals($"{api}a", StringComparison.OrdinalIgnoreCase) ||
                    entryPointLower.Equals($"{api}w", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsKnownIl2CppInteropBridge(MethodDefinition methodDef, string dllName, string entryPoint)
        {
            if (methodDef.DeclaringType == null)
                return false;

            if (!methodDef.DeclaringType.FullName.Equals("Il2CppInterop.Runtime.IL2CPP", StringComparison.Ordinal))
                return false;

            if (!dllName.Equals("GameAssembly", StringComparison.OrdinalIgnoreCase) &&
                !dllName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return entryPoint.StartsWith("il2cpp_", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsNativeExecutionEntryPoint(string entryPointLower)
        {
            if (string.IsNullOrWhiteSpace(entryPointLower))
                return false;

            return NativeExecutionFunctions.Any(func =>
                entryPointLower.Contains(func, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsLowRiskAudioMediaDll(string lowerDllName)
        {
            // Normalize: remove .dll extension for comparison
            var normalizedDllName = NormalizeDllName(lowerDllName);

            foreach (var audioDll in LowRiskAudioMediaDlls)
            {
                // Normalize the known audio DLL name too
                var normalizedAudioDll = NormalizeDllName(audioDll);

                if (normalizedDllName == normalizedAudioDll)
                    return true;
            }

            return false;
        }

        private static bool IsBenignUserInteractionApi(MethodDefinition methodDef, string lowerDllName, string entryPointLower)
        {
            if (!NormalizeDllName(lowerDllName).Equals("user32", StringComparison.Ordinal))
            {
                return false;
            }

            if (!MatchesKnownApi(entryPointLower, BenignUserInteractionFunctions))
            {
                return false;
            }

            return HasStandardMessageBoxSignature(methodDef);
        }

        private static bool HasStandardMessageBoxSignature(MethodDefinition methodDef)
        {
            if (methodDef.ReturnType.MetadataType != MetadataType.Int32)
            {
                return false;
            }

            if (methodDef.Parameters.Count != 4)
            {
                return false;
            }

            if (methodDef.Parameters[0].ParameterType.MetadataType != MetadataType.IntPtr)
            {
                return false;
            }

            if (methodDef.Parameters[1].ParameterType.MetadataType != MetadataType.String ||
                methodDef.Parameters[2].ParameterType.MetadataType != MetadataType.String)
            {
                return false;
            }

            return IsMessageBoxOptionsType(methodDef.Parameters[3].ParameterType);
        }

        private static bool IsMessageBoxOptionsType(TypeReference parameterType)
        {
            if (parameterType.MetadataType == MetadataType.Int32 ||
                parameterType.MetadataType == MetadataType.UInt32)
            {
                return true;
            }

            if (parameterType.Resolve() is not { IsEnum: true } enumType)
            {
                return false;
            }

            var underlyingField = enumType.Fields.FirstOrDefault(field => field.Name == "value__");
            return underlyingField?.FieldType.MetadataType == MetadataType.Int32 ||
                   underlyingField?.FieldType.MetadataType == MetadataType.UInt32;
        }

        private static string NormalizeDllName(string dllName)
        {
            var normalizedDllName = dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? dllName.Substring(0, dllName.Length - 4)
                : dllName;

            return normalizedDllName.ToLowerInvariant();
        }
    }
}
