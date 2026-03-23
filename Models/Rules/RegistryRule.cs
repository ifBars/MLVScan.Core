using MLVScan.Abstractions;
using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects Windows Registry reads and writes through managed APIs and P/Invoke entry points.
    /// </summary>
    public class RegistryRule : IScanRule
    {
        private Severity _severity = Severity.Critical;
        private string _description =
            "Detected Windows Registry manipulation, which is suspicious for a game mod. Registry access could be used to persist malware or modify system settings.";

        /// <summary>
        /// Gets the description for the most recently matched registry action.
        /// </summary>
        public string Description =>
            _description;

        /// <summary>
        /// Gets the severity for the most recently matched registry action.
        /// </summary>
        public Severity Severity => _severity;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "RegistryRule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding before it can trigger.
        /// </summary>
        public bool RequiresCompanionFinding => false;

        /// <summary>
        /// Gets guidance for legitimate configuration storage alternatives.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "Game mods should not modify the Windows Registry. For persistent settings, use your mod framework's configuration system: " +
            "MelonPreferences for MelonLoader, Config.Bind<T>() for BepInEx, or Unity's PlayerPrefs for simple settings.",
            null,
            new[]
            {
                "MelonPreferences.CreateEntry<T> (MelonLoader)", "Config.Bind<T> (BepInEx)",
                "UnityEngine.PlayerPrefs (Unity)"
            },
            false // Registry access is inherently suspicious
        );

        private static readonly string[] RegistryFunctions =
        [
            "regcreatekeyex",
            "regopenkey",
            "regopenkeya",
            "regopenkeyex",
            "regopenkeyexa",
            "regopenkeyexw",
            "regsetvalue",
            "regsetvaluea",
            "regsetvaluew",
            "regsetvalueex",
            "regsetvalueexa",
            "regsetvalueexw",
            "reggetvalue",
            "reggetvaluea",
            "reggetvaluew",
            "regdeletekey",
            "regdeletevalue",
            "regenumkey",
            "regenumvalue",
            "regqueryvalue",
            "regqueryvalueex",
            "regcreatekey",
            "regsetkeysecurity",
            "regloadkey",
            "regsavekey",
            "regnotifychangekeyvalue"
        ];

        private static readonly string[] RegistryWriteFunctions =
        [
            "regcreatekeyex",
            "regcreatekey",
            "regsetvalue",
            "regsetvaluea",
            "regsetvaluew",
            "regsetvalueex",
            "regsetvalueexa",
            "regsetvalueexw",
            "regdeletekey",
            "regdeletevalue",
            "regsetkeysecurity",
            "regloadkey",
            "regsavekey",
            "regnotifychangekeyvalue"
        ];

        private static readonly string[] RegistryReadFunctions =
        [
            "regopenkey",
            "regopenkeya",
            "regopenkeyex",
            "regopenkeyexa",
            "regopenkeyexw",
            "reggetvalue",
            "reggetvaluea",
            "reggetvaluew",
            "regenumkey",
            "regenumvalue",
            "regqueryvalue",
            "regqueryvalueex"
        ];

        /// <summary>
        /// Returns true when the supplied method is a managed or native registry access API.
        /// </summary>
        /// <param name="method">The method reference to inspect.</param>
        /// <returns><see langword="true"/> when the method manipulates or queries the Windows Registry.</returns>
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name.ToLowerInvariant();

            if (typeName.Contains("Microsoft.Win32.Registry", StringComparison.Ordinal) ||
                typeName.Contains("RegistryKey", StringComparison.Ordinal) ||
                typeName.Contains("RegistryHive", StringComparison.Ordinal))
            {
                return ClassifyManagedRegistryCall(methodName);
            }

            if (RegistryWriteFunctions.Any(regFunction => methodName.Contains(regFunction, StringComparison.Ordinal)))
            {
                _severity = Severity.Critical;
                _description =
                    "Detected Windows Registry write operation, which could be used for persistence or system tampering.";
                return true;
            }

            if (RegistryReadFunctions.Any(regFunction => methodName.Contains(regFunction, StringComparison.Ordinal)))
            {
                _severity = Severity.Low;
                _description =
                    "Detected Windows Registry read access. This can be legitimate for configuration discovery, but should not be used to modify the system.";
                return true;
            }

            if (method.Resolve() is not { } methodDef)
                return false;

            // Check if this is a PInvoke method
            if ((methodDef.Attributes & MethodAttributes.PInvokeImpl) == 0)
                return false;

            if (methodDef.PInvokeInfo == null)
                return false;

            var dllName = methodDef.PInvokeInfo.Module.Name;
            var entryPoint = methodDef.PInvokeInfo.EntryPoint ?? method.Name;

            // Check if it's advapi32.dll (registry DLL)
            if (!dllName.ToLowerInvariant().Contains("advapi32"))
                return false;

            if (RegistryWriteFunctions.Any(func => methodName.Contains(func, StringComparison.Ordinal)))
            {
                _severity = Severity.Critical;
                _description =
                    $"Detected native Windows Registry write API {entryPoint} from {dllName}, which could be used for persistence or system tampering.";
                return true;
            }

            var entryPointLower = entryPoint.ToLowerInvariant();
            if (RegistryWriteFunctions.Any(func => entryPointLower.Contains(func, StringComparison.Ordinal)))
            {
                _severity = Severity.Critical;
                _description =
                    $"Detected native Windows Registry write API {entryPoint} from {dllName}, which could be used for persistence or system tampering.";
                return true;
            }

            if (RegistryReadFunctions.Any(func => methodName.Contains(func, StringComparison.Ordinal)) ||
                RegistryReadFunctions.Any(func => entryPointLower.Contains(func, StringComparison.Ordinal)))
            {
                _severity = Severity.Low;
                _description =
                    $"Detected native Windows Registry read API {entryPoint} from {dllName}. This can be legitimate for configuration discovery, but should not modify the system.";
                return true;
            }

            return false;
        }

        /// <summary>
        /// Classifies managed registry access by operation type so the emitted severity matches the action.
        /// </summary>
        /// <param name="methodName">The normalized managed registry method name.</param>
        /// <returns><see langword="true"/> when the method maps to a tracked registry operation.</returns>
        private bool ClassifyManagedRegistryCall(string methodName)
        {
            if (methodName.Contains("setvalue", StringComparison.Ordinal) ||
                methodName.Contains("create", StringComparison.Ordinal) ||
                methodName.Contains("delete", StringComparison.Ordinal) ||
                methodName.Contains("save", StringComparison.Ordinal) ||
                methodName.Contains("flush", StringComparison.Ordinal))
            {
                _severity = Severity.Critical;
                _description =
                    "Detected Windows Registry write operation, which could be used for persistence or system tampering.";
                return true;
            }

            if (methodName.Contains("getvalue", StringComparison.Ordinal) ||
                methodName.Contains("open", StringComparison.Ordinal) ||
                methodName.Contains("query", StringComparison.Ordinal) ||
                methodName.Contains("enum", StringComparison.Ordinal))
            {
                _severity = Severity.Low;
                _description =
                    "Detected Windows Registry read access. This can be legitimate for configuration discovery, but should not be used to modify the system.";
                return true;
            }

            _severity = Severity.Medium;
            _description =
                "Detected Windows Registry access. Registry interaction is uncommon in mods and should be reviewed carefully.";
            return true;
        }
    }
}
