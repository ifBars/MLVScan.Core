using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules
{
    /// <summary>
    /// Detects calls to <see cref="System.Convert.FromBase64String(string)"/> and related Base64 decode
    /// entry points.
    /// </summary>
    public class Base64Rule : IScanRule
    {
        /// <summary>
        /// Gets the human-readable description for this rule.
        /// </summary>
        public string Description => "Detected FromBase64String call which decodes base64 encrypted strings.";

        /// <summary>
        /// Gets the severity assigned to Base64 decoding patterns.
        /// </summary>
        public Severity Severity => Severity.Low;

        /// <summary>
        /// Gets the stable identifier for this rule.
        /// </summary>
        public string RuleId => "Base64Rule";

        /// <summary>
        /// Gets a value indicating whether this rule requires another finding to trigger.
        /// </summary>
        public bool RequiresCompanionFinding => true;

        /// <summary>
        /// Gets developer guidance for replacing Base64-encoded configuration or payload handling.
        /// </summary>
        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "If decoding configuration data, store it in plain text or use your mod framework's configuration system. " +
            "For MelonLoader: use MelonPreferences. For BepInEx: use Config.Bind<T>(). " +
            "If decoding assets, embed them directly in your mod or load from standard resources.",
            null,
            new[]
            {
                "MelonPreferences.CreateEntry<T> (MelonLoader)", "MelonPreferences.GetEntry<T> (MelonLoader)",
                "Config.Bind<T> (BepInEx)"
            },
            true
        );

        /// <summary>
        /// Returns true when the supplied method is a Base64 decode call.
        /// </summary>
        /// <param name="method">The method reference to inspect.</param>
        /// <returns><see langword="true"/> when the method matches a Base64 decoding API; otherwise <see langword="false"/>.</returns>
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return typeName == "System.Convert" &&
                   methodName is "FromBase64String" or "FromBase64CharArray";
        }

        /// <summary>
        /// Suppresses ordinary Base64 decoding while retaining decode evidence near obfuscated payloads,
        /// staging, reflection, or execution.
        /// </summary>
        /// <param name="method">The Base64 decode method.</param>
        /// <param name="instructions">The containing method's IL instructions.</param>
        /// <param name="instructionIndex">The Base64 call index.</param>
        /// <param name="methodSignals">Signals collected for the containing method.</param>
        /// <param name="typeSignals">Optional signals collected for the containing type.</param>
        /// <returns><see langword="true"/> when the decode has no security-relevant local context.</returns>
        public bool ShouldSuppressFinding(
            MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals,
            MethodSignals? typeSignals = null)
        {
            if (!IsSuspicious(method))
                return true;

            ObfuscatedExecutionEvidence evidence =
                ObfuscatedExecutionHeuristics.CollectEvidence(instructions);

            bool hasExecutionOrDynamicSink =
                evidence.HasProcessLikeSink ||
                evidence.HasReflectionInvokeSink ||
                evidence.HasAssemblyLoadSink ||
                evidence.HasNativeSink ||
                evidence.HasDynamicTargetResolution;

            bool hasPayloadOrStagingEvidence =
                evidence.HasEncodedLiteral ||
                evidence.HasDangerousLiteral ||
                evidence.HasFileWriteCall ||
                evidence.HasSensitivePathAccess;

            return !hasExecutionOrDynamicSink && !hasPayloadOrStagingEvidence;
        }
    }
}
