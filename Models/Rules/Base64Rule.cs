using MLVScan.Models;
using Mono.Cecil;

namespace MLVScan.Models.Rules
{
    public class Base64Rule : IScanRule
    {
        public string Description => "Detected FromBase64String call which decodes base64 encrypted strings.";
        public Severity Severity => Severity.Low;
        public string RuleId => "Base64Rule";
        public bool RequiresCompanionFinding => true;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "If decoding configuration data, store it in plain text or use your mod framework's configuration system. " +
            "For MelonLoader: use MelonPreferences. For BepInEx: use Config.Bind<T>(). " +
            "If decoding assets, embed them directly in your mod or load from standard resources.",
            null,
            new[] {
                "MelonPreferences.CreateEntry<T> (MelonLoader)",
                "MelonPreferences.GetEntry<T> (MelonLoader)",
                "Config.Bind<T> (BepInEx)"
            },
            true
        );

        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return typeName.Contains("Convert") && methodName.Contains("FromBase64");
        }
    }
}
