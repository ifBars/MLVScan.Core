using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class Base64Rule : IScanRule
    {
        public string Description => "Detected FromBase64String call which decodes base64 encrypted strings.";
        public Severity Severity => Severity.Low;
        public string RuleId => "Base64Rule";
        public bool RequiresCompanionFinding => false;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "If decoding configuration data, store it in plain text or use MelonPreferences. If decoding assets, embed them directly in your mod.",
            "https://melonwiki.xyz/#/modders/preferences",
            new[] { "MelonPreferences.CreateEntry<T>", "MelonPreferences.GetEntry<T>" },
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