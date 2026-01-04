using Mono.Cecil;
using MLVScan.Models;

namespace MLVScan.Models.Rules
{
    public class ProcessStartRule : IScanRule
    {
        public string Description => "Detected Process.Start call which could execute arbitrary programs.";
        public Severity Severity => Severity.Critical;
        public string RuleId => "ProcessStartRule";
        public bool RequiresCompanionFinding => false;

        public IDeveloperGuidance? DeveloperGuidance => new DeveloperGuidance(
            "MelonLoader mods should not start external processes.",
            null,
            null,
            false
        );
        
        public bool IsSuspicious(MethodReference method)
        {
            if (method?.DeclaringType == null)
                return false;

            var typeName = method.DeclaringType.FullName;
            var methodName = method.Name;

            return (typeName.Contains("System.Diagnostics.Process") && methodName == "Start") ||
                   (typeName.Contains("Process") && methodName == "Start");
        }
    }
}
