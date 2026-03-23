using MLVScan.Models;
using System.Reflection;
using MLVScan.Abstractions;

namespace MLVScan.Services.Helpers
{
    internal static class RuleOverrideChecker
    {
        public static bool OverridesRuleMethod(IScanRule rule, string methodName, params Type[] parameterTypes)
        {
            var method = rule.GetType().GetMethod(
                methodName,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                types: parameterTypes,
                modifiers: null);

            return method != null && method.DeclaringType != typeof(IScanRule);
        }
    }
}
