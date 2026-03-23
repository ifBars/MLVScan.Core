using MLVScan.Models;
using System.Reflection;
using MLVScan.Abstractions;

namespace MLVScan.Services.Helpers
{
    /// <summary>
    /// Detects whether a rule type overrides a specific rule interface method.
    /// </summary>
    internal static class RuleOverrideChecker
    {
        /// <summary>
        /// Determines whether a rule type declares its own implementation of the given method.
        /// </summary>
        /// <param name="rule">The rule instance to inspect.</param>
        /// <param name="methodName">The method name to look up.</param>
        /// <param name="parameterTypes">The parameter signature used to resolve the method.</param>
        /// <returns><see langword="true"/> when the method exists on the rule type and is not the interface implementation.</returns>
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
