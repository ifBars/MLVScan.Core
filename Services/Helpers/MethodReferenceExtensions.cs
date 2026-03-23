using Mono.Cecil;

namespace MLVScan.Services.Helpers
{
    /// <summary>
    /// Extension methods for formatting Cecil method references and definitions.
    /// </summary>
    internal static class MethodReferenceExtensions
    {
        /// <summary>
        /// Gets a stable key for a method reference.
        /// </summary>
        /// <param name="method">The method reference to format.</param>
        /// <returns>The Cecil full name for the method.</returns>
        public static string GetMethodKey(this MethodReference method)
        {
            return method.FullName;
        }

        /// <summary>
        /// Gets a compact display name for a method reference.
        /// </summary>
        /// <param name="method">The method reference to format.</param>
        /// <returns>A short display string in the form <c>Type.Method</c>.</returns>
        public static string GetDisplayName(this MethodReference method)
        {
            return $"{method.DeclaringType?.Name}.{method.Name}";
        }

        /// <summary>
        /// Gets a fully qualified method location string.
        /// </summary>
        /// <param name="method">The method definition to format.</param>
        /// <returns>A location string in the form <c>Namespace.Type.Method</c>.</returns>
        public static string GetMethodLocation(this MethodDefinition method)
        {
            return $"{method.DeclaringType?.FullName}.{method.Name}";
        }
    }
}
