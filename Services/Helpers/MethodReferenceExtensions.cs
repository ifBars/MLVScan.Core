using Mono.Cecil;

namespace MLVScan.Services.Helpers
{
    internal static class MethodReferenceExtensions
    {
        public static string GetMethodKey(this MethodReference method)
        {
            return method.FullName;
        }

        public static string GetDisplayName(this MethodReference method)
        {
            return $"{method.DeclaringType?.Name}.{method.Name}";
        }

        public static string GetMethodLocation(this MethodDefinition method)
        {
            return $"{method.DeclaringType?.FullName}.{method.Name}";
        }
    }
}
