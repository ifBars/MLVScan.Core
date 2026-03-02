using Mono.Cecil;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Provides environment-specific entry point detection.
    /// Different mod loaders and frameworks have different entry point conventions.
    /// </summary>
    public interface IEntryPointProvider
    {
        /// <summary>
        /// Determines if a method is likely an entry point for the current environment.
        /// </summary>
        bool IsEntryPoint(MethodDefinition method);

        /// <summary>
        /// Gets the set of known entry point names for documentation purposes.
        /// </summary>
        IEnumerable<string> GetKnownEntryPointNames();
    }

    /// <summary>
    /// Generic entry point provider that detects common patterns across multiple environments.
    /// This is the default provider used when no specific environment is configured.
    /// </summary>
    public class GenericEntryPointProvider : IEntryPointProvider
    {
        // Common entry point patterns across mod loaders and game frameworks
        private static readonly HashSet<string> CommonEntryPoints = new(StringComparer.OrdinalIgnoreCase)
        {
            // Unity MonoBehaviour lifecycle
            "Awake",
            "Start",
            "Update",
            "LateUpdate",
            "FixedUpdate",
            "OnEnable",
            "OnDisable",
            "OnDestroy",
            
            // Unity application lifecycle
            "OnApplicationQuit",
            "OnApplicationPause",
            "OnApplicationFocus",
            
            // Common initialization patterns
            "Initialize",
            "Init",
            "Setup",
            
            // Static constructors
            ".cctor"
        };

        // Method name prefixes that suggest entry points
        private static readonly string[] EntryPointPrefixes = new[]
        {
            "On",
        };

        public bool IsEntryPoint(MethodDefinition method)
        {
            var name = method.Name;

            // Check exact matches
            if (CommonEntryPoints.Contains(name))
                return true;

            // Check prefixes (e.g., "OnSomething")
            foreach (var prefix in EntryPointPrefixes)
            {
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public IEnumerable<string> GetKnownEntryPointNames()
        {
            return CommonEntryPoints.OrderBy(n => n);
        }
    }
}
