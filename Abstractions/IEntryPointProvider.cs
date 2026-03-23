using Mono.Cecil;
using System.ComponentModel;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Provides environment-specific entry-point detection.
    /// </summary>
    public interface IEntryPointProvider
    {
        /// <summary>
        /// Determines whether a method should be treated as an entry point for the current environment.
        /// </summary>
        /// <param name="method">Method to evaluate.</param>
        /// <returns><see langword="true"/> when the method is treated as an entry point.</returns>
        bool IsEntryPoint(MethodDefinition method);

        /// <summary>
        /// Gets the set of entry-point names known to the provider.
        /// </summary>
        /// <returns>Names that the provider recognizes as entry-point-like.</returns>
        IEnumerable<string> GetKnownEntryPointNames();
    }

    /// <summary>
    /// Generic entry-point provider that detects common patterns across multiple environments.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
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

        /// <inheritdoc />
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

        /// <inheritdoc />
        public IEnumerable<string> GetKnownEntryPointNames()
        {
            return CommonEntryPoints.OrderBy(n => n);
        }
    }
}
