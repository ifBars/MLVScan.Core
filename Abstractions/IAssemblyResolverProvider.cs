using Mono.Cecil;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction for providing assembly resolvers.
    /// Different platforms (MelonLoader, BepInEx) need to resolve game assemblies differently.
    /// </summary>
    public interface IAssemblyResolverProvider
    {
        /// <summary>
        /// Creates an assembly resolver configured for the current platform.
        /// </summary>
        IAssemblyResolver CreateResolver();
    }

    /// <summary>
    /// Default provider that creates a basic DefaultAssemblyResolver without any search directories.
    /// Suitable for web scenarios or standalone scanning where game assembly resolution isn't needed.
    /// </summary>
    public sealed class DefaultAssemblyResolverProvider : IAssemblyResolverProvider
    {
        /// <summary>
        /// Singleton instance for convenience.
        /// </summary>
        public static readonly DefaultAssemblyResolverProvider Instance = new();

        private DefaultAssemblyResolverProvider() { }

        public IAssemblyResolver CreateResolver() => new DefaultAssemblyResolver();
    }
}
