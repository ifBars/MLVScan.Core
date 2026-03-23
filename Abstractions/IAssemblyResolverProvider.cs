using Mono.Cecil;
using System.ComponentModel;

namespace MLVScan.Abstractions
{
    /// <summary>
    /// Abstraction for providing assembly resolvers.
    /// </summary>
    public interface IAssemblyResolverProvider
    {
        /// <summary>
        /// Creates an assembly resolver configured for the current environment.
        /// </summary>
        /// <returns>A resolver that can be used to resolve referenced assemblies.</returns>
        IAssemblyResolver CreateResolver();
    }

    /// <summary>
    /// Default provider that creates a basic <see cref="DefaultAssemblyResolver"/>.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class DefaultAssemblyResolverProvider : IAssemblyResolverProvider
    {
        /// <summary>
        /// Singleton instance for convenience.
        /// </summary>
        public static readonly DefaultAssemblyResolverProvider Instance = new();

        private DefaultAssemblyResolverProvider() { }

        /// <inheritdoc />
        public IAssemblyResolver CreateResolver() => new DefaultAssemblyResolver();
    }
}
