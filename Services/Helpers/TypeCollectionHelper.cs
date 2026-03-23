using Mono.Cecil;
using System.ComponentModel;

namespace MLVScan.Services.Helpers
{
    /// <summary>
    /// Collects all top-level and nested type definitions from a Cecil module.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class TypeCollectionHelper
    {
        /// <summary>
        /// Gets every type in the module, including nested types.
        /// </summary>
        /// <param name="module">The module to enumerate.</param>
        /// <returns>All type definitions discovered in the module.</returns>
        public static IEnumerable<TypeDefinition> GetAllTypes(ModuleDefinition module)
        {
            var allTypes = new List<TypeDefinition>();

            try
            {
                // Add top-level types
                foreach (var type in module.Types)
                {
                    allTypes.Add(type);

                    // Add nested types
                    CollectNestedTypes(type, allTypes);
                }
            }
            catch (Exception)
            {
                // Ignore errors
            }

            return allTypes;
        }

        private static void CollectNestedTypes(TypeDefinition type, List<TypeDefinition> allTypes)
        {
            try
            {
                foreach (var nestedType in type.NestedTypes)
                {
                    allTypes.Add(nestedType);
                    CollectNestedTypes(nestedType, allTypes);
                }
            }
            catch (Exception)
            {
                // Ignore errors
            }
        }
    }
}
