namespace MLVScan.Tools.SchemaGen;

internal static class TypeDiscovery
{
    public static IReadOnlyList<Type> CollectSchemaObjectTypes(Type rootType)
    {
        var discoveredTypes = new HashSet<Type>();
        var queue = new Queue<Type>();

        Enqueue(rootType, discoveredTypes, queue);

        while (queue.Count > 0)
        {
            var currentType = queue.Dequeue();

            foreach (var property in SchemaTypeConventions.GetSchemaProperties(currentType))
            {
                foreach (var nestedType in GetNestedSchemaObjectTypes(property.PropertyType))
                {
                    Enqueue(nestedType, discoveredTypes, queue);
                }
            }
        }

        return discoveredTypes
            .OrderBy(type => type == rootType ? 0 : 1)
            .ThenBy(SchemaTypeConventions.GetSchemaTypeName, StringComparer.Ordinal)
            .ToList();
    }

    public static IReadOnlyList<StringUnionSpec> CollectStringUnions(IEnumerable<Type> objectTypes)
    {
        return objectTypes
            .SelectMany(SchemaTypeConventions.GetSchemaProperties)
            .Select(SchemaTypeConventions.GetStringUnion)
            .Where(static unionSpec => unionSpec != null)
            .Select(static unionSpec => unionSpec!)
            .GroupBy(static unionSpec => unionSpec.Name, StringComparer.Ordinal)
            .Select(static group => group.First())
            .OrderBy(static unionSpec => unionSpec.Name, StringComparer.Ordinal)
            .ToList();
    }

    private static IEnumerable<Type> GetNestedSchemaObjectTypes(Type type)
    {
        var nonNullableType = Nullable.GetUnderlyingType(type) ?? type;

        if (SchemaTypeConventions.IsCollectionType(nonNullableType))
        {
            foreach (var nestedType in GetNestedSchemaObjectTypes(SchemaTypeConventions.GetCollectionElementType(nonNullableType)))
            {
                yield return nestedType;
            }

            yield break;
        }

        if (SchemaTypeConventions.IsDictionaryType(nonNullableType))
        {
            foreach (var nestedType in GetNestedSchemaObjectTypes(nonNullableType.GetGenericArguments()[1]))
            {
                yield return nestedType;
            }

            yield break;
        }

        if (SchemaTypeConventions.IsSchemaObjectType(nonNullableType))
        {
            yield return nonNullableType;
        }
    }

    private static void Enqueue(Type type, ISet<Type> discoveredTypes, Queue<Type> queue)
    {
        if (discoveredTypes.Add(type))
        {
            queue.Enqueue(type);
        }
    }
}
