using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using System.Reflection;

namespace MLVScan.Tools.SchemaGen;

internal sealed class JsonSchemaBuilder
{
    private readonly IReadOnlyList<Type> _objectTypes;
    private readonly NullabilityInfoContext _nullabilityContext = new();

    public JsonSchemaBuilder(IReadOnlyList<Type> objectTypes)
    {
        _objectTypes = objectTypes;
    }

    public string Build()
    {
        var rootType = _objectTypes[0];
        var definitions = BuildDefinitions();
        var rootSchema = BuildObjectSchema(rootType);

        rootSchema["$schema"] = "https://json-schema.org/draft/2020-12/schema";
        rootSchema["$id"] = $"https://mlvscan.com/schemas/scan-result/{MLVScanVersions.SchemaVersion}/schema.json";
        rootSchema["title"] = "MLVScan Scan Result";
        rootSchema["description"] =
            $"Generated from MLVScan.Core DTOs. Schema version {MLVScanVersions.SchemaVersion}.";
        rootSchema["$defs"] = definitions;

        return rootSchema.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver()
        }) + "\n";
    }

    private JsonObject BuildDefinitions()
    {
        var definitions = new JsonObject();

        foreach (var stringUnion in TypeDiscovery.CollectStringUnions(_objectTypes))
        {
            definitions[stringUnion.Name] = BuildStringUnionSchema(stringUnion);
        }

        foreach (var type in _objectTypes.Skip(1))
        {
            definitions[SchemaTypeConventions.GetSchemaTypeName(type)] = BuildObjectSchema(type);
        }

        return definitions;
    }

    private JsonObject BuildObjectSchema(Type type)
    {
        var properties = new JsonObject();
        var required = new JsonArray();

        foreach (var property in SchemaTypeConventions.GetSchemaProperties(type))
        {
            properties[SchemaTypeConventions.GetJsonPropertyName(property)] = BuildPropertySchema(property);

            if (!SchemaTypeConventions.IsNullableProperty(property, _nullabilityContext))
            {
                required.Add(SchemaTypeConventions.GetJsonPropertyName(property));
            }
        }

        var schema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = properties
        };

        if (required.Count > 0)
        {
            schema["required"] = required;
        }

        return schema;
    }

    private JsonNode BuildPropertySchema(PropertyInfo property)
    {
        var baseSchema = BuildNonNullableTypeSchema(property.PropertyType, property);
        return SchemaTypeConventions.IsNullableProperty(property, _nullabilityContext)
            ? WrapNullable(baseSchema)
            : baseSchema;
    }

    private JsonNode BuildNonNullableTypeSchema(Type type, PropertyInfo? property = null)
    {
        var nonNullableType = Nullable.GetUnderlyingType(type) ?? type;

        if (property != null && SchemaTypeConventions.GetStringUnion(property) is { } stringUnion)
        {
            return new JsonObject
            {
                ["$ref"] = $"#/$defs/{stringUnion.Name}"
            };
        }

        if (nonNullableType == typeof(string))
        {
            return new JsonObject { ["type"] = "string" };
        }

        if (nonNullableType == typeof(bool))
        {
            return new JsonObject { ["type"] = "boolean" };
        }

        if (nonNullableType == typeof(int) || nonNullableType == typeof(long))
        {
            return new JsonObject { ["type"] = "integer" };
        }

        if (nonNullableType == typeof(float) || nonNullableType == typeof(double) || nonNullableType == typeof(decimal))
        {
            return new JsonObject { ["type"] = "number" };
        }

        if (SchemaTypeConventions.IsCollectionType(nonNullableType))
        {
            return new JsonObject
            {
                ["type"] = "array",
                ["items"] = BuildNonNullableTypeSchema(SchemaTypeConventions.GetCollectionElementType(nonNullableType))
            };
        }

        if (SchemaTypeConventions.IsDictionaryType(nonNullableType))
        {
            return new JsonObject
            {
                ["type"] = "object",
                ["additionalProperties"] = BuildNonNullableTypeSchema(nonNullableType.GetGenericArguments()[1])
            };
        }

        if (SchemaTypeConventions.IsSchemaObjectType(nonNullableType))
        {
            return new JsonObject
            {
                ["$ref"] = $"#/$defs/{SchemaTypeConventions.GetSchemaTypeName(nonNullableType)}"
            };
        }

        throw new NotSupportedException($"Schema generation does not support CLR type '{nonNullableType.FullName}'.");
    }

    private static JsonObject BuildStringUnionSchema(StringUnionSpec stringUnion)
    {
        var schema = new JsonObject
        {
            ["type"] = "string"
        };

        if (stringUnion.IsConst)
        {
            schema["const"] = stringUnion.Values[0];
            return schema;
        }

        var enumValues = new JsonArray();
        foreach (var value in stringUnion.Values)
        {
            enumValues.Add(value);
        }

        schema["enum"] = enumValues;
        return schema;
    }

    private static JsonObject WrapNullable(JsonNode baseSchema)
    {
        return new JsonObject
        {
            ["anyOf"] = new JsonArray
            {
                baseSchema,
                new JsonObject { ["type"] = "null" }
            }
        };
    }
}
