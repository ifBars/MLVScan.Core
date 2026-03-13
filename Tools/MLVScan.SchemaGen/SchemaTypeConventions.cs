using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Models.ThreatIntel;

namespace MLVScan.Tools.SchemaGen;

internal static class SchemaTypeConventions
{
    private static readonly IReadOnlyDictionary<PropertyKey, StringUnionSpec> StringUnionMappings =
        new Dictionary<PropertyKey, StringUnionSpec>
        {
            [new(typeof(ScanResultDto), nameof(ScanResultDto.SchemaVersion))] =
                StringUnionSpec.CreateConst("SchemaVersion", MLVScanVersions.SchemaVersion),
            [new(typeof(ScanMetadataDto), nameof(ScanMetadataDto.ScanMode))] =
                StringUnionSpec.CreateUnion("ScanMode", "summary", "detailed", "developer"),
            [new(typeof(ScanMetadataDto), nameof(ScanMetadataDto.Platform))] =
                StringUnionSpec.CreateUnion("ScanPlatform", "core", "wasm", "cli", "server", "desktop", "mcp"),
            [new(typeof(FindingDto), nameof(FindingDto.Severity))] = StringUnionSpec.CreateEnum<Severity>("Severity"),
            [new(typeof(CallChainDto), nameof(CallChainDto.Severity))] = StringUnionSpec.CreateEnum<Severity>("Severity"),
            [new(typeof(DataFlowChainDto), nameof(DataFlowChainDto.Severity))] = StringUnionSpec.CreateEnum<Severity>("Severity"),
            [new(typeof(CallChainNodeDto), nameof(CallChainNodeDto.NodeType))] =
                StringUnionSpec.CreateEnum<CallChainNodeType>("CallChainNodeType"),
            [new(typeof(DataFlowChainDto), nameof(DataFlowChainDto.Pattern))] =
                StringUnionSpec.CreateEnum<DataFlowPattern>("DataFlowPattern"),
            [new(typeof(DataFlowNodeDto), nameof(DataFlowNodeDto.NodeType))] =
                StringUnionSpec.CreateEnum<DataFlowNodeType>("DataFlowNodeType"),
            [new(typeof(ThreatFamilyDto), nameof(ThreatFamilyDto.MatchKind))] =
                StringUnionSpec.CreateEnum<ThreatMatchKind>("ThreatMatchKind")
        };

    public static IReadOnlyList<PropertyInfo> GetSchemaProperties(Type type)
    {
        return type.GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(static property => property.GetMethod != null && property.GetIndexParameters().Length == 0)
            .OrderBy(static property => property.MetadataToken)
            .ToList();
    }

    public static string GetJsonPropertyName(PropertyInfo property)
    {
        var explicitName = property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name;
        if (!string.IsNullOrWhiteSpace(explicitName))
        {
            return explicitName;
        }

        return JsonNamingPolicy.CamelCase.ConvertName(property.Name);
    }

    public static StringUnionSpec? GetStringUnion(PropertyInfo property)
    {
        if (property.DeclaringType == null)
        {
            return null;
        }

        StringUnionMappings.TryGetValue(new PropertyKey(property.DeclaringType, property.Name), out var unionSpec);
        return unionSpec;
    }

    public static string GetSchemaTypeName(Type type)
    {
        return type.Name.EndsWith("Dto", StringComparison.Ordinal)
            ? type.Name[..^3]
            : type.Name;
    }

    public static bool IsDictionaryType(Type type)
    {
        if (!type.IsGenericType)
        {
            return false;
        }

        var genericDefinition = type.GetGenericTypeDefinition();
        return genericDefinition == typeof(Dictionary<,>) || genericDefinition == typeof(IDictionary<,>);
    }

    public static bool IsCollectionType(Type type)
    {
        if (type == typeof(string))
        {
            return false;
        }

        if (type.IsArray)
        {
            return true;
        }

        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>);
    }

    public static Type GetCollectionElementType(Type type)
    {
        return type.IsArray ? type.GetElementType()! : type.GetGenericArguments()[0];
    }

    public static bool IsSchemaObjectType(Type type)
    {
        return type.IsClass &&
               type != typeof(string) &&
               !IsCollectionType(type) &&
               !IsDictionaryType(type);
    }

    public static bool IsNullableProperty(PropertyInfo property, NullabilityInfoContext nullabilityContext)
    {
        var propertyType = property.PropertyType;
        if (Nullable.GetUnderlyingType(propertyType) != null)
        {
            return true;
        }

        if (!propertyType.IsValueType)
        {
            return nullabilityContext.Create(property).WriteState == NullabilityState.Nullable;
        }

        return false;
    }
}
