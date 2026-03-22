using System.Reflection;
using System.Text.Json.Serialization;
using FluentAssertions;
using MLVScan.Models.Dto;
using MLVScan.Tools.SchemaGen;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Tools;

public sealed class SchemaTypeConventionsTests
{
    private static readonly Assembly SchemaGenAssembly = typeof(SchemaArtifactsGenerator).Assembly;
    private static readonly Type SchemaTypeConventionsType =
        SchemaGenAssembly.GetType("MLVScan.Tools.SchemaGen.SchemaTypeConventions", throwOnError: true)!;
    private static readonly Type TypeDiscoveryType =
        SchemaGenAssembly.GetType("MLVScan.Tools.SchemaGen.TypeDiscovery", throwOnError: true)!;

    [Fact]
    public void GetStringUnion_ReturnsConfiguredUnionForMappedProperty()
    {
        var property = typeof(ScanResultDto).GetProperty(nameof(ScanResultDto.SchemaVersion))!;

        var unionSpec = InvokeStaticMethod("GetStringUnion", property);

        unionSpec.Should().NotBeNull();
        unionSpec!.GetType().GetProperty("Name")!.GetValue(unionSpec).Should().Be("SchemaVersion");
        unionSpec.GetType().GetProperty("IsConst")!.GetValue(unionSpec).Should().Be(true);
        ((IReadOnlyList<string>)unionSpec.GetType().GetProperty("Values")!.GetValue(unionSpec)!)
            .Should()
            .ContainSingle(MLVScanVersions.SchemaVersion);
    }

    [Fact]
    public void GetStringUnion_ForUnmappedProperty_ReturnsNull()
    {
        var property = typeof(ScanMetadataDto).GetProperty(nameof(ScanMetadataDto.CoreVersion))!;

        var unionSpec = InvokeStaticMethod("GetStringUnion", property);

        unionSpec.Should().BeNull();
    }

    [Fact]
    public void GetJsonPropertyName_PrefersExplicitNameAndFallsBackToCamelCase()
    {
        var explicitProperty = typeof(JsonPropertyNameTestModel).GetProperty(nameof(JsonPropertyNameTestModel.ExplicitName))!;
        var plainProperty = typeof(JsonPropertyNameTestModel).GetProperty(nameof(JsonPropertyNameTestModel.PlainName))!;

        InvokeStaticMethod("GetJsonPropertyName", explicitProperty).Should().Be("explicit_name");
        InvokeStaticMethod("GetJsonPropertyName", plainProperty).Should().Be("plainName");
    }

    [Fact]
    public void CollectionAndDictionaryHelpers_ClassifyTypesCorrectly()
    {
        InvokeStaticMethod("IsDictionaryType", typeof(Dictionary<string, string>)).Should().Be(true);
        InvokeStaticMethod("IsDictionaryType", typeof(List<string>)).Should().Be(false);
        InvokeStaticMethod("IsCollectionType", typeof(List<int>)).Should().Be(true);
        InvokeStaticMethod("IsCollectionType", typeof(int[])).Should().Be(true);
        InvokeStaticMethod("IsCollectionType", typeof(string)).Should().Be(false);
        InvokeStaticMethod("GetCollectionElementType", typeof(List<int>)).Should().Be(typeof(int));
        InvokeStaticMethod("GetCollectionElementType", typeof(string[])).Should().Be(typeof(string));
    }

    [Fact]
    public void IsSchemaObjectType_RejectsCollectionsAndStrings()
    {
        InvokeStaticMethod("IsSchemaObjectType", typeof(ScanMetadataDto)).Should().Be(true);
        InvokeStaticMethod("IsSchemaObjectType", typeof(List<ScanMetadataDto>)).Should().Be(false);
        InvokeStaticMethod("IsSchemaObjectType", typeof(Dictionary<string, ScanMetadataDto>)).Should().Be(false);
        InvokeStaticMethod("IsSchemaObjectType", typeof(string)).Should().Be(false);
    }

    [Fact]
    public void IsNullableProperty_DetectsReferenceAndValueNullability()
    {
        var nullabilityContext = new NullabilityInfoContext();
        var optionalReferenceProperty = typeof(ScanResultDto).GetProperty(nameof(ScanResultDto.CallChains))!;
        var optionalValueProperty = typeof(NullablePropertyTestModel).GetProperty(nameof(NullablePropertyTestModel.OptionalNumber))!;
        var requiredValueProperty = typeof(NullablePropertyTestModel).GetProperty(nameof(NullablePropertyTestModel.RequiredNumber))!;

        InvokeStaticMethod("IsNullableProperty", optionalReferenceProperty, nullabilityContext).Should().Be(true);
        InvokeStaticMethod("IsNullableProperty", optionalValueProperty, nullabilityContext).Should().Be(true);
        InvokeStaticMethod("IsNullableProperty", requiredValueProperty, nullabilityContext).Should().Be(false);
    }

    [Fact]
    public void CollectSchemaObjectTypes_IncludesRootAndNestedTypesWithoutDuplicates()
    {
        var objectTypes = ((IEnumerable<Type>)InvokeTypeDiscoveryMethod("CollectSchemaObjectTypes", typeof(ScanResultDto))!)
            .ToList();

        objectTypes.Should().NotBeEmpty();
        objectTypes[0].Should().Be(typeof(ScanResultDto));
        objectTypes.Should().Contain(typeof(ScanMetadataDto));
        objectTypes.Should().Contain(typeof(FindingDto));
        objectTypes.Should().Contain(typeof(DeveloperGuidanceDto));
        objectTypes.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void CollectStringUnions_DeduplicatesUnionSpecsByName()
    {
        var objectTypes = (IEnumerable<Type>)InvokeTypeDiscoveryMethod("CollectSchemaObjectTypes", typeof(ScanResultDto))!;
        var unionSpecs = ((IEnumerable<object>)InvokeTypeDiscoveryMethod("CollectStringUnions", objectTypes)!)
            .ToList();
        var unionNames = unionSpecs
            .Select(spec => (string)spec.GetType().GetProperty("Name")!.GetValue(spec)!)
            .ToList();

        unionNames.Should().Contain(["SchemaVersion", "ScanMode", "Severity", "ThreatMatchKind"]);
        unionNames.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void PropertyKey_UsesValueEqualityForDeclaringTypeAndPropertyName()
    {
        var propertyKeyType = SchemaGenAssembly.GetType("MLVScan.Tools.SchemaGen.PropertyKey", throwOnError: true)!;
        var left = CreatePropertyKeyInstance(propertyKeyType, typeof(ScanResultDto), nameof(ScanResultDto.SchemaVersion));
        var same = CreatePropertyKeyInstance(propertyKeyType, typeof(ScanResultDto), nameof(ScanResultDto.SchemaVersion));
        var different = CreatePropertyKeyInstance(propertyKeyType, typeof(ScanMetadataDto), nameof(ScanMetadataDto.Platform));

        left.Equals(same).Should().BeTrue();
        left.Equals(different).Should().BeFalse();
        left.GetHashCode().Should().Be(same.GetHashCode());
    }

    private static object? InvokeStaticMethod(string methodName, params object[] arguments)
    {
        var parameterTypes = arguments.Select(argument => argument.GetType()).ToArray();
        var method = SchemaTypeConventionsType.GetMethod(
            methodName,
            BindingFlags.Public | BindingFlags.Static,
            binder: null,
            types: parameterTypes,
            modifiers: null);

        method.Should().NotBeNull($"expected SchemaTypeConventions.{methodName} to exist");
        return method!.Invoke(null, arguments);
    }

    private static object? InvokeTypeDiscoveryMethod(string methodName, params object[] arguments)
    {
        var parameterTypes = arguments.Select(argument => argument.GetType()).ToArray();
        var method = TypeDiscoveryType.GetMethod(
            methodName,
            BindingFlags.Public | BindingFlags.Static,
            binder: null,
            types: parameterTypes,
            modifiers: null);

        method.Should().NotBeNull($"expected TypeDiscovery.{methodName} to exist");
        return method!.Invoke(null, arguments);
    }

    private static object CreatePropertyKeyInstance(Type propertyKeyType, Type declaringType, string propertyName)
    {
        var instance = Activator.CreateInstance(
            propertyKeyType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [declaringType, propertyName],
            culture: null);

        instance.Should().NotBeNull("expected PropertyKey constructor invocation to succeed");
        return instance!;
    }

    private sealed class JsonPropertyNameTestModel
    {
        [JsonPropertyName("explicit_name")]
        public string ExplicitName { get; set; } = string.Empty;

        public string PlainName { get; set; } = string.Empty;
    }

    private sealed class NullablePropertyTestModel
    {
        public int? OptionalNumber { get; set; }

        public int RequiredNumber { get; set; }
    }
}
