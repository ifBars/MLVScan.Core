using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Services.Helpers;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.Helpers;

public class TypeCollectionHelperTests
{
    [Fact]
    public void GetAllTypes_WithTopLevelAndNestedTypes_ReturnsFlattenedCollection()
    {
        var builder = TestAssemblyBuilder.Create("TypeTreeTest");
        var parentType = builder.AddType("Test.Parent").TypeDefinition;

        var childType = new TypeDefinition("Test", "Child", TypeAttributes.NestedPublic | TypeAttributes.Class, builder.Module.TypeSystem.Object);
        var grandChildType = new TypeDefinition("Test", "GrandChild", TypeAttributes.NestedPublic | TypeAttributes.Class, builder.Module.TypeSystem.Object);
        childType.NestedTypes.Add(grandChildType);
        parentType.NestedTypes.Add(childType);

        var assembly = builder.Build();

        var allTypes = TypeCollectionHelper.GetAllTypes(assembly.MainModule).ToList();

        allTypes.Should().Contain(parentType);
        allTypes.Should().Contain(childType);
        allTypes.Should().Contain(grandChildType);
    }

    [Fact]
    public void GetAllTypes_WithEmptyModule_ReturnsEmptyCollection()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("EmptyModule", new Version(1, 0, 0, 0)),
            "EmptyModule",
            ModuleKind.Dll);
        assembly.MainModule.Types.Clear();

        var allTypes = TypeCollectionHelper.GetAllTypes(assembly.MainModule);

        allTypes.Should().BeEmpty();
    }
}
