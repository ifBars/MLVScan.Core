using Mono.Cecil;

namespace MLVScan.Core.Tests.TestUtilities;

/// <summary>
/// Helper for creating MethodReference objects for rule testing.
/// </summary>
public static class MethodReferenceFactory
{
    /// <summary>
    /// Creates a MethodReference with the specified declaring type and method name.
    /// Useful for testing IScanRule.IsSuspicious() without building full assemblies.
    /// </summary>
    public static MethodReference Create(string declaringTypeFullName, string methodName)
    {
        // Create a minimal module for type references
        var assemblyName = new AssemblyNameDefinition("TestAssembly", new Version(1, 0));
        var assembly = AssemblyDefinition.CreateAssembly(assemblyName, "TestModule", ModuleKind.Dll);
        var module = assembly.MainModule;

        var lastDot = declaringTypeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? declaringTypeFullName[..lastDot] : "";
        var name = lastDot > 0 ? declaringTypeFullName[(lastDot + 1)..] : declaringTypeFullName;

        var typeRef = new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
        var methodRef = new MethodReference(methodName, module.TypeSystem.Void, typeRef);

        return methodRef;
    }

    /// <summary>
    /// Creates a MethodReference with null DeclaringType for edge case testing.
    /// </summary>
    public static MethodReference CreateWithNullType(string methodName)
    {
        var assemblyName = new AssemblyNameDefinition("TestAssembly", new Version(1, 0));
        var assembly = AssemblyDefinition.CreateAssembly(assemblyName, "TestModule", ModuleKind.Dll);
        var module = assembly.MainModule;

        // Create method ref without declaring type
        var methodRef = new MethodReference(methodName, module.TypeSystem.Void);
        return methodRef;
    }
}
