using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DllImportScannerTests
{
    [Fact]
    public void Constructor_WithNullRules_ThrowsArgumentNullException()
    {
        var act = () => new DllImportScanner(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("rules");
    }

    [Fact]
    public void Constructor_WithNullCallGraphBuilder_DoesNotThrow()
    {
        var rules = new List<IScanRule> { new DllImportRule() };

        var act = () => new DllImportScanner(rules, null);

        act.Should().NotThrow();
    }

    [Fact]
    public void ScanForDllImports_WithNoPInvokeMethods_ReturnsEmpty()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        // Add a regular method (not P/Invoke)
        var type = new TypeDefinition("Test", "TestType", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);
        var method = new MethodDefinition("RegularMethod", MethodAttributes.Public, assembly.MainModule.TypeSystem.Void);
        type.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule);

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForDllImports_WithNonSuspiciousPInvoke_ReturnsEmpty()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        // Create a P/Invoke method but with PInvokeInfo = null (edge case)
        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);
        var method = new MethodDefinition("SomeMethod",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.IntPtr);
        // Deliberately don't set PInvokeInfo
        type.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule);

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForDllImports_WithSuspiciousPInvoke_ReturnsFindings()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        // Create a P/Invoke method importing from kernel32.dll
        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("CreateProcess",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.IntPtr);

        var moduleRef = new ModuleReference("kernel32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "CreateProcess", moduleRef);
        type.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule).ToList();

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical); // CreateProcess is high-risk
        findings[0].Description.Should().Contain("CreateProcess");
    }

    [Fact]
    public void ScanForDllImports_WithCallGraphBuilder_RegistersButReturnsEmpty()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var callGraphBuilder = new CallGraphBuilder(rules, snippetBuilder);
        var scanner = new DllImportScanner(rules, callGraphBuilder);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        // Create a P/Invoke method
        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("VirtualAlloc",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.IntPtr);

        var moduleRef = new ModuleReference("kernel32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "VirtualAlloc", moduleRef);
        type.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule).ToList();

        // When call graph builder is present, direct findings are not returned
        findings.Should().BeEmpty();

        // But the declaration should be registered in the call graph builder
        callGraphBuilder.SuspiciousDeclarationCount.Should().Be(1);
    }

    [Fact]
    public void ScanForDllImports_WithMultiplePInvokes_ReturnsMultipleFindings()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var moduleRef = new ModuleReference("kernel32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);

        // Add multiple P/Invoke methods
        for (int i = 0; i < 3; i++)
        {
            var method = new MethodDefinition($"VirtualAlloc{i}",
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
                assembly.MainModule.TypeSystem.IntPtr);
            method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "VirtualAlloc", moduleRef);
            type.Methods.Add(method);
        }

        var findings = scanner.ScanForDllImports(assembly.MainModule).ToList();

        findings.Should().HaveCount(3);
    }

    [Fact]
    public void ScanForDllImports_WithMethodsInNestedTypes_FindsPInvokes()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        // Create parent type
        var parentType = new TypeDefinition("Test", "ParentType", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(parentType);

        // Create nested type
        var nestedType = new TypeDefinition("Test", "NativeMethods",
            TypeAttributes.NestedPublic | TypeAttributes.Class);
        parentType.NestedTypes.Add(nestedType);

        var moduleRef = new ModuleReference("kernel32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);

        var method = new MethodDefinition("LoadLibrary",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.IntPtr);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "LoadLibrary", moduleRef);
        nestedType.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule).ToList();

        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("LoadLibrary");
    }

    [Fact]
    public void ScanForDllImports_HandlesMethodAnalysisExceptions_ContinuesScanning()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        // Should not throw even if methods have issues
        var act = () => scanner.ScanForDllImports(assembly.MainModule).ToList();

        act.Should().NotThrow();
    }

    [Fact]
    public void ScanForDllImports_SetsRuleMetadata_OnFindings()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("VirtualAlloc",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.IntPtr);

        var moduleRef = new ModuleReference("kernel32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "VirtualAlloc", moduleRef);
        type.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule).ToList();

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("DllImportRule");
        findings[0].DeveloperGuidance.Should().NotBeNull();
    }

    [Fact]
    public void ScanForDllImports_GeneratesCodeSnippet_WithDllImportDeclaration()
    {
        var rules = new List<IScanRule> { new DllImportRule() };
        var scanner = new DllImportScanner(rules);

        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();

        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("MessageBox",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.Int32);

        // Add some parameters to test snippet generation
        method.Parameters.Add(new ParameterDefinition("hwnd", ParameterAttributes.None, assembly.MainModule.TypeSystem.IntPtr));
        method.Parameters.Add(new ParameterDefinition("text", ParameterAttributes.None, assembly.MainModule.TypeSystem.String));

        var moduleRef = new ModuleReference("user32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "MessageBoxA", moduleRef);
        type.Methods.Add(method);

        var findings = scanner.ScanForDllImports(assembly.MainModule).ToList();

        findings.Should().HaveCount(1);
        findings[0].CodeSnippet.Should().Contain("[DllImport(");
        findings[0].CodeSnippet.Should().Contain("user32.dll");
        findings[0].CodeSnippet.Should().Contain("MessageBoxA");
    }
}
