using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

/// <summary>
/// Tests to ensure MLVScan.Core detects MLVBypass-style reflection attacks
/// while NOT falsely flagging legitimate reflection usage in mods.
/// </summary>
public class ReflectionBypassDetectionTests
{
    /// <summary>
    /// Test 1: MLVBypass pattern SHOULD be detected
    /// Uses Type.GetTypeFromProgID + Activator.CreateInstance + InvokeMember
    /// </summary>
    [Fact]
    public void Scan_MLVBypassPattern_ShouldDetect()
    {
        // Build an assembly that mimics MLVBypass's reflective shell execution
        var builder = TestAssemblyBuilder.Create("MLVBypass");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("BypassPayload.ReflectiveShellMod")
                .AddMethod("OnInitializeMelon")
                    // Type shellType = Type.GetTypeFromProgID("Shell.Application");
                    .EmitString("Shell.Application")
                    .EmitCall("System.Type", "GetTypeFromProgID", GetTypeRef(module, "System.Type"))
                    .AddLocal("System.Type", out int shellTypeIdx)
                    .EmitStloc(shellTypeIdx)
                    
                    // object shell = Activator.CreateInstance(shellType);
                    .EmitLdloc(shellTypeIdx)
                    .EmitCall("System.Activator", "CreateInstance", module.TypeSystem.Object)
                    .AddLocal("System.Object", out int shellObjIdx)
                    .EmitStloc(shellObjIdx)
                    
                    // shellType.InvokeMember("ShellExecute", ...)
                    .EmitLdloc(shellTypeIdx)
                    .EmitString("ShellExecute")
                    .EmitInt(256) // BindingFlags.InvokeMethod
                    .EmitCall("System.Type", "InvokeMember")
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "MLVBypass.dll").ToList();

        // Should detect the malicious pattern
        findings.Should().NotBeEmpty("MLVBypass pattern should be detected");
        findings.Should().Contain(f => 
            f.Description.Contains("reflection", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("Shell", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("InvokeMember", StringComparison.OrdinalIgnoreCase),
            "Should detect reflection-based shell execution");
        
        // Should have high or critical severity
        findings.Should().Contain(f => f.Severity >= Severity.High,
            "Shell execution via reflection should be high severity");
    }

    /// <summary>
    /// Test 2: Behind-Bars style legitimate reflection SHOULD NOT trigger
    /// Uses GetMethod/GetProperty for Il2Cpp interop without malicious patterns
    /// </summary>
    [Fact]
    public void Scan_LegitimateReflectionForIl2CppInterop_ShouldNotDetect()
    {
        // Build an assembly that uses reflection like Behind-Bars does
        var builder = TestAssemblyBuilder.Create("Behind-Bars");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("Behind_Bars.Systems.Jail.InventoryProcessor")
                .AddMethod("GetAllInventorySlots")
                    // var getAllSlotsMethod = inventory.GetType().GetMethod("GetAllInventorySlots");
                    .AddLocal("System.Object", out int inventoryIdx)
                    .EmitLdloc(inventoryIdx)
                    .EmitCallVirt("System.Object", "GetType", GetTypeRef(module, "System.Type"))
                    .EmitString("GetAllInventorySlots")
                    .EmitCallVirt("System.Type", "GetMethod", GetMethodInfoRef(module))
                    .AddLocal("System.Reflection.MethodInfo", out int methodIdx)
                    .EmitStloc(methodIdx)
                    
                    // var allSlots = getAllSlotsMethod.Invoke(inventory, null);
                    .EmitLdloc(methodIdx)
                    .EmitLdloc(inventoryIdx)
                    .EmitCall("System.Reflection.MethodInfo", "Invoke", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "Behind-Bars.dll").ToList();

        // Should NOT detect this as malicious (no companion signals)
        findings.Should().BeEmpty("Legitimate Il2Cpp reflection should not be flagged");
    }

    /// <summary>
    /// Test 3: Reflection with GetProperty (like Behind-Bars uses extensively) SHOULD NOT trigger
    /// </summary>
    [Fact]
    public void Scan_ReflectionGetProperty_ShouldNotDetect()
    {
        var builder = TestAssemblyBuilder.Create("BehindBars");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("InventoryChecker")
                .AddMethod("CheckItem")
                    // var itemInstanceProperty = slot.GetType().GetProperty("ItemInstance");
                    .AddLocal("System.Object", out int slotIdx)
                    .EmitLdloc(slotIdx)
                    .EmitCallVirt("System.Object", "GetType", GetTypeRef(module, "System.Type"))
                    .EmitString("ItemInstance")
                    .EmitCallVirt("System.Type", "GetProperty", GetPropertyInfoRef(module))
                    .AddLocal("System.Reflection.PropertyInfo", out int propIdx)
                    .EmitStloc(propIdx)
                    
                    // var itemInstance = itemInstanceProperty.GetValue(slot);
                    .EmitLdloc(propIdx)
                    .EmitLdloc(slotIdx)
                    .EmitCallVirt("System.Reflection.PropertyInfo", "GetValue", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "BehindBars.dll").ToList();

        findings.Should().BeEmpty("GetProperty reflection for Il2Cpp interop should not be flagged");
    }

    /// <summary>
    /// Test 4: Reflection invoke WITHOUT malicious context SHOULD NOT trigger
    /// Tests that ReflectionRule.RequiresCompanionFinding works correctly
    /// </summary>
    [Fact]
    public void Scan_ReflectionInvokeWithoutMaliciousContext_ShouldNotDetect()
    {
        var builder = TestAssemblyBuilder.Create("LegitMod");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("ConfigLoader")
                .AddMethod("LoadSettings")
                    // methodInfo.Invoke(target, args) - legitimate plugin pattern
                    .AddLocal("System.Reflection.MethodInfo", out int methodIdx)
                    .AddLocal("System.Object", out int targetIdx)
                    
                    .EmitLdloc(methodIdx)
                    .EmitLdloc(targetIdx)
                    .EmitCall("System.Reflection.MethodInfo", "Invoke", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "LegitMod.dll").ToList();

        // Should not trigger because there are no companion malicious signals
        findings.Should().BeEmpty("MethodInfo.Invoke without malicious context should not trigger");
    }

    /// <summary>
    /// Test 5: Reflection WITH malicious strings SHOULD trigger
    /// Combines reflection with suspicious method names or patterns
    /// </summary>
    [Fact]
    public void Scan_ReflectionWithSuspiciousStrings_ShouldDetect()
    {
        var builder = TestAssemblyBuilder.Create("SuspiciousMod");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("ShellLoader")
                .AddMethod("ExecuteCommand")
                    // Has "cmd.exe" string - malicious pattern
                    .EmitString("cmd.exe")
                    .AddLocal("System.String", out int cmdIdx)
                    .EmitStloc(cmdIdx)
                    
                    // Also uses reflection invoke
                    .AddLocal("System.Reflection.MethodInfo", out int methodIdx)
                    .AddLocal("System.Object", out int targetIdx)
                    .EmitLdloc(methodIdx)
                    .EmitLdloc(targetIdx)
                    .EmitCall("System.Reflection.MethodInfo", "Invoke", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "SuspiciousMod.dll").ToList();

        // Should detect because of cmd.exe + reflection combination
        findings.Should().NotBeEmpty("Reflection with cmd.exe should be flagged");
    }

    /// <summary>
    /// Test 6: GetTypeFromProgID with Shell.Application SHOULD trigger
    /// </summary>
    [Fact]
    public void Scan_GetTypeFromProgIDWithShellApplication_ShouldDetect()
    {
        var builder = TestAssemblyBuilder.Create("ShellMod");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("ShellAccess")
                .AddMethod("GetShellType")
                    .EmitString("Shell.Application")
                    .EmitCall("System.Type", "GetTypeFromProgID", GetTypeRef(module, "System.Type"))
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "ShellMod.dll").ToList();

        // Should detect Shell.Application COM access
        findings.Should().NotBeEmpty("Shell.Application COM access should be flagged");
        findings.Should().Contain(f => 
            f.Description.Contains("Shell", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
            f.Description.Contains("reflection", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Test 7: Activator.CreateInstance without suspicious context SHOULD NOT trigger
    /// </summary>
    [Fact]
    public void Scan_ActivatorCreateInstanceNormal_ShouldNotDetect()
    {
        var builder = TestAssemblyBuilder.Create("FactoryMod");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("ObjectFactory")
                .AddMethod("CreateObject")
                    // Activator.CreateInstance(someType) - legitimate use
                    .AddLocal("System.Type", out int typeIdx)
                    .EmitLdloc(typeIdx)
                    .EmitCall("System.Activator", "CreateInstance", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "FactoryMod.dll").ToList();

        // Should NOT trigger - legitimate object creation
        findings.Should().BeEmpty("Normal Activator.CreateInstance should not be flagged");
    }

    /// <summary>
    /// Test 8: Reflection combined with Base64 SHOULD trigger
    /// Tests multi-signal detection
    /// </summary>
    [Fact]
    public void Scan_ReflectionWithBase64_ShouldDetect()
    {
        var builder = TestAssemblyBuilder.Create("EncodedMod");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("DataLoader")
                .AddMethod("LoadEncoded")
                    // Base64 decode
                    .EmitString("U2hlbGxFeGVjdXRl") // "ShellExecute" in base64
                    .EmitCall("System.Convert", "FromBase64String", new ArrayType(module.TypeSystem.Byte))
                    
                    // Reflection invoke
                    .AddLocal("System.Reflection.MethodInfo", out int methodIdx)
                    .AddLocal("System.Object", out int targetIdx)
                    .EmitLdloc(methodIdx)
                    .EmitLdloc(targetIdx)
                    .EmitCall("System.Reflection.MethodInfo", "Invoke", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "EncodedMod.dll").ToList();

        // Should detect Base64 + reflection combination
        findings.Should().NotBeEmpty("Base64 + reflection should be flagged as multi-signal pattern");
    }

    /// <summary>
    /// Test 9: GetField reflection (like Behind-Bars uses) SHOULD NOT trigger
    /// </summary>
    [Fact]
    public void Scan_GetFieldReflection_ShouldNotDetect()
    {
        var builder = TestAssemblyBuilder.Create("FieldMod");
        var module = builder.Module;
        
        var assembly = builder
            .AddType("FieldAccessor")
                .AddMethod("ReadField")
                    // var field = type.GetField("legalStatus");
                    .AddLocal("System.Type", out int typeIdx)
                    .EmitLdloc(typeIdx)
                    .EmitString("legalStatus")
                    .EmitCallVirt("System.Type", "GetField", GetFieldInfoRef(module))
                    .AddLocal("System.Reflection.FieldInfo", out int fieldIdx)
                    .EmitStloc(fieldIdx)
                    
                    // var value = field.GetValue(obj);
                    .EmitLdloc(fieldIdx)
                    .AddLocal("System.Object", out int objIdx)
                    .EmitLdloc(objIdx)
                    .EmitCallVirt("System.Reflection.FieldInfo", "GetValue", module.TypeSystem.Object)
                .EndMethod()
            .EndType()
            .Build();

        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var findings = scanner.Scan(stream, "FieldMod.dll").ToList();

        findings.Should().BeEmpty("GetField reflection for Il2Cpp should not be flagged");
    }

    // Helper methods to create type references
    private static TypeReference GetTypeRef(ModuleDefinition module, string fullName)
    {
        return fullName switch
        {
            "System.Type" => new TypeReference("System", "Type", module, module.TypeSystem.CoreLibrary),
            _ => module.TypeSystem.Object
        };
    }

    private static TypeReference GetMethodInfoRef(ModuleDefinition module)
    {
        return new TypeReference("System.Reflection", "MethodInfo", module, module.TypeSystem.CoreLibrary);
    }

    private static TypeReference GetPropertyInfoRef(ModuleDefinition module)
    {
        return new TypeReference("System.Reflection", "PropertyInfo", module, module.TypeSystem.CoreLibrary);
    }

    private static TypeReference GetFieldInfoRef(ModuleDefinition module)
    {
        return new TypeReference("System.Reflection", "FieldInfo", module, module.TypeSystem.CoreLibrary);
    }
}
