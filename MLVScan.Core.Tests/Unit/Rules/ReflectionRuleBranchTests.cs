using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ReflectionRuleBranchTests
{
    private readonly ReflectionRule _rule = new();

    [Fact]
    public void AnalyzeInstructions_WithGetMethodAndInvokeChain_ReturnsExecutionChainFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.Type", "GetMethod")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateMethodReference(method.Module, "System.Reflection.MethodInfo", "Invoke", hasThis: true)));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle(finding => finding.Description.Contains("reflection execution chain"));
    }

    [Fact]
    public void AnalyzeInstructions_WithRuntimeTypeEnumerationPattern_ReturnsFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.AppDomain", "GetAssemblies")));
        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.Linq.Enumerable", "SelectMany")));
        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.Linq.Enumerable", "FirstOrDefault")));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle(finding => finding.Description.Contains("runtime type scanning"));
    }

    [Fact]
    public void AnalyzeInstructions_WithAssemblyMetadataAttributeAccessor_ReturnsFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();
        var attributeAccessor = CreateMethodReference(
            method.Module,
            "System.Reflection.CustomAttributeExtensions",
            "GetCustomAttributes",
            parameterTypeFullNames: ["System.Reflection.AssemblyMetadataAttribute"]);

        il.Append(Instruction.Create(OpCodes.Call, attributeAccessor));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle(finding => finding.Description.Contains("AssemblyMetadataAttribute"));
    }

    [Fact]
    public void AnalyzeInstructions_WithNonMetadataAttributeAccessor_DoesNotReturnMetadataFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();
        var attributeAccessor = CreateMethodReference(
            method.Module,
            "System.Reflection.CustomAttributeExtensions",
            "GetCustomAttributes",
            parameterTypeFullNames: ["System.ObsoleteAttribute"]);

        il.Append(Instruction.Create(OpCodes.Call, attributeAccessor));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_WithSequentialIntegerLoadsBeforeDynamicInvoke_ReturnsFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)7));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateMethodReference(method.Module, "System.Reflection.MethodInfo", "Invoke", hasThis: true)));
        il.Append(Instruction.Create(OpCodes.Ret));

        var dynamicInvoke = CreateMethodReference(
            method.Module,
            "System.Reflection.MethodInfo",
            "Invoke",
            hasThis: true,
            scopeName: "ThirdParty.Reflection");

        var findings = _rule.AnalyzeContextualPattern(dynamicInvoke, method.Body.Instructions, 3, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("3 sequential integer constants");
    }

    [Fact]
    public void AnalyzeContextualPattern_WithSystemAssemblyScope_ReturnsNoFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_2));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateMethodReference(method.Module, "System.Reflection.MethodInfo", "Invoke", hasThis: true)));
        il.Append(Instruction.Create(OpCodes.Ret));

        var systemScopedInvoke = CreateMethodReference(
            method.Module,
            "System.Reflection.MethodInfo",
            "Invoke",
            hasThis: true,
            scopeName: "System.Runtime");

        var findings = _rule.AnalyzeContextualPattern(systemScopedInvoke, method.Body.Instructions, 3, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void IsLdcI4Instruction_RecognizesAllSupportedOpCodes()
    {
        var method = typeof(ReflectionRule).GetMethod(
            "IsLdcI4Instruction",
            global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Static)!;
        var supportedInstructions = new[]
        {
            Instruction.Create(OpCodes.Ldc_I4, 42),
            Instruction.Create(OpCodes.Ldc_I4_0),
            Instruction.Create(OpCodes.Ldc_I4_1),
            Instruction.Create(OpCodes.Ldc_I4_2),
            Instruction.Create(OpCodes.Ldc_I4_3),
            Instruction.Create(OpCodes.Ldc_I4_4),
            Instruction.Create(OpCodes.Ldc_I4_5),
            Instruction.Create(OpCodes.Ldc_I4_6),
            Instruction.Create(OpCodes.Ldc_I4_7),
            Instruction.Create(OpCodes.Ldc_I4_8),
            Instruction.Create(OpCodes.Ldc_I4_M1),
            Instruction.Create(OpCodes.Ldc_I4_S, (sbyte)9)
        };

        foreach (var instruction in supportedInstructions)
        {
            ((bool)method.Invoke(null, [instruction])!).Should().BeTrue();
        }

        ((bool)method.Invoke(null, [Instruction.Create(OpCodes.Ldc_R4, 1f)])!).Should().BeFalse();
    }

    [Fact]
    public void IsLocalVariableLoad_RecognizesAllSupportedOpCodes()
    {
        var method = typeof(ReflectionRule).GetMethod(
            "IsLocalVariableLoad",
            global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Static)!;
        var variable = new VariableDefinition(CreateTypeReference(CreateMethod().Module, "System.String"));
        var supportedInstructions = new[]
        {
            Instruction.Create(OpCodes.Ldloc, variable),
            Instruction.Create(OpCodes.Ldloc_0),
            Instruction.Create(OpCodes.Ldloc_1),
            Instruction.Create(OpCodes.Ldloc_2),
            Instruction.Create(OpCodes.Ldloc_3),
            Instruction.Create(OpCodes.Ldloc_S, variable)
        };

        foreach (var instruction in supportedInstructions)
        {
            ((bool)method.Invoke(null, [instruction])!).Should().BeTrue();
        }

        ((bool)method.Invoke(null, [Instruction.Create(OpCodes.Stloc_0)])!).Should().BeFalse();
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("System.Runtime", true)]
    [InlineData("Microsoft.Extensions.Logging", true)]
    [InlineData("System.Core.dll", true)]
    [InlineData("Custom.Plugin", false)]
    public void IsSystemAssembly_ReturnsExpected(string? assemblyName, bool expected)
    {
        var method = typeof(ReflectionRule).GetMethod(
            "IsSystemAssembly",
            global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Static)!;

        ((bool)method.Invoke(null, [assemblyName!])!).Should().Be(expected);
    }

    [Theory]
    [InlineData("System.Reflection.PropertyInfo", true)]
    [InlineData("System.Reflection.MethodInfo", true)]
    [InlineData("System.Reflection.FieldInfo", false)]
    public void IsReflectionInvocationType_ReturnsExpected(string typeName, bool expected)
    {
        var method = typeof(ReflectionRule).GetMethod(
            "IsReflectionInvocationType",
            global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Static)!;

        ((bool)method.Invoke(null, [typeName])!).Should().Be(expected);
    }

    private static MethodDefinition CreateMethod()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ReflectionRuleBranchTests", new Version(1, 0, 0, 0)),
            "ReflectionRuleBranchTests",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition(
            "Test",
            "ReflectionType",
            Mono.Cecil.TypeAttributes.Public | Mono.Cecil.TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition(
            "Run",
            Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static,
            module.TypeSystem.Void);
        method.Body = new Mono.Cecil.Cil.MethodBody(method);
        type.Methods.Add(method);
        return method;
    }

    private static MethodReference CreateMethodReference(
        ModuleDefinition module,
        string declaringTypeFullName,
        string methodName,
        bool hasThis = false,
        string? scopeName = null,
        params string[] parameterTypeFullNames)
    {
        var declaringType = CreateTypeReference(module, declaringTypeFullName, scopeName);
        var methodReference = new MethodReference(methodName, module.TypeSystem.Void, declaringType)
        {
            HasThis = hasThis
        };

        foreach (var parameterTypeFullName in parameterTypeFullNames)
        {
            methodReference.Parameters.Add(new ParameterDefinition(CreateTypeReference(module, parameterTypeFullName)));
        }

        return methodReference;
    }

    private static TypeReference CreateTypeReference(ModuleDefinition module, string fullName, string? scopeName = null)
    {
        var lastDot = fullName.LastIndexOf('.');
        var @namespace = lastDot > 0 ? fullName[..lastDot] : string.Empty;
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
        var scope = scopeName == null ? module.TypeSystem.CoreLibrary : new AssemblyNameReference(scopeName, new Version(1, 0, 0, 0));

        return new TypeReference(@namespace, name, module, scope);
    }
}
