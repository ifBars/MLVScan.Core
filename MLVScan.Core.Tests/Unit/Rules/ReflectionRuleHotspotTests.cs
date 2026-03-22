using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public sealed class ReflectionRuleHotspotTests
{
    private readonly ReflectionRule _rule = new();

    [Fact]
    public void AnalyzeInstructions_WithMoreThanThreeReflectionLocals_TruncatesDescription()
    {
        var method = CreateMethodWithLocals(
            "System.Reflection.MethodInfo",
            "System.Reflection.MethodBase",
            "System.Reflection.ConstructorInfo",
            "System.Reflection.PropertyInfo",
            "System.Reflection.MethodInfo");
        var signals = new MethodSignals();
        signals.MarkRuleTriggered("OtherRule");

        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, signals).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("and 2 more");
    }

    [Fact]
    public void AnalyzeInstructions_WithCurrentDomainPattern_ReturnsTypeEnumerationFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.AppDomain", "get_CurrentDomain")));
        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.Linq.Enumerable", "SelectMany")));
        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.Linq.Enumerable", "FirstOrDefault")));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle(f => f.Description.Contains("runtime type scanning"));
    }

    [Fact]
    public void AnalyzeInstructions_WithGenericAssemblyMetadataAccessor_ReturnsMetadataFinding()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();
        var genericAttributeAccessor = CreateGenericAttributeMethodReference(method.Module);

        il.Append(Instruction.Create(OpCodes.Call, genericAttributeAccessor));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle(f => f.Description.Contains("AssemblyMetadataAttribute"));
    }

    [Fact]
    public void AnalyzeInstructions_WithInvokeBeforeGetMethod_DoesNotReportExecutionChain()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Callvirt, CreateMethodReference(method.Module, "System.Reflection.MethodInfo", "Invoke", hasThis: true)));
        il.Append(Instruction.Create(OpCodes.Call, CreateMethodReference(method.Module, "System.Type", "GetMethod")));
        il.Append(Instruction.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Theory]
    [InlineData("System.Activator", "CreateInstance")]
    [InlineData("Custom.DelegateProxy", "DynamicInvoke")]
    public void AnalyzeContextualPattern_WithDynamicCallsAndSequentialIntegers_ReturnsFinding(string typeName, string methodName)
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Ldc_I4_2));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateMethodReference(method.Module, typeName, methodName, hasThis: methodName == "DynamicInvoke")));
        il.Append(Instruction.Create(OpCodes.Ret));

        var dynamicCall = CreateMethodReference(
            method.Module,
            typeName,
            methodName,
            hasThis: methodName == "DynamicInvoke",
            scopeName: "ThirdParty.Reflection");

        var findings = _rule.AnalyzeContextualPattern(dynamicCall, method.Body.Instructions, 3, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
    }

    private static MethodDefinition CreateMethod()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ReflectionRuleHotspotTests", new Version(1, 0, 0, 0)),
            "ReflectionRuleHotspotTests",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "ReflectionType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);
        return method;
    }

    private static MethodDefinition CreateMethodWithLocals(params string[] localTypeNames)
    {
        var method = CreateMethod();

        foreach (var fullName in localTypeNames)
        {
            var lastDot = fullName.LastIndexOf('.');
            var ns = lastDot > 0 ? fullName[..lastDot] : string.Empty;
            var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
            method.Body!.Variables.Add(new VariableDefinition(new TypeReference(ns, name, method.Module, method.Module.TypeSystem.CoreLibrary)));
        }

        method.Body!.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        return method;
    }

    private static MethodReference CreateMethodReference(
        ModuleDefinition module,
        string declaringTypeFullName,
        string methodName,
        bool hasThis = false,
        string? scopeName = null)
    {
        var lastDot = declaringTypeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? declaringTypeFullName[..lastDot] : string.Empty;
        var typeName = lastDot > 0 ? declaringTypeFullName[(lastDot + 1)..] : declaringTypeFullName;
        var scope = scopeName == null
            ? module.TypeSystem.CoreLibrary
            : new AssemblyNameReference(scopeName, new Version(1, 0, 0, 0));

        return new MethodReference(methodName, module.TypeSystem.Void, new TypeReference(ns, typeName, module, scope))
        {
            HasThis = hasThis
        };
    }

    private static MethodReference CreateGenericAttributeMethodReference(ModuleDefinition module)
    {
        var attributeMethod = new MethodReference(
            "GetCustomAttribute",
            module.TypeSystem.Object,
            new TypeReference("System.Reflection", "CustomAttributeExtensions", module, module.TypeSystem.CoreLibrary))
        {
            HasThis = false
        };

        var generic = new GenericInstanceMethod(attributeMethod);
        generic.GenericArguments.Add(new TypeReference(
            "System.Reflection",
            "AssemblyMetadataAttribute",
            module,
            new AssemblyNameReference("System.Runtime", new Version(1, 0, 0, 0))));

        return generic;
    }
}
