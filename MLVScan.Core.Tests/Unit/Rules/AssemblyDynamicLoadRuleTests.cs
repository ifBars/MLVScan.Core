using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class AssemblyDynamicLoadRuleTests
{
    private readonly AssemblyDynamicLoadRule _rule = new();

    [Fact]
    public void AnalyzeContextualPattern_LoadStringWithSafeAssemblyName_IsSuppressed()
    {
        var methodRef = CreateAssemblyLoadMethod("System.String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "System.Xml"),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_LoadBytesWithCorrelatedSignals_ProducesCriticalBypassFinding()
    {
        var methodRef = CreateAssemblyLoadMethod("System.Byte[]");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Call, methodRef),
            Instruction.Create(OpCodes.Ret)
        };
        var signals = new MethodSignals
        {
            HasProcessLikeCall = true,
            HasNetworkCall = true,
            HasFileWrite = true,
            UsesSensitiveFolder = true,
            HasEncodedStrings = true,
            HasBase64 = true
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, signals).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].BypassCompanionCheck.Should().BeTrue();
        findings[0].RiskScore.Should().NotBeNull();
        findings[0].RiskScore.Should().BeGreaterThanOrEqualTo(75);
        findings[0].Description.Should().Contain("Assembly.Load(byte[])");
    }

    [Fact]
    public void AnalyzeInstructions_AssemblyResolveSubscriptionWithRiskyHandler_ProducesHighFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ResolveTest", new Version(1, 0, 0, 0)),
            "ResolveTest",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "ResolveType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var handler = new MethodDefinition("OnResolve", MethodAttributes.Private | MethodAttributes.Static, module.TypeSystem.Object)
        {
            Body = new MethodBody(null!)
        };
        handler.Body = new MethodBody(handler);
        type.Methods.Add(handler);

        var hIl = handler.Body.GetILProcessor();
        hIl.Append(hIl.Create(OpCodes.Call, CreateAssemblyLoadMethod("System.Byte[]")));
        hIl.Append(hIl.Create(OpCodes.Call, CreateMethod(module, "System.Security.Cryptography", "Aes", "Create")));
        hIl.Append(hIl.Create(OpCodes.Callvirt, CreateMethod(module, "System.Net", "WebClient", "DownloadData")));
        hIl.Append(hIl.Create(OpCodes.Ldnull));
        hIl.Append(hIl.Create(OpCodes.Ret));

        var subscriber = new MethodDefinition("Subscribe", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        subscriber.Body = new MethodBody(subscriber);
        type.Methods.Add(subscriber);

        var appDomainType = new TypeReference("System", "AppDomain", module, module.TypeSystem.CoreLibrary);
        var addResolve = new MethodReference("add_AssemblyResolve", module.TypeSystem.Void, appDomainType) { HasThis = true };
        addResolve.Parameters.Add(new ParameterDefinition(new TypeReference("System", "ResolveEventHandler", module, module.TypeSystem.CoreLibrary)));

        var sIl = subscriber.Body.GetILProcessor();
        sIl.Append(sIl.Create(OpCodes.Ldftn, handler));
        sIl.Append(sIl.Create(OpCodes.Call, addResolve));
        sIl.Append(sIl.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(subscriber, subscriber.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].BypassCompanionCheck.Should().BeTrue();
        findings[0].Description.Should().Contain("AssemblyResolve/Resolving event subscription");
        findings[0].Description.Should().Contain("Handler:");
    }

    [Fact]
    public void AnalyzeInstructions_ReflectiveGetMethodPattern_ProducesMediumFinding()
    {
        var assembly = TestAssemblyBuilder.Create("ReflectiveLoadTest").Build();
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "ReflectionType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Probe", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var getMethodRef = CreateMethod(module, "System", "Type", "GetMethod");
        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Ldstr, "LoadFrom"));
        il.Append(il.Create(OpCodes.Call, getMethodRef));
        il.Append(il.Create(OpCodes.Ldstr, "System.Reflection.Assembly"));
        il.Append(il.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Medium);
        findings[0].Description.Should().Contain("Reflective invocation of Assembly.LoadFrom");
        findings[0].RiskScore.Should().Be(40);
    }

    private static MethodReference CreateAssemblyLoadMethod(string firstParamFullName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("MethodRefFactory", new Version(1, 0, 0, 0)),
            "MethodRefFactory",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var assemblyType = new TypeReference("System.Reflection", "Assembly", module, module.TypeSystem.CoreLibrary);

        var method = new MethodReference("Load", assemblyType, assemblyType)
        {
            HasThis = false
        };

        TypeReference paramType = firstParamFullName switch
        {
            "System.String" => module.TypeSystem.String,
            "System.Byte[]" => new ArrayType(module.TypeSystem.Byte),
            _ => module.TypeSystem.Object
        };

        method.Parameters.Add(new ParameterDefinition(paramType));
        return method;
    }

    private static MethodReference CreateMethod(ModuleDefinition module, string ns, string typeName, string methodName)
    {
        var type = new TypeReference(ns, typeName, module, module.TypeSystem.CoreLibrary);
        return new MethodReference(methodName, module.TypeSystem.Void, type);
    }
}
