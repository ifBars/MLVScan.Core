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

    #region IsSuspicious Tests

    [Theory]
    [InlineData("System.Reflection.Assembly", "Load", true)]
    [InlineData("System.Reflection.Assembly", "LoadFrom", true)]
    [InlineData("System.Reflection.Assembly", "LoadFile", true)]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext", "LoadFromStream", true)]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext", "LoadFromAssemblyPath", true)]
    [InlineData("System.String", "Concat", false)]
    [InlineData("System.Object", "ToString", false)]
    public void IsSuspicious_VariousMethods_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var methodRef = CreateMethodRefWithType(typeName, methodName);

        var result = _rule.IsSuspicious(methodRef);

        result.Should().Be(expected);
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullDeclaringType_ReturnsFalse()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("Test", new Version(1, 0)),
            "Test",
            ModuleKind.Dll);
        var method = new MethodReference("Load", assembly.MainModule.TypeSystem.Void);
        // DeclaringType is null by default

        _rule.IsSuspicious(method).Should().BeFalse();
    }

    #endregion

    #region AnalyzeContextualPattern Tests

    [Fact]
    public void AnalyzeContextualPattern_NullMethod_ReturnsEmpty()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        var findings = _rule.AnalyzeContextualPattern(null!, instructions, 0, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NullDeclaringType_ReturnsEmpty()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("Test", new Version(1, 0)),
            "Test",
            ModuleKind.Dll);
        var method = new MethodReference("Load", assembly.MainModule.TypeSystem.Void);
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        var findings = _rule.AnalyzeContextualPattern(method, instructions, 0, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NonAssemblyLoadMethod_ReturnsEmpty()
    {
        var methodRef = CreateMethodRefWithType("System.String", "Concat");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 0, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_LoadFromWithSuspiciousProvenance_ProducesHighFinding()
    {
        var methodRef = CreateAssemblyLoadMethod("System.String");
        methodRef.Name = "LoadFrom";

        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("Test", new Version(1, 0)),
            "Test",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        // Create method with network download before LoadFrom
        var type = new TypeDefinition("Test", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Call, CreateMethod(module, "System.Net", "WebClient", "DownloadData")));
        il.Append(il.Create(OpCodes.Call, methodRef));
        il.Append(il.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeContextualPattern(methodRef, method.Body.Instructions, 1, new MethodSignals()).ToList();

        findings.Should().NotBeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_LoadBytesWithPDB_ProducesHighScore()
    {
        var methodRef = CreateAssemblyLoadMethod("System.Byte[]");
        methodRef.Name = "Load";
        // Add second parameter for PDB
        methodRef.Parameters.Add(new ParameterDefinition(new ArrayType(methodRef.Module.TypeSystem.Byte)));

        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Call, methodRef),
            Instruction.Create(OpCodes.Ret)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        findings.Should().NotBeEmpty();
        findings[0].RiskScore.Should().BeGreaterThanOrEqualTo(45);
    }

    [Fact]
    public void AnalyzeContextualPattern_ScoreTooLow_ReturnsEmpty()
    {
        var methodRef = CreateAssemblyLoadMethod("System.String");
        methodRef.Name = "Load";

        // Simple load with no suspicious context - should not produce finding
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "SomeAssembly"),
            Instruction.Create(OpCodes.Call, methodRef),
            Instruction.Create(OpCodes.Ret)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        // Score may be too low to produce a finding
        findings.Should().BeEmpty();
    }

    #endregion

    #region Safe Assembly Name Tests

    [Theory]
    [InlineData("System.Xml")]
    [InlineData("Newtonsoft.Json")]
    [InlineData("UnityEngine.CoreModule")]
    [InlineData("0Harmony")]
    [InlineData("MelonLoader")]
    [InlineData("BepInEx")]
    [InlineData("Il2Cpp")]
    [InlineData("Microsoft.NET")]
    public void AnalyzeContextualPattern_SafeAssemblyNames_AreSuppressed(string assemblyName)
    {
        var methodRef = CreateAssemblyLoadMethod("System.String");
        methodRef.Name = "Load";
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, assemblyName),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_UnsafeAssemblyName_ProducesFinding()
    {
        var methodRef = CreateAssemblyLoadMethod("System.String");
        methodRef.Name = "LoadFrom";
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "C:\\Temp\\malicious.dll"),
            Instruction.Create(OpCodes.Call, methodRef)
        };

        var findings = _rule.AnalyzeContextualPattern(methodRef, instructions, 1, new MethodSignals()).ToList();

        findings.Should().NotBeEmpty();
    }

    #endregion

    #region AnalyzeInstructions Tests

    [Fact]
    public void AnalyzeInstructions_AssemblyLoadContextResolving_ProducesFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("Test", new Version(1, 0)),
            "Test",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var subscriber = new MethodDefinition("Subscribe", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        subscriber.Body = new MethodBody(subscriber);
        type.Methods.Add(subscriber);

        var alcType = new TypeReference("System.Runtime.Loader", "AssemblyLoadContext", module, module.TypeSystem.CoreLibrary);
        var addResolving = new MethodReference("add_Resolving", module.TypeSystem.Void, alcType) { HasThis = true };
        addResolving.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Func`2", module, module.TypeSystem.CoreLibrary)));

        var sIl = subscriber.Body.GetILProcessor();
        sIl.Append(sIl.Create(OpCodes.Call, addResolving));
        sIl.Append(sIl.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(subscriber, subscriber.Body.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("Resolving");
    }

    [Fact]
    public void AnalyzeInstructions_NoResolveSubscription_ReturnsEmpty()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("Test", new Version(1, 0)),
            "Test",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("RegularMethod", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Ret));

        var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    #endregion

    #region Developer Guidance Tests

    [Fact]
    public void DeveloperGuidance_IsNotNull()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.AlternativeApis.Should().NotBeEmpty();
    }

    #endregion

    #region Rule Properties Tests

    [Fact]
    public void Description_IsNotNullOrEmpty()
    {
        _rule.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Severity_IsHigh()
    {
        _rule.Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void RuleId_IsCorrect()
    {
        _rule.RuleId.Should().Be("AssemblyDynamicLoadRule");
    }

    [Fact]
    public void RequiresCompanionCheck_IsTrue()
    {
        _rule.RequiresCompanionFinding.Should().BeTrue();
    }

    #endregion

    private static MethodReference CreateMethodRefWithType(string typeName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("Test", new Version(1, 0)),
            "Test",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var lastDot = typeName.LastIndexOf('.');
        var ns = lastDot > 0 ? typeName[..lastDot] : "";
        var name = lastDot > 0 ? typeName[(lastDot + 1)..] : typeName;

        var typeRef = new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
        return new MethodReference(methodName, module.TypeSystem.Void, typeRef);
    }
}
