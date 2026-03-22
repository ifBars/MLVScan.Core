using System.Reflection;
using FluentAssertions;
using Mono.Cecil;
using Mono.Cecil.Cil;
using TypeAttributes = Mono.Cecil.TypeAttributes;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using ParameterAttributes = Mono.Cecil.ParameterAttributes;
using FieldAttributes = Mono.Cecil.FieldAttributes;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models.Rules.Helpers;

public sealed class InstructionValueResolverBranchTests
{
    private static readonly Assembly CoreAssembly = typeof(MLVScan.Models.ScanFinding).Assembly;
    private static readonly Type ResolverType =
        CoreAssembly.GetType("MLVScan.Models.Rules.Helpers.InstructionValueResolver", throwOnError: true)!;

    [Fact]
    public void TryResolveUseShellExecute_WithFalseLiteral_ReturnsFalseValue()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_UseShellExecute")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveUseShellExecute").Invoke(null, args)!;

        result.Should().BeTrue();
        args[3].Should().Be(false);
    }

    [Fact]
    public void TryResolveCreateNoWindow_WithFalseLiteral_ReturnsFalseValue()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4_0));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_CreateNoWindow")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveCreateNoWindow").Invoke(null, args)!;

        result.Should().BeTrue();
        args[3].Should().Be(false);
    }

    [Fact]
    public void TryResolveWindowStyle_WithFieldLoad_ResolvesStoredInteger()
    {
        var method = CreateMethod();
        var field = new FieldDefinition("WindowStyleValue", FieldAttributes.Private | FieldAttributes.Static, method.Module.TypeSystem.Int32);
        method.DeclaringType.Fields.Add(field);
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4_1));
        il.Append(Instruction.Create(OpCodes.Stsfld, field));
        il.Append(Instruction.Create(OpCodes.Ldsfld, field));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_WindowStyle")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveWindowStyle").Invoke(null, args)!;

        result.Should().BeTrue();
        args[3].Should().Be(1);
    }

    [Fact]
    public void TryResolveWorkingDirectory_WithUppercaseLiteral_NormalizesToLowercase()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldstr, @"C:\TEMP\PAYLOADS"));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_WorkingDirectory")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveWorkingDirectory").Invoke(null, args)!;

        result.Should().BeTrue();
        args[3].Should().Be(@"c:\temp\payloads");
    }

    [Fact]
    public void TryResolveStackValueDisplay_WithBoxedInteger_ReturnsNumericDisplay()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldc_I4, 7));
        il.Append(Instruction.Create(OpCodes.Box, method.Module.TypeSystem.Int32));

        var args = new object?[] { method, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveStackValueDisplay").Invoke(null, args)!;

        result.Should().BeTrue();
        args[3].Should().Be("7");
    }

    [Fact]
    public void TryResolveStackValueDisplay_WithLdnull_ReturnsNullMarker()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Ldnull));

        var args = new object?[] { method, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveStackValueDisplay").Invoke(null, args)!;

        result.Should().BeTrue();
        args[3].Should().Be("<null>");
    }

    [Fact]
    public void TryResolveProcessTarget_WithPathGetTempPath_FallsBackToUnknownTarget()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Call, CreatePathMethodRef(method.Module, "GetTempPath")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_FileName")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, CreateProcessStartMethodRef(method.Module), method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveProcessTarget").Invoke(null, args)!;

        result.Should().BeTrue();
        args[4].Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void TryResolveProcessTarget_WithGuidNewGuid_ReturnsGuidMarker()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();

        il.Append(Instruction.Create(OpCodes.Call, CreateGuidMethodRef(method.Module, "NewGuid")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_FileName")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, CreateProcessStartMethodRef(method.Module), method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveProcessTarget").Invoke(null, args)!;

        result.Should().BeTrue();
        args[4].Should().Be("<guid>");
    }

    [Fact]
    public void TryResolveProcessTarget_WithModuleLocalMethodReturn_UsesResolvedReturnValue()
    {
        var method = CreateMethod();
        var helper = new MethodDefinition("BuildTarget", MethodAttributes.Private | MethodAttributes.Static, method.Module.TypeSystem.String);
        helper.Body = new Mono.Cecil.Cil.MethodBody(helper);
        helper.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ldstr, "curl.exe"));
        helper.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        method.DeclaringType.Methods.Add(helper);

        var helperRef = new MethodReference(helper.Name, method.Module.TypeSystem.String, method.DeclaringType)
        {
            HasThis = false
        };

        var il = method.Body!.GetILProcessor();
        il.Append(Instruction.Create(OpCodes.Call, helperRef));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateStartInfoSetterMethodRef(method.Module, "set_FileName")));
        il.Append(Instruction.Create(OpCodes.Callvirt, CreateProcessStartMethodRef(method.Module)));

        var args = new object?[] { method, CreateProcessStartMethodRef(method.Module), method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveProcessTarget").Invoke(null, args)!;

        result.Should().BeTrue();
        args[4].Should().Be("\"curl.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_WithSingleArgumentNonStartCall_ReturnsUnknown()
    {
        var method = CreateMethod();
        var il = method.Body!.GetILProcessor();
        var calledMethod = new MethodReference("Launch", method.Module.TypeSystem.Void, new TypeReference("Tests", "Runner", method.Module, method.Module.TypeSystem.CoreLibrary))
        {
            HasThis = false
        };
        calledMethod.Parameters.Add(new ParameterDefinition("fileName", ParameterAttributes.None, method.Module.TypeSystem.String));

        il.Append(Instruction.Create(OpCodes.Ldstr, "calc.exe"));
        il.Append(Instruction.Create(OpCodes.Call, calledMethod));

        var args = new object?[] { method, calledMethod, method.Body.Instructions, method.Body.Instructions.Count - 1, null };
        var result = (bool)GetResolverMethod("TryResolveProcessTarget").Invoke(null, args)!;

        result.Should().BeFalse();
        args[4].Should().Be("<unknown/non-literal>");
    }

    private static MethodInfo GetResolverMethod(string name)
    {
        var method = ResolverType.GetMethod(name, BindingFlags.Public | BindingFlags.Static);
        method.Should().NotBeNull();
        return method!;
    }

    private static MethodDefinition CreateMethod()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("InstructionValueResolverBranchTests", new Version(1, 0, 0, 0)),
            "InstructionValueResolverBranchTests",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Tests", "Holder", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new Mono.Cecil.Cil.MethodBody(null!)
        };
        method.Body = new Mono.Cecil.Cil.MethodBody(method);
        type.Methods.Add(method);
        return method;
    }

    private static MethodReference CreateProcessStartMethodRef(ModuleDefinition module)
    {
        return new MethodReference("Start", module.TypeSystem.Boolean, new TypeReference("System.Diagnostics", "Process", module, module.TypeSystem.CoreLibrary))
        {
            HasThis = true
        };
    }

    private static MethodReference CreateStartInfoSetterMethodRef(ModuleDefinition module, string methodName)
    {
        return new MethodReference(methodName, module.TypeSystem.Void, new TypeReference("System.Diagnostics", "ProcessStartInfo", module, module.TypeSystem.CoreLibrary))
        {
            HasThis = true
        };
    }

    private static MethodReference CreatePathMethodRef(ModuleDefinition module, string methodName)
    {
        return new MethodReference(methodName, module.TypeSystem.String, new TypeReference("System.IO", "Path", module, module.TypeSystem.CoreLibrary))
        {
            HasThis = false
        };
    }

    private static MethodReference CreateGuidMethodRef(ModuleDefinition module, string methodName)
    {
        return new MethodReference(methodName, new TypeReference("System", "Guid", module, module.TypeSystem.CoreLibrary), new TypeReference("System", "Guid", module, module.TypeSystem.CoreLibrary))
        {
            HasThis = false
        };
    }
}
