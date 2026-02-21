using System.Reflection;
using FluentAssertions;
using Mono.Cecil;
using Mono.Cecil.Cil;
using TypeAttributes = Mono.Cecil.TypeAttributes;
using FieldAttributes = Mono.Cecil.FieldAttributes;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models.Rules.Helpers;

public class InstructionValueResolverTests
{
    private static readonly Assembly CoreAssembly = typeof(MLVScan.Models.ScanFinding).Assembly;
    private static readonly Type ResolverType = CoreAssembly.GetType("MLVScan.Models.Rules.Helpers.InstructionValueResolver")!;

    private static readonly MethodInfo TryResolveProcessTargetMethod =
        ResolverType.GetMethod("TryResolveProcessTarget", BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo TryResolveProcessArgumentsMethod =
        ResolverType.GetMethod("TryResolveProcessArguments", BindingFlags.Static | BindingFlags.NonPublic)!;

    #region TryResolveProcessTarget - StartInfo.FileName Setter Tests

    [Fact]
    public void TryResolveProcessTarget_StartInfoFileNameWithLiteral_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "notepad.exe");
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"notepad.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_StartInfoFileNameWithPath_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, @"C:\Windows\System32\cmd.exe");
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"cmd.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_StartInfoFileNameWithLocal_ReturnsLocalMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldloc_0);
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("<local V_0>");
    }

    [Fact]
    public void TryResolveProcessTarget_StartInfoFileNameWithArgument_ReturnsArgumentMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("<arg 0>");
    }

    #endregion

    #region TryResolveProcessTarget - Path.Combine Tests

    [Fact]
    public void TryResolveProcessTarget_PathCombineWithExecutable_ReturnsQuotedExecutable()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:\\Tools");
        processor.Emit(OpCodes.Ldstr, "curl.exe");
        processor.Emit(OpCodes.Call, CreatePathMethodRef("Combine", 2));
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"curl.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_PathCombineWithNonExecutable_ReturnsUnknownMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:\\Data");
        processor.Emit(OpCodes.Ldstr, "file.txt");
        processor.Emit(OpCodes.Call, CreatePathMethodRef("Combine", 2));
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Contain("<dynamic via Path.Combine");
    }

    [Fact]
    public void TryResolveProcessTarget_PathGetFileName_ExtractsExecutable()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, @"C:\Windows\System32\powershell.exe");
        processor.Emit(OpCodes.Call, CreatePathMethodRef("GetFileName", 1));
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"powershell.exe\"");
    }

    #endregion

    #region TryResolveProcessTarget - String.Concat Tests

    [Fact]
    public void TryResolveProcessTarget_StringConcatWithExecutable_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "powers");
        processor.Emit(OpCodes.Ldstr, "hell.exe");
        processor.Emit(OpCodes.Call, CreateStringMethodRef("Concat", 2));
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"powershell.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_StringFormat_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "{0}.exe");
        processor.Emit(OpCodes.Ldstr, "cmd");
        processor.Emit(OpCodes.Call, CreateStringMethodRef("Format", 2));
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Contain("cmd.exe");
    }

    #endregion

    #region TryResolveProcessTarget - Field Tests

    [Fact]
    public void TryResolveProcessTarget_StaticFieldWithExecutable_ReturnsQuotedValue()
    {
        var type = new TypeDefinition("Tests", "Holder", TypeAttributes.Public | TypeAttributes.Class, new TypeReference("", "Object", null, null));
        var field = new FieldDefinition("ExecutablePath", FieldAttributes.Public | FieldAttributes.Static, new TypeReference("", "String", null, null));
        type.Fields.Add(field);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static, new TypeReference("", "Void", null, null));
        type.Methods.Add(method);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "calc.exe");
        processor.Emit(OpCodes.Stsfld, field);
        processor.Emit(OpCodes.Ldsfld, field);
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"calc.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_InstanceFieldWithExecutable_ReturnsQuotedValue()
    {
        var type = new TypeDefinition("Tests", "Holder", TypeAttributes.Public | TypeAttributes.Class, new TypeReference("", "Object", null, null));
        var field = new FieldDefinition("ExecutablePath", FieldAttributes.Public, new TypeReference("", "String", null, null));
        type.Fields.Add(field);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        type.Methods.Add(method);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Ldstr, "mspaint.exe");
        processor.Emit(OpCodes.Stfld, field);
        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Ldfld, field);
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"mspaint.exe\"");
    }

    #endregion

    #region TryResolveProcessTarget - Start Method with Arguments Tests

    [Fact]
    public void TryResolveProcessTarget_StartMethodWithSingleArg_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "wmic.exe");
        var startRef = CreateProcessStartMethodRef();
        startRef.HasThis = false;
        startRef.ReturnType = new TypeReference("System.Diagnostics", "Process", null, null);
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        processor.Emit(OpCodes.Call, startRef);

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            startRef,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"wmic.exe\"");
    }

    [Fact]
    public void TryResolveProcessTarget_StartMethodWithMultipleArgs_ReturnsFirstArgAsTarget()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "regsvr32.exe");
        processor.Emit(OpCodes.Ldstr, "/s");
        var startRef = CreateProcessStartMethodRef();
        startRef.HasThis = false;
        startRef.ReturnType = new TypeReference("System.Diagnostics", "Process", null, null);
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        processor.Emit(OpCodes.Call, startRef);

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            startRef,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"regsvr32.exe\"");
    }

    #endregion

    #region TryResolveProcessTarget - Edge Cases

    [Fact]
    public void TryResolveProcessTarget_NoStartInfoSetter_ReturnsUnknownMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeFalse();
        target.Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void TryResolveProcessTarget_StartInfoSetterBeyondSearchRange_ReturnsUnknownMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        for (int i = 0; i < 500; i++)
        {
            processor.Emit(OpCodes.Nop);
        }

        processor.Emit(OpCodes.Ldstr, "shouldnotfind.exe");
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeFalse();
        target.Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void TryResolveProcessTarget_WithBatFile_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "setup.bat");
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"setup.bat\"");
    }

    [Fact]
    public void TryResolveProcessTarget_WithPowershellScript_ReturnsQuotedValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "script.ps1");
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_FileName"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;
        var calledMethod = CreateProcessStartMethodRef();

        var result = TryResolveProcessTargetMethod.Invoke(null, new object[]
        {
            method,
            calledMethod,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var target = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        target.Should().Be("\"script.ps1\"");
    }

    #endregion

    #region TryResolveProcessArguments Tests

    [Fact]
    public void TryResolveProcessArguments_StartInfoArgumentsWithLiteral_ReturnsValue()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "--version --help");
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_Arguments"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;

        var result = TryResolveProcessArgumentsMethod.Invoke(null, new object[]
        {
            method,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var arguments = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        arguments.Should().Be("--version --help");
    }

    [Fact]
    public void TryResolveProcessArguments_StartInfoArgumentsWithLocal_ReturnsLocalMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldloc_0);
        processor.Emit(OpCodes.Callvirt, CreateStartInfoSetterMethodRef("set_Arguments"));
        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;

        var result = TryResolveProcessArgumentsMethod.Invoke(null, new object[]
        {
            method,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var arguments = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeTrue();
        arguments.Should().Be("<local V_0>");
    }

    [Fact]
    public void TryResolveProcessArguments_NoArgumentsSetter_ReturnsUnknownMarker()
    {
        var method = CreateTestMethod();
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Callvirt, CreateProcessStartMethodRef());

        var instructions = method.Body.Instructions;
        int processStartIndex = instructions.Count - 1;

        var result = TryResolveProcessArgumentsMethod.Invoke(null, new object[]
        {
            method,
            instructions,
            processStartIndex,
            null!
        })!;

        var success = (bool)result.GetType().GetProperty("Item1")!.GetValue(result)!;
        var arguments = (string)result.GetType().GetProperty("Item2")!.GetValue(result)!;

        success.Should().BeFalse();
        arguments.Should().Be("<unknown/no-arguments>");
    }

    #endregion

    #region Helper Methods

    private static MethodDefinition CreateTestMethod()
    {
        return new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
    }

    private static MethodReference CreateProcessStartMethodRef()
    {
        return new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));
    }

    private static MethodReference CreateStartInfoSetterMethodRef(string methodName)
    {
        return new MethodReference(methodName, new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null));
    }

    private static MethodReference CreatePathMethodRef(string methodName, int paramCount)
    {
        var methodRef = new MethodReference(methodName, new TypeReference("", "String", null, null), new TypeReference("System.IO", "Path", null, null));
        for (int i = 0; i < paramCount; i++)
        {
            methodRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        }
        return methodRef;
    }

    private static MethodReference CreateStringMethodRef(string methodName, int paramCount)
    {
        var methodRef = new MethodReference(methodName, new TypeReference("", "String", null, null), new TypeReference("System", "String", null, null));
        for (int i = 0; i < paramCount; i++)
        {
            methodRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "Object", null, null)));
        }
        return methodRef;
    }

    #endregion
}
