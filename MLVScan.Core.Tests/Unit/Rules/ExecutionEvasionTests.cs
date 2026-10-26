using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ExecutionEvasionTests
{
    [Theory]
    [InlineData("System.Diagnostics.Process", "Start", true, true)]
    [InlineData("System.Diagnostics.Process", "GetCurrentProcess", true, false)]
    [InlineData("System.String", "StartsWith", true, false)]
    [InlineData("System.Diagnostics.Process", "Start", false, false)]
    public void ReflectedTarget_RequiresExecutionOfProcessStart(string typeName, string member, bool invoke, bool expected)
    {
        using var module = ModuleDefinition.CreateModule("ReflectionTarget", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        var target = new TypeReference(typeName[..typeName.LastIndexOf('.')], typeName[(typeName.LastIndexOf('.') + 1)..], module, module.TypeSystem.CoreLibrary);
        il.Emit(OpCodes.Ldtoken, target);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle))!));
        il.Emit(OpCodes.Ldstr, member);
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(Type).GetMethod(nameof(Type.GetMethod), [typeof(string)])!));
        if (invoke)
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Reflection.MethodBase).GetMethod("Invoke", [typeof(object), typeof(object[])])!));
        }
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var findings = new ProcessStartRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();
        findings.Any(finding => finding.Severity >= Severity.High).Should().Be(expected);
        if (expected)
        {
            var dto = ScanResultMapper.ToDto(findings, "probe.dll", [], false);
            dto.Disposition!.Classification.Should().Be("Suspicious");
        }
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void Base64_RequiresDecodedValueToReachProcessTarget(bool useDecodedTarget, bool expected)
    {
        using var module = ModuleDefinition.CreateModule("DecodedTarget", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Text.Encoding).GetProperty("UTF8")!.GetMethod!));
        il.Emit(OpCodes.Ldstr, "dG9vbC5leGU=");
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Convert).GetMethod(nameof(Convert.FromBase64String))!));
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Text.Encoding).GetMethod("GetString", [typeof(byte[])])!));
        if (!useDecodedTarget)
        {
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldstr, "tool.exe");
        }
        il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(string)])!));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var findings = new ObfuscatedReflectiveExecutionRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();
        findings.Any(finding => finding.Description.Contains("reconstructed execution target", StringComparison.Ordinal)).Should().Be(expected);
    }

    [Theory]
    [InlineData(7, "helper.exe", "Suspicious")]
    [InlineData(24, "helper.cmd", "Suspicious")]
    [InlineData(7, "readme.txt", "Clean")]
    [InlineData(26, "settings.json", "Clean")]
    public void FolderWrite_UsesDestinationAndExecutableContent(int folder, string fileName, string expected)
    {
        using var module = ModuleDefinition.CreateModule("FolderWrite", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4, folder);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Environment).GetMethod("GetFolderPath", [typeof(Environment.SpecialFolder)])!));
        il.Emit(OpCodes.Ldstr, fileName);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Path).GetMethod("Combine", [typeof(string), typeof(string)])!));
        il.Emit(OpCodes.Ldstr, "content");
        var write = module.ImportReference(typeof(File).GetMethod("WriteAllText", [typeof(string), typeof(string)])!);
        il.Emit(OpCodes.Call, write);
        il.Emit(OpCodes.Ret);
        int index = method.Body.Instructions.Count - 2;
        var findings = new PersistenceRule().AnalyzeContextualPattern(write, method.Body.Instructions, index, new MethodSignals()).ToList();
        findings.ForEach(finding => finding.RuleId = "PersistenceRule");
        ScanResultMapper.ToDto(findings, "probe.dll", [], false).Disposition!.Classification.Should().Be(expected);
        if (folder is 7 or 24)
        {
            findings.Should().NotBeEmpty();
        }
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void ReversedCharacters_RequiresSameArrayToReachProcess(bool sameArray, bool expected)
    {
        using var module = ModuleDefinition.CreateModule("ReversedTarget", ModuleKind.Dll);
        var method = AddMethod(module);
        var chars = new VariableDefinition(new ArrayType(module.TypeSystem.Char));
        method.Body.Variables.Add(chars);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "exe.loot");
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(string).GetMethod("ToCharArray", Type.EmptyTypes)!));
        il.Emit(OpCodes.Stloc, chars);
        il.Emit(OpCodes.Ldloc, chars);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Array).GetMethod("Reverse", [typeof(Array)])!));
        if (sameArray)
        {
            il.Emit(OpCodes.Ldloc, chars);
            il.Emit(OpCodes.Newobj, module.ImportReference(typeof(string).GetConstructor([typeof(char[])])!));
        }
        else
        {
            il.Emit(OpCodes.Ldstr, "tool.exe");
        }
        il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(string)])!));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var findings = new ObfuscatedReflectiveExecutionRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();
        findings.Any(finding => finding.Description.Contains("reconstructed execution target", StringComparison.Ordinal)).Should().Be(expected);
    }

    [Theory]
    [InlineData("Win32_Process", "Create", true)]
    [InlineData("Win32_Process", "GetOwner", false)]
    [InlineData("Win32_Service", "Create", false)]
    public void Wmi_RequiresProcessClassAndCreateOnSameReceiver(string className, string member, bool expected)
    {
        using var module = ModuleDefinition.CreateModule("WmiTarget", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        var wmi = new TypeReference("System.Management", "ManagementClass", module, module.TypeSystem.CoreLibrary);
        var constructor = new MethodReference(".ctor", module.TypeSystem.Void, wmi) { HasThis = true };
        constructor.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        var invoke = new MethodReference("InvokeMethod", module.TypeSystem.Object, wmi) { HasThis = true };
        invoke.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        invoke.Parameters.Add(new ParameterDefinition(new ArrayType(module.TypeSystem.Object)));
        il.Emit(OpCodes.Ldstr, className);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Ldstr, member);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Callvirt, invoke);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        new ProcessStartRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).Any()
            .Should().Be(expected);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void XorLoading_RequiresTransformedArrayToReachAssemblyLoad(bool sameArray)
    {
        using var module = ModuleDefinition.CreateModule("XorLoader", ModuleKind.Dll);
        var method = AddMethod(module);
        var decoded = new VariableDefinition(new ArrayType(module.TypeSystem.Byte));
        var unrelated = new VariableDefinition(new ArrayType(module.TypeSystem.Byte));
        method.Body.Variables.Add(decoded);
        method.Body.Variables.Add(unrelated);
        var il = method.Body.GetILProcessor();
        foreach (var local in new[] { decoded, unrelated })
        {
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Newarr, module.TypeSystem.Byte);
            il.Emit(OpCodes.Stloc, local);
        }
        il.Emit(OpCodes.Ldloc, decoded);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Ldc_I4, 17);
        il.Emit(OpCodes.Ldc_I4_3);
        il.Emit(OpCodes.Xor);
        il.Emit(OpCodes.Conv_U1);
        il.Emit(OpCodes.Stelem_I1);
        il.Emit(OpCodes.Ldloc, sameArray ? decoded : unrelated);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Reflection.Assembly).GetMethod("Load", [typeof(byte[])])!));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Reflection.MethodBase).GetMethod("Invoke", [typeof(object), typeof(object[])])!));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var findings = new ObfuscatedReflectiveExecutionRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();
        findings.Any().Should().Be(sameArray);
    }

    [Fact]
    public void NestedPathArguments_PreserveTempRootAcrossInstanceCalls()
    {
        using var module = ModuleDefinition.CreateModule("NestedPath", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Path).GetMethod("GetTempPath")!));
        il.Emit(OpCodes.Ldstr, "subfolder");
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(object).GetMethod("ToString")!));
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Path).GetMethod("Combine", [typeof(string), typeof(string), typeof(string)])!));
        il.Emit(OpCodes.Ldstr, "content");
        var write = module.ImportReference(typeof(File).GetMethod("WriteAllText", [typeof(string), typeof(string)])!);
        il.Emit(OpCodes.Call, write);
        il.Emit(OpCodes.Ret);
        int index = method.Body.Instructions.Count - 2;
        MLVScan.Models.Rules.Helpers.InstructionValueResolver.TryResolveCallArgumentDisplay(method, write,
            method.Body.Instructions, index, 0, out string destination).Should().BeTrue();
        destination.Should().StartWith("%TEMP%/subfolder/");
    }

    [Fact]
    public void PathArrayArguments_ResolveAllSegmentsInOrder()
    {
        using var module = ModuleDefinition.CreateModule("PathArray", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        string[] parts = ["Windows", "SysNative", "WindowsPowerShell", "v1.0", "powershell.exe"];
        il.Emit(OpCodes.Ldc_I4, parts.Length);
        il.Emit(OpCodes.Newarr, module.TypeSystem.String);
        for (int index = 0; index < parts.Length; index++)
        {
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, index);
            il.Emit(OpCodes.Ldstr, parts[index]);
            il.Emit(OpCodes.Stelem_Ref);
        }
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Path).GetMethod("Combine", [typeof(string[])])!));
        il.Emit(OpCodes.Ldstr, "content");
        var write = module.ImportReference(typeof(File).GetMethod("WriteAllText", [typeof(string), typeof(string)])!);
        il.Emit(OpCodes.Call, write);
        il.Emit(OpCodes.Ret);
        MLVScan.Models.Rules.Helpers.InstructionValueResolver.TryResolveCallArgumentDisplay(method, write,
            method.Body.Instructions, method.Body.Instructions.Count - 2, 0, out string destination).Should().BeTrue();
        destination.Should().Be(string.Join('/', parts));
    }

    [Theory]
    [InlineData("Start", true)]
    [InlineData("GetCurrentProcess", false)]
    public void EmittedTarget_RequiresProcessStartMethodInfo(string member, bool expected)
    {
        using var module = ModuleDefinition.CreateModule("EmittedTarget", ModuleKind.Dll);
        var method = AddMethod(module);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ldsfld, module.ImportReference(typeof(System.Reflection.Emit.OpCodes).GetField("Call")!));
        il.Emit(OpCodes.Ldtoken, module.ImportReference(typeof(System.Diagnostics.Process)));
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Type).GetMethod("GetTypeFromHandle")!));
        il.Emit(OpCodes.Ldstr, member);
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(Type).GetMethod("GetMethod", [typeof(string)])!));
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Reflection.Emit.ILGenerator).GetMethod("Emit",
            [typeof(System.Reflection.Emit.OpCode), typeof(System.Reflection.MethodInfo)])!));
        il.Emit(OpCodes.Ret);

        new ProcessStartRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).Any()
            .Should().Be(expected);
    }

    private static MethodDefinition AddMethod(ModuleDefinition module)
    {
        var type = new TypeDefinition("Probe", "Entry", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        return method;
    }
}
