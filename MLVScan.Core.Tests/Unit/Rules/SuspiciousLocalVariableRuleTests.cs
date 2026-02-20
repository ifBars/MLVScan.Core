using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class SuspiciousLocalVariableRuleTests
{
    private readonly SuspiciousLocalVariableRule _rule = new();

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = CreateMethodReference("System.String", "Concat");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_NoLocalVariables_ReturnsEmpty()
    {
        var method = CreateMethodWithLocals();

        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_WithSuspiciousLocals_MarksSignalWithoutStandaloneFinding()
    {
        var method = CreateMethodWithLocals(
            "System.Diagnostics.Process",
            "System.Runtime.InteropServices.Marshal",
            "System.Net.WebClient",
            "System.Net.Http.HttpClient",
            "System.String");

        var methodSignals = new MethodSignals();

        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, methodSignals).ToList();

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeTrue();
        methodSignals.HasAnyTriggeredRule().Should().BeTrue();
    }

    [Fact]
    public void AnalyzeInstructions_WithControlledProcessPattern_SuppressesProcessFinding()
    {
        var method = CreateMethodWithLocalsAndInstructions(
            new[] { "System.Diagnostics.Process" },
            il =>
            {
                il.Append(il.Create(OpCodes.Ldc_I4_0));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.ProcessStartInfo", "set_UseShellExecute")));
                il.Append(il.Create(OpCodes.Ldc_I4_1));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.ProcessStartInfo", "set_RedirectStandardOutput")));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.Process", "Start")));
                il.Append(il.Create(OpCodes.Ldc_I4, 120000));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.Process", "WaitForExit")));
            });

        var methodSignals = new MethodSignals();
        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, methodSignals).ToList();

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_WithDangerousCommandLiteral_MarksSignalWithoutStandaloneFinding()
    {
        var method = CreateMethodWithLocalsAndInstructions(
            new[] { "System.Diagnostics.Process" },
            il =>
            {
                il.Append(il.Create(OpCodes.Ldstr, "powershell.exe -nop"));
                il.Append(il.Create(OpCodes.Ldc_I4_0));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.ProcessStartInfo", "set_UseShellExecute")));
                il.Append(il.Create(OpCodes.Ldc_I4_1));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.ProcessStartInfo", "set_RedirectStandardOutput")));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.Process", "Start")));
                il.Append(il.Create(OpCodes.Ldc_I4, 120000));
                il.Append(il.Create(OpCodes.Callvirt, CreateMethodReference("System.Diagnostics.Process", "WaitForExit")));
            });

        var methodSignals = new MethodSignals();
        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, methodSignals).ToList();

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeTrue();
    }

    private static MethodReference CreateMethodReference(string declaringTypeFullName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("LocalRuleMethodRefFactory", new Version(1, 0, 0, 0)),
            "LocalRuleMethodRefFactory",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var lastDot = declaringTypeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? declaringTypeFullName[..lastDot] : string.Empty;
        var typeName = lastDot > 0 ? declaringTypeFullName[(lastDot + 1)..] : declaringTypeFullName;
        var typeRef = new TypeReference(ns, typeName, module, module.TypeSystem.CoreLibrary);
        return new MethodReference(methodName, module.TypeSystem.Void, typeRef);
    }

    private static MethodDefinition CreateMethodWithLocals(params string[] localTypeNames)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("LocalRuleAssembly", new Version(1, 0, 0, 0)),
            "LocalRuleAssembly",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "LocalType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        foreach (var fullName in localTypeNames)
        {
            var lastDot = fullName.LastIndexOf('.');
            var ns = lastDot > 0 ? fullName[..lastDot] : string.Empty;
            var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
            method.Body.Variables.Add(new VariableDefinition(new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary)));
        }

        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Ret));
        return method;
    }

    private static MethodDefinition CreateMethodWithLocalsAndInstructions(
        string[] localTypeNames,
        Action<ILProcessor> buildInstructions)
    {
        var method = CreateMethodWithLocals(localTypeNames);
        method.Body!.Instructions.Clear();

        var il = method.Body.GetILProcessor();
        buildInstructions(il);
        il.Append(il.Create(OpCodes.Ret));

        return method;
    }
}
