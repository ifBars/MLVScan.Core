using System.Linq;
using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ReflectionDetectorTests
{
    [Theory]
    [InlineData("System.Type", "InvokeMember", true)]
    [InlineData("System.Type", "GetTypeFromProgID", true)]
    [InlineData("System.Activator", "CreateInstance", true)]
    [InlineData("System.Reflection.MethodInfo", "Invoke", true)]
    [InlineData("System.String", "Concat", false)]
    public void IsReflectionInvokeMethod_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var detector = CreateDetector();
        var method = CreateMethodReference(typeName, methodName);

        detector.IsReflectionInvokeMethod(method).Should().Be(expected);
    }

    [Fact]
    public void ScanForReflectionInvocation_NonLiteralWithoutSignals_ReturnsEmpty()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForReflectionInvocation_NonLiteralWithSignals_ReturnsHighFinding()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasNetworkCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("non-literal target method name");
    }

    [Fact]
    public void ScanForReflectionInvocation_LiteralMethodNameAndMatchingRule_ReturnsBypassFinding()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Start"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("Potential reflection bypass");
        findings[0].Severity.Should().NotBe(Severity.Low);
    }

    private static ReflectionDetector CreateDetector()
    {
        var rules = new IScanRule[] { new ProcessStartRule(), new Shell32Rule() };
        var signalTracker = new SignalTracker(new ScanConfig { EnableMultiSignalDetection = true });
        return new ReflectionDetector(rules, signalTracker, new StringPatternDetector(), new CodeSnippetBuilder());
    }

    private static MethodReference CreateMethodReference(string declaringTypeFullName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("ReflectionMethodRef", new Version(1, 0, 0, 0)), "ReflectionMethodRef", ModuleKind.Dll);
        var module = assembly.MainModule;
        var idx = declaringTypeFullName.LastIndexOf('.');
        var ns = idx > 0 ? declaringTypeFullName[..idx] : string.Empty;
        var type = idx > 0 ? declaringTypeFullName[(idx + 1)..] : declaringTypeFullName;
        return new MethodReference(methodName, module.TypeSystem.Void, new TypeReference(ns, type, module, module.TypeSystem.CoreLibrary));
    }

    private static MethodDefinition CreateMethodDefinition()
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("ReflectionMethod", new Version(1, 0, 0, 0)), "ReflectionMethod", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "ReflectionType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);
        return method;
    }
}
