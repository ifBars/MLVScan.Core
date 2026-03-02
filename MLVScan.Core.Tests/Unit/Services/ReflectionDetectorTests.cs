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
    public void IsReflectionInvokeMethod_NullDeclaringType_ReturnsFalse()
    {
        var detector = CreateDetector();
        var method = CreateMethodReferenceWithNullType("SomeMethod");

        detector.IsReflectionInvokeMethod(method).Should().BeFalse();
    }

    [Theory]
    [InlineData("System.Type", "GetTypeFromProgID", "Shell", true)]
    [InlineData("System.Type", "GetTypeFromProgID", "Command", true)]
    [InlineData("System.Type", "GetTypeFromProgID", "Process", true)]
    [InlineData("System.Type", "GetTypeFromProgID", "Exec", true)]
    [InlineData("System.Type", "GetTypeFromProgID", "NormalParam", true)] // All GetTypeFromProgID are flagged
    public void IsReflectionInvokeMethod_GetTypeFromProgID_WithSuspiciousParam_ReturnsExpected(string typeName, string methodName, string paramName, bool expected)
    {
        var detector = CreateDetector();
        var method = CreateMethodReferenceWithParameter(typeName, methodName, paramName);

        detector.IsReflectionInvokeMethod(method).Should().Be(expected);
    }

    [Fact]
    public void IsReflectionInvokeMethod_GetTypeFromCLSID_ReturnsTrue()
    {
        var detector = CreateDetector();
        var method = CreateMethodReferenceWithParameter("System.Type", "GetTypeFromCLSID", "Shell.Application");

        detector.IsReflectionInvokeMethod(method).Should().BeTrue();
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
        var signals = new MethodSignals { HasEncodedStrings = true };

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

    [Fact]
    public void ScanForReflectionInvocation_NoMatchingRule_ReturnsEmpty()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "ToString"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        // Use empty signals so no suspicious patterns trigger
        var signals = new MethodSignals();

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForReflectionInvocation_WithTypeLevelSignals_ReturnsFinding()
    {
        var signalTracker = new SignalTracker(new ScanConfig { EnableMultiSignalDetection = true });
        var detector = new ReflectionDetector(
            new IScanRule[] { new ProcessStartRule() },
            signalTracker,
            new StringPatternDetector(),
            new CodeSnippetBuilder());

        // Track type-level signals using GetOrCreateTypeSignals
        var typeSignals = signalTracker.GetOrCreateTypeSignals("Test.ReflectionType");
        if (typeSignals != null)
        {
            typeSignals.HasEncodedStrings = true;
        }

        var methodDef = CreateMethodDefinition("Test.ReflectionType", "TestMethod");
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Nop),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Theory]
    [InlineData("ShellExecute")]
    [InlineData("Execute")]
    [InlineData("Shell")]
    [InlineData("Start")]
    [InlineData("cmd.exe")]
    [InlineData("powershell.exe")]
    [InlineData("wscript.exe")]
    public void ScanForReflectionInvocation_SuspiciousMethodName_ReturnsFinding(string methodName)
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, methodName),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        findings.Should().ContainSingle();
    }

    [Fact]
    public void ScanForReflectionInvocation_ShellApplication_ReturnsFinding()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        findings.Should().ContainSingle();
    }

    [Fact]
    public void ScanForReflectionInvocation_EncodedString_DecodesAndDetects()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        // Use numeric-encoded "ShellExecute"
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "83101101108108101119117116101"), // Numeric encoding of "ShellExecute"
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        // This should detect the encoded string
        findings.Should().ContainSingle();
    }

    [Fact]
    public void ScanForReflectionInvocation_LiteralMethodNameForwardLookup_ReturnsFinding()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Call, calledMethod),
            Instruction.Create(OpCodes.Ldstr, "ShellExecute")
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[0], calledMethod, 0, instructions, signals).ToList();

        findings.Should().ContainSingle();
    }

    [Fact]
    public void ScanForReflectionInvocation_NonReflectionMethod_ReturnsEmpty()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.String", "Concat");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Start"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[1], calledMethod, 1, instructions, signals).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForReflectionInvocation_LocalVariableTracking_ReturnsFinding()
    {
        var detector = CreateDetector();
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "ShellExecute"),
            Instruction.Create(OpCodes.Stloc_0),
            Instruction.Create(OpCodes.Ldloc_0),
            Instruction.Create(OpCodes.Call, calledMethod)
        };
        var signals = new MethodSignals { HasProcessLikeCall = true };

        var findings = detector.ScanForReflectionInvocation(methodDef, instructions[3], calledMethod, 3, instructions, signals).ToList();

        findings.Should().ContainSingle();
    }

    private static ReflectionDetector CreateDetector()
    {
        var rules = new IScanRule[] { new ProcessStartRule() };
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

    private static MethodReference CreateMethodReferenceWithNullType(string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("ReflectionMethodRef", new Version(1, 0, 0, 0)), "ReflectionMethodRef", ModuleKind.Dll);
        var module = assembly.MainModule;
        return new MethodReference(methodName, module.TypeSystem.Void);
    }

    private static MethodReference CreateMethodReferenceWithParameter(string declaringTypeFullName, string methodName, string paramName)
    {
        var method = CreateMethodReference(declaringTypeFullName, methodName);
        method.Parameters.Add(new ParameterDefinition(paramName, ParameterAttributes.None, method.Module.TypeSystem.String));
        return method;
    }

    private static MethodDefinition CreateMethodDefinition(string typeFullName = "Test.ReflectionType", string methodName = "Run")
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("ReflectionMethod", new Version(1, 0, 0, 0)), "ReflectionMethod", ModuleKind.Dll);
        var module = assembly.MainModule;
        var lastDot = typeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? typeFullName[..lastDot] : "";
        var type = lastDot > 0 ? typeFullName[(lastDot + 1)..] : typeFullName;
        var typeDef = new TypeDefinition(ns, type, TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(typeDef);
        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        typeDef.Methods.Add(method);
        return method;
    }
}
