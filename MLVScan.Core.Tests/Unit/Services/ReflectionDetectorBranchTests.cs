using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public sealed class ReflectionDetectorBranchTests
{
    [Fact]
    public void IsReflectionInvokeMethod_GetTypeFromCLSID_WithoutSuspiciousParameter_ReturnsFalse()
    {
        var detector = CreateDetector(new ProcessStartRule());
        var calledMethod = CreateMethodReferenceWithParameter("System.Type", "GetTypeFromCLSID", "typeId");

        detector.IsReflectionInvokeMethod(calledMethod).Should().BeFalse();
    }

    [Fact]
    public void ScanForReflectionInvocation_ProcessSubstringOnly_DoesNotMatchProcessStartRule()
    {
        var detector = CreateDetector(new ProcessStartRule());
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "StartUpdateVolume"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(
            methodDef,
            instructions[1],
            calledMethod,
            1,
            instructions,
            new MethodSignals { HasProcessLikeCall = true }).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForReflectionInvocation_SensitiveFolderSignalAlone_DoesNotElevateReflectionFinding()
    {
        var detector = CreateDetector(new ProcessStartRule());
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Start"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(
            methodDef,
            instructions[1],
            calledMethod,
            1,
            instructions,
            new MethodSignals { UsesSensitiveFolder = true }).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanForReflectionInvocation_SensitiveFolderWithFileWrite_ElevatesReflectionFinding()
    {
        var detector = CreateDetector(new ProcessStartRule());
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Start"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(
            methodDef,
            instructions[1],
            calledMethod,
            1,
            instructions,
            new MethodSignals
            {
                UsesSensitiveFolder = true,
                HasFileWrite = true
            }).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("ProcessStartRule");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void ScanForReflectionInvocation_AssemblyLoadMethodNameWithSignals_ReturnsAssemblyDynamicLoadFinding()
    {
        var detector = CreateDetector(new AssemblyDynamicLoadRule());
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "LoadFrom"),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(
            methodDef,
            instructions[1],
            calledMethod,
            1,
            instructions,
            new MethodSignals { HasEncodedStrings = true }).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("AssemblyDynamicLoadRule");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void ScanForReflectionInvocation_LocalVariableTracking_UsesTrackedMethodName()
    {
        var detector = CreateDetector(new ExactMethodNameRule("ShellExecute", "ShellExecuteRule", Severity.High));
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "ShellExecute"),
            Instruction.Create(OpCodes.Stloc_0),
            Instruction.Create(OpCodes.Ldloc_0),
            Instruction.Create(OpCodes.Call, calledMethod)
        };

        var findings = detector.ScanForReflectionInvocation(
            methodDef,
            instructions[3],
            calledMethod,
            3,
            instructions,
            new MethodSignals { HasProcessLikeCall = true }).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("ShellExecuteRule");
    }

    [Fact]
    public void ScanForReflectionInvocation_ForwardLookup_UsesFutureMethodNameLiteral()
    {
        var detector = CreateDetector(new ExactMethodNameRule("ShellExecute", "ShellExecuteRule", Severity.High));
        var methodDef = CreateMethodDefinition();
        var calledMethod = CreateMethodReference("System.Type", "InvokeMember");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Call, calledMethod),
            Instruction.Create(OpCodes.Ldstr, "ShellExecute")
        };

        var findings = detector.ScanForReflectionInvocation(
            methodDef,
            instructions[0],
            calledMethod,
            0,
            instructions,
            new MethodSignals { HasProcessLikeCall = true }).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("ShellExecuteRule");
    }

    private static ReflectionDetector CreateDetector(params IScanRule[] rules)
    {
        var signalTracker = new SignalTracker(new ScanConfig { EnableMultiSignalDetection = true });
        return new ReflectionDetector(rules, signalTracker, new StringPatternDetector(), new CodeSnippetBuilder());
    }

    private static MethodReference CreateMethodReference(string declaringTypeFullName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ReflectionBranchMethodRef", new Version(1, 0, 0, 0)),
            "ReflectionBranchMethodRef",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var lastDot = declaringTypeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? declaringTypeFullName[..lastDot] : string.Empty;
        var typeName = lastDot > 0 ? declaringTypeFullName[(lastDot + 1)..] : declaringTypeFullName;

        return new MethodReference(methodName, module.TypeSystem.Void, new TypeReference(ns, typeName, module, module.TypeSystem.CoreLibrary));
    }

    private static MethodReference CreateMethodReferenceWithParameter(string declaringTypeFullName, string methodName, string parameterName)
    {
        var method = CreateMethodReference(declaringTypeFullName, methodName);
        method.Parameters.Add(new ParameterDefinition(parameterName, ParameterAttributes.None, method.Module.TypeSystem.String));
        return method;
    }

    private static MethodDefinition CreateMethodDefinition(string typeFullName = "Test.ReflectionBranchType", string methodName = "Run")
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ReflectionBranchMethod", new Version(1, 0, 0, 0)),
            "ReflectionBranchMethod",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var lastDot = typeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? typeFullName[..lastDot] : string.Empty;
        var typeName = lastDot > 0 ? typeFullName[(lastDot + 1)..] : typeFullName;
        var typeDef = new TypeDefinition(ns, typeName, TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(typeDef);

        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        typeDef.Methods.Add(method);
        return method;
    }

    private sealed class ExactMethodNameRule : IScanRule
    {
        private readonly string _methodName;

        public ExactMethodNameRule(string methodName, string ruleId, Severity severity)
        {
            _methodName = methodName;
            RuleId = ruleId;
            Severity = severity;
        }

        public string Description => "Detected process execution through exact reflected method name.";
        public Severity Severity { get; }
        public string RuleId { get; }
        public bool RequiresCompanionFinding => false;
        public IDeveloperGuidance? DeveloperGuidance => null;

        public bool IsSuspicious(MethodReference method)
        {
            return string.Equals(method.Name, _methodName, StringComparison.Ordinal);
        }
    }
}
