using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class LocalVariableAnalyzerTests
{
    [Fact]
    public void Constructor_WithNullRules_ThrowsArgumentNullException()
    {
        var config = new ScanConfig();
        var tracker = new SignalTracker(config);

        var act = () => new LocalVariableAnalyzer(null!, tracker, config);

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("rules");
    }

    [Fact]
    public void AnalyzeLocalVariables_WhenDisabled_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzeLocalVariables = false };
        var tracker = new SignalTracker(config);
        var analyzer = new LocalVariableAnalyzer(new IScanRule[] { new SuspiciousLocalVariableRule() }, tracker, config);
        var method = CreateMethodWithLocal("System.Diagnostics.Process");
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals);

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeFalse();
    }

    [Fact]
    public void AnalyzeLocalVariables_IgnoresNonLocalVariableRules()
    {
        var config = new ScanConfig { AnalyzeLocalVariables = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var rule = new LocalRuleStub();
        var analyzer = new LocalVariableAnalyzer(new IScanRule[] { rule }, tracker, config);
        var method = CreateMethodWithLocal("System.Diagnostics.Process");
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals).ToList();

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeFalse();
        rule.AnalyzeInstructionsCallCount.Should().Be(0);
    }

    [Fact]
    public void AnalyzeLocalVariables_WithSuspiciousProcessVariable_MarksSignalsWithoutStandaloneFinding()
    {
        var config = new ScanConfig { AnalyzeLocalVariables = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var analyzer = new LocalVariableAnalyzer(new IScanRule[] { new SuspiciousLocalVariableRule() }, tracker, config);
        var method = CreateMethodWithLocal("System.Diagnostics.Process");
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals).ToList();

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeTrue();
        methodSignals.HasTriggeredRuleOtherThan("DifferentRule").Should().BeTrue();
    }

    [Fact]
    public void AnalyzeLocalVariables_WithSuspiciousProcessVariable_PropagatesTypeLevelSignal()
    {
        var config = new ScanConfig { AnalyzeLocalVariables = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var analyzer = new LocalVariableAnalyzer(new IScanRule[] { new SuspiciousLocalVariableRule() }, tracker, config);
        var method = CreateMethodWithLocal("System.Diagnostics.Process");
        var methodSignals = new MethodSignals();
        var typeSignals = tracker.GetOrCreateTypeSignals(method.DeclaringType!.FullName);

        analyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals).ToList();

        typeSignals.Should().NotBeNull();
        typeSignals!.HasSuspiciousLocalVariables.Should().BeTrue();
    }

    private static MethodDefinition CreateMethodWithLocal(string localVariableTypeName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("LocalVarTestAssembly", new Version(1, 0, 0, 0)),
            "LocalVarTestModule",
            ModuleKind.Dll);

        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "LocalVarType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        var variableType = localVariableTypeName == "System.Diagnostics.Process"
            ? new TypeReference("System.Diagnostics", "Process", module, module.TypeSystem.CoreLibrary)
            : module.TypeSystem.String;
        method.Body.Variables.Add(new VariableDefinition(variableType));
        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Nop));
        il.Append(il.Create(OpCodes.Ret));

        type.Methods.Add(method);
        return method;
    }

    private sealed class LocalRuleStub : IScanRule
    {
        public int AnalyzeInstructionsCallCount { get; private set; }
        public string Description => "Local variable rule stub";
        public Severity Severity => Severity.Low;
        public string RuleId => "LocalRuleStub";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            AnalyzeInstructionsCallCount++;
            return new[] { new ScanFinding("L", "D") };
        }
    }
}
