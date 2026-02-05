using FluentAssertions;
using MLVScan.Models;
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
        var analyzer = new LocalVariableAnalyzer(new[] { new LocalRuleStub("RuleA", false, new[] { new ScanFinding("L", "D") }) }, tracker, config);
        var method = CreateMethodWithLocal();

        var findings = analyzer.AnalyzeLocalVariables(method, method.Body.Variables, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeLocalVariables_CompanionRuleWithoutOtherTriggers_SkipsFinding()
    {
        var config = new ScanConfig { AnalyzeLocalVariables = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var analyzer = new LocalVariableAnalyzer(new[]
        {
            new LocalRuleStub("CompanionRule", true, new[] { new ScanFinding("Test.Method", "Companion finding", Severity.High) })
        }, tracker, config);
        var method = CreateMethodWithLocal();
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals).ToList();

        findings.Should().BeEmpty();
        methodSignals.HasSuspiciousLocalVariables.Should().BeFalse();
    }

    [Fact]
    public void AnalyzeLocalVariables_WithAllowedFinding_AddsFindingAndMarksSignals()
    {
        var config = new ScanConfig { AnalyzeLocalVariables = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var rule = new LocalRuleStub("LocalRule", false, new[]
        {
            new ScanFinding("Test.Method", "Local variable suspicious", Severity.Low)
        });
        var analyzer = new LocalVariableAnalyzer(new[] { rule }, tracker, config);
        var method = CreateMethodWithLocal();
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeLocalVariables(method, method.Body.Variables, methodSignals).ToList();

        findings.Should().ContainSingle();
        methodSignals.HasSuspiciousLocalVariables.Should().BeTrue();
        methodSignals.HasTriggeredRuleOtherThan("DifferentRule").Should().BeTrue();
    }

    private static MethodDefinition CreateMethodWithLocal()
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
        method.Body.Variables.Add(new VariableDefinition(module.TypeSystem.String));
        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Nop));
        il.Append(il.Create(OpCodes.Ret));

        type.Methods.Add(method);
        return method;
    }

    private sealed class LocalRuleStub : IScanRule
    {
        private readonly IReadOnlyCollection<ScanFinding> _findings;

        public LocalRuleStub(string ruleId, bool requiresCompanionFinding, IEnumerable<ScanFinding> findings)
        {
            RuleId = ruleId;
            RequiresCompanionFinding = requiresCompanionFinding;
            _findings = findings.ToList();
        }

        public string Description => "Local variable rule stub";
        public Severity Severity => Severity.Low;
        public string RuleId { get; }
        public bool RequiresCompanionFinding { get; }

        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
            => _findings;
    }
}
