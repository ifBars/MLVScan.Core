using System.Linq;
using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class MethodScannerTests
{
    [Fact]
    public void ScanMethod_WithoutBody_ReturnsEmptyResult()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var scanner = CreateScanner(config, new IScanRule[] { new PassiveRule("RuleA") });
        var method = CreateMethod(withBody: false);

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().BeEmpty();
        result.PendingReflectionFindings.Should().BeEmpty();
    }

    [Fact]
    public void ScanMethod_CompanionRuleWithoutOtherTriggers_SuppressesHighFinding()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var scanner = CreateScanner(config, new IScanRule[]
        {
            new AnalyzeInstructionRule("Companion", true, Severity.High)
        });
        var method = CreateMethod();

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanMethod_CompanionRuleWithOtherTriggeredRule_AllowsFinding()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var scanner = CreateScanner(config, new IScanRule[]
        {
            new AnalyzeInstructionRule("Primary", false, Severity.Medium),
            new AnalyzeInstructionRule("Companion", true, Severity.High)
        });
        var method = CreateMethod();

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().HaveCount(2);
        result.Findings.Any(f => f.RuleId == "Companion").Should().BeTrue();
    }

    [Fact]
    public void ScanMethod_CompanionRuleLowSeverity_IsAllowedWithoutOtherRules()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var scanner = CreateScanner(config, new IScanRule[]
        {
            new AnalyzeInstructionRule("CompanionLow", true, Severity.Low)
        });
        var method = CreateMethod();

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().ContainSingle();
        result.Findings[0].RuleId.Should().Be("CompanionLow");
    }

    [Fact]
    public void ScanMethod_WithCriticalSignalCombination_AddsCriticalCombinationFinding()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var scanner = CreateScanner(config, new IScanRule[]
        {
            new SignalMutatingRule()
        });
        var method = CreateMethod();

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Any(f => f.Description.StartsWith("Critical:")).Should().BeTrue();
    }

    private static MethodScanner CreateScanner(ScanConfig config, IEnumerable<IScanRule> rules)
    {
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, config, null);
        return new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, localVariableAnalyzer, exceptionHandlerAnalyzer, config);
    }

    private static MethodDefinition CreateMethod(bool withBody = true)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("MethodScannerTest", new Version(1, 0, 0, 0)), "MethodScannerTest", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Type", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);

        if (withBody)
        {
            method.Body = new MethodBody(method);
            method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        }

        return method;
    }

    private sealed class PassiveRule : IScanRule
    {
        public PassiveRule(string ruleId) => RuleId = ruleId;
        public string Description => "Passive";
        public Severity Severity => Severity.Low;
        public string RuleId { get; }
        public bool RequiresCompanionFinding => false;
        public bool IsSuspicious(MethodReference method) => false;
    }

    private sealed class AnalyzeInstructionRule : IScanRule
    {
        public AnalyzeInstructionRule(string ruleId, bool requiresCompanionFinding, Severity severity)
        {
            RuleId = ruleId;
            RequiresCompanionFinding = requiresCompanionFinding;
            Severity = severity;
        }

        public string Description => "Analyze instruction rule";
        public Severity Severity { get; }
        public string RuleId { get; }
        public bool RequiresCompanionFinding { get; }
        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
            => new[] { new ScanFinding($"{method.DeclaringType?.FullName}.{method.Name}", $"finding:{RuleId}", Severity, "snippet") };
    }

    private sealed class SignalMutatingRule : IScanRule
    {
        public string Description => "Signal mutator";
        public Severity Severity => Severity.Low;
        public string RuleId => "SignalMutator";
        public bool RequiresCompanionFinding => false;
        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            methodSignals.HasEncodedStrings = true;
            methodSignals.HasProcessLikeCall = true;
            return Enumerable.Empty<ScanFinding>();
        }
    }
}
