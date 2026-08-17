using System.Linq;
using FluentAssertions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
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

    [Fact]
    public void ScanMethod_WithLocalVariables_DoesNotReplayAnalyzeInstructionsForNonLocalRules()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true, AnalyzeLocalVariables = true };
        var countingRule = new CountingAnalyzeInstructionRule();
        var scanner = CreateScanner(config, new IScanRule[] { countingRule });
        var method = CreateMethod(withLocalVariable: true);

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().ContainSingle();
        countingRule.AnalyzeInstructionsCallCount.Should().Be(1);
    }

    [Theory]
    [InlineData(0xD800)]
    [InlineData(0xDC00)]
    public void ScanMethod_UnpairedSurrogateDoesNotSuppressProcessStartFinding(int malformedCodeUnit)
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true };
        var scanner = CreateScanner(config, new IScanRule[]
        {
            new ObfuscatedReflectiveExecutionRule(),
            new ProcessStartRule()
        });
        var method = CreateMethod();
        var processor = method.Body.GetILProcessor();
        var ret = method.Body.Instructions.Single();
        var processStart = method.Module.ImportReference(
            typeof(System.Diagnostics.Process).GetMethod(
                nameof(System.Diagnostics.Process.Start),
                new[] { typeof(string) })!);

        processor.InsertBefore(ret, Instruction.Create(OpCodes.Ldstr, new string((char)malformedCodeUnit, 1)));
        processor.InsertBefore(ret, Instruction.Create(OpCodes.Pop));
        processor.InsertBefore(ret, Instruction.Create(OpCodes.Ldstr, "cmd.exe"));
        processor.InsertBefore(ret, Instruction.Create(OpCodes.Call, processStart));
        processor.InsertBefore(ret, Instruction.Create(OpCodes.Pop));

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().Contain(finding => finding.RuleId == "ProcessStartRule");
    }

    [Fact]
    public void ScanMethod_MultiSignalDisabled_PropagatesExceptionHandlersToSuppression()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = false };
        var rule = new CapturingSuppressionRule();
        var scanner = CreateScanner(config, new IScanRule[] { rule });
        var method = CreateMethod();
        var il = method.Body.GetILProcessor();
        var ret = method.Body.Instructions.Single();
        var tryStart = Instruction.Create(OpCodes.Nop);
        var handlerStart = Instruction.Create(OpCodes.Pop);
        var afterHandler = Instruction.Create(OpCodes.Call,
            new MethodReference("Target", method.Module.TypeSystem.Void,
                new TypeReference("Test", "Target", method.Module, method.Module.TypeSystem.CoreLibrary)));
        il.InsertBefore(ret, tryStart);
        il.InsertBefore(ret, Instruction.Create(OpCodes.Leave, afterHandler));
        il.InsertBefore(ret, handlerStart);
        il.InsertBefore(ret, Instruction.Create(OpCodes.Leave, afterHandler));
        il.InsertBefore(ret, afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler,
            CatchType = method.Module.ImportReference(typeof(Exception))
        });

        using var assemblyBytes = new MemoryStream();
        method.Module.Assembly.Write(assemblyBytes);
        assemblyBytes.Position = 0;
        using var reloadedAssembly = AssemblyDefinition.ReadAssembly(assemblyBytes);
        var reloadedMethod = reloadedAssembly.MainModule.Types
            .Single(type => type.FullName == "Test.Type").Methods
            .Single(candidate => candidate.Name == "Run");

        var result = scanner.ScanMethod(reloadedMethod, "Test.Type");

        result.Findings.Should().BeEmpty();
        rule.ObservedExceptionHandlerCount.Should().Be(1);
    }

    [Fact]
    public void ScanMethod_MultiSignalDisabled_DoesNotEnableCompanionCorrelation()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = false };
        var scanner = CreateScanner(config, new IScanRule[]
        {
            new NamedCallRule("Primary", "Primary", requiresCompanionFinding: false),
            new ContextualNamedCallRule("Companion", "Target")
        });
        var method = CreateMethod();
        var il = method.Body.GetILProcessor();
        var ret = method.Body.Instructions.Single();
        il.InsertBefore(ret, Instruction.Create(OpCodes.Call,
            new MethodReference("Primary", method.Module.TypeSystem.Void,
                new TypeReference("Test", "Target", method.Module, method.Module.TypeSystem.CoreLibrary))));
        il.InsertBefore(ret, Instruction.Create(OpCodes.Call,
            new MethodReference("Target", method.Module.TypeSystem.Void,
                new TypeReference("Test", "Target", method.Module, method.Module.TypeSystem.CoreLibrary))));

        var result = scanner.ScanMethod(method, "Test.Type");

        result.Findings.Should().ContainSingle(finding => finding.RuleId == "Primary");
        result.Findings.Should().NotContain(finding => finding.RuleId == "Companion");
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

    private static MethodDefinition CreateMethod(bool withBody = true, bool withLocalVariable = false)
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
            if (withLocalVariable)
            {
                method.Body.Variables.Add(new VariableDefinition(module.TypeSystem.String));
            }

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

    private sealed class CountingAnalyzeInstructionRule : IScanRule
    {
        public int AnalyzeInstructionsCallCount { get; private set; }

        public string Description => "Counting rule";
        public Severity Severity => Severity.Low;
        public string RuleId => "CountingRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method,
            Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
        {
            AnalyzeInstructionsCallCount++;
            return new[] { new ScanFinding($"{method.DeclaringType?.FullName}.{method.Name}", "counted", Severity.Low) };
        }
    }

    private sealed class CapturingSuppressionRule : IScanRule
    {
        public int ObservedExceptionHandlerCount { get; private set; }

        public string Description => "Capturing suppression rule";
        public Severity Severity => Severity.High;
        public string RuleId => "CapturingSuppressionRule";
        public bool RequiresCompanionFinding => false;
        public bool IsSuspicious(MethodReference method) => method.Name == "Target";

        public bool ShouldSuppressFinding(
            MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions,
            int instructionIndex,
            MethodSignals methodSignals,
            MethodSignals? typeSignals = null)
        {
            ObservedExceptionHandlerCount = methodSignals.ExceptionHandlers.Count;
            return true;
        }
    }

    private sealed class NamedCallRule : IScanRule
    {
        private readonly string _methodName;

        public NamedCallRule(string ruleId, string methodName, bool requiresCompanionFinding)
        {
            RuleId = ruleId;
            _methodName = methodName;
            RequiresCompanionFinding = requiresCompanionFinding;
        }

        public string Description => $"Named call: {_methodName}";
        public Severity Severity => Severity.High;
        public string RuleId { get; }
        public bool RequiresCompanionFinding { get; }
        public bool IsSuspicious(MethodReference method) => method.Name == _methodName;
    }

    private sealed class ContextualNamedCallRule : IScanRule
    {
        private readonly string _methodName;

        public ContextualNamedCallRule(string ruleId, string methodName)
        {
            RuleId = ruleId;
            _methodName = methodName;
        }

        public string Description => $"Contextual named call: {_methodName}";
        public Severity Severity => Severity.High;
        public string RuleId { get; }
        public bool RequiresCompanionFinding => true;
        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference calledMethod,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals)
        {
            return calledMethod.Name == _methodName
                ? new[] { new ScanFinding("Test.Type.Run", Description, Severity) { RuleId = RuleId } }
                : Enumerable.Empty<ScanFinding>();
        }
    }
}
