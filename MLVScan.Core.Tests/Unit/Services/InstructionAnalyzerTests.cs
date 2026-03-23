using FluentAssertions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class InstructionAnalyzerTests
{
    [Fact]
    public void AnalyzeInstructions_WithMatchingDirectRule_CallsIsSuspiciousOnce()
    {
        var config = new ScanConfig();
        var rule = new CountingSuspiciousRule(matchMethodName: "InvokePayload");
        var analyzer = CreateAnalyzer(config, new IScanRule[] { rule });
        var method = CreateMethodCalling("InvokePayload");

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals(),
            method.DeclaringType!.FullName);

        result.Findings.Should().ContainSingle();
        result.Findings[0].RuleId.Should().Be("CountingSuspiciousRule");
        rule.IsSuspiciousCallCount.Should().Be(1);
    }

    [Fact]
    public void AnalyzeInstructions_UsesFirstMatchingRuleWithoutDoubleEvaluatingLaterRules()
    {
        var config = new ScanConfig();
        var firstRule = new CountingSuspiciousRule(matchMethodName: "InvokePayload", ruleId: "FirstRule");
        var secondRule = new CountingSuspiciousRule(matchMethodName: "InvokePayload", ruleId: "SecondRule");
        var analyzer = CreateAnalyzer(config, new IScanRule[] { firstRule, secondRule });
        var method = CreateMethodCalling("InvokePayload");

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals(),
            method.DeclaringType!.FullName);

        result.Findings.Should().ContainSingle();
        result.Findings[0].RuleId.Should().Be("FirstRule");
        firstRule.IsSuspiciousCallCount.Should().Be(1);
        secondRule.IsSuspiciousCallCount.Should().Be(0);
    }

    [Fact]
    public void AnalyzeInstructions_WhenFirstRuleDoesNotMatch_EvaluatesSecondRuleOnce()
    {
        var config = new ScanConfig();
        var firstRule = new CountingSuspiciousRule(matchMethodName: "SomethingElse", ruleId: "FirstRule");
        var secondRule = new CountingSuspiciousRule(matchMethodName: "InvokePayload", ruleId: "SecondRule");
        var analyzer = CreateAnalyzer(config, new IScanRule[] { firstRule, secondRule });
        var method = CreateMethodCalling("InvokePayload");

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals(),
            method.DeclaringType!.FullName);

        result.Findings.Should().ContainSingle();
        result.Findings[0].RuleId.Should().Be("SecondRule");
        firstRule.IsSuspiciousCallCount.Should().Be(1);
        secondRule.IsSuspiciousCallCount.Should().Be(1);
    }

    [Fact]
    public void AnalyzeInstructions_PreservesDirectFindingWhenSameRuleAlsoProducesContextualFinding()
    {
        var config = new ScanConfig();
        var rule = new CountingContextualAndDirectRule(matchMethodName: "InvokePayload", emitContextualFinding: true);
        var analyzer = CreateAnalyzer(config, new IScanRule[] { rule });
        var method = CreateMethodCalling("InvokePayload");

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals(),
            method.DeclaringType!.FullName);

        result.Findings.Should().HaveCount(2);
        result.Findings.Select(f => f.Description).Should().Contain(new[] { "contextual", "Matched InvokePayload" });
        rule.IsSuspiciousCallCount.Should().Be(1);
        rule.ContextualCallCount.Should().Be(1);
    }

    [Fact]
    public void AnalyzeInstructions_StillCreatesDirectFindingWhenContextualRuleReturnsNoFindings()
    {
        var config = new ScanConfig();
        var rule = new CountingContextualAndDirectRule(matchMethodName: "InvokePayload", emitContextualFinding: false);
        var analyzer = CreateAnalyzer(config, new IScanRule[] { rule });
        var method = CreateMethodCalling("InvokePayload");

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals(),
            method.DeclaringType!.FullName);

        result.Findings.Should().ContainSingle();
        result.Findings[0].Description.Should().Be("Matched InvokePayload");
        rule.IsSuspiciousCallCount.Should().Be(1);
        rule.ContextualCallCount.Should().Be(1);
    }

    [Fact]
    public void AnalyzeInstructions_WithNullMethodSignals_ProvidesNonNullSignalBagToRuleCallbacks()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = false };
        var rule = new NullSafeContextualRule();
        var analyzer = CreateAnalyzer(config, new IScanRule[] { rule });
        var method = CreateMethodCalling("InvokePayload");

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, null, method.DeclaringType!.FullName);

        result.Findings.Should().ContainSingle();
        rule.ContextualReceivedNull.Should().BeFalse();
        rule.SuppressReceivedNull.Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_WithoutReflectionRule_StillRunsReflectionBypassDetector()
    {
        var config = new ScanConfig();
        var analyzer = CreateAnalyzer(config, new IScanRule[] { new ProcessStartRule() });
        var method = CreateReflectionInvokeMethodWithSuspiciousStrings();
        var methodSignals = new MethodSignals
        {
            HasProcessLikeCall = true
        };

        var result = analyzer.AnalyzeInstructions(method, method.Body.Instructions, methodSignals,
            method.DeclaringType!.FullName);

        result.Findings.Should().ContainSingle();
        result.Findings[0].Description.Should().Contain("reflection bypass");
        result.Findings[0].RuleId.Should().Be("ProcessStartRule");
    }

    private static InstructionAnalyzer CreateAnalyzer(ScanConfig config, IEnumerable<IScanRule> rules)
    {
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        return new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector,
            snippetBuilder, config, null);
    }

    private static MethodDefinition CreateMethodCalling(string calledMethodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("InstructionAnalyzerTest", new Version(1, 0, 0, 0)),
            "InstructionAnalyzerTest",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Type", TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        var calledType = new TypeReference("Test", "Target", module, module.TypeSystem.CoreLibrary);
        var calledMethod = new MethodReference(calledMethodName, module.TypeSystem.Void, calledType);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Call, calledMethod));
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);

        return method;
    }

    private static MethodDefinition CreateReflectionInvokeMethodWithSuspiciousStrings()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("InstructionAnalyzerReflectionTest", new Version(1, 0, 0, 0)),
            "InstructionAnalyzerReflectionTest",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "ReflectionType", TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        var methodInfoType = new TypeReference("System.Reflection", "MethodInfo", module, module.TypeSystem.CoreLibrary);
        var invokeMethod = new MethodReference("Invoke", module.TypeSystem.Object, methodInfoType);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ldstr, "Start"));
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Call, invokeMethod));
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(method);

        return method;
    }

    private sealed class CountingSuspiciousRule : IScanRule
    {
        private readonly string _matchMethodName;

        public CountingSuspiciousRule(string matchMethodName, string ruleId = "CountingSuspiciousRule")
        {
            _matchMethodName = matchMethodName;
            RuleId = ruleId;
        }

        public int IsSuspiciousCallCount { get; private set; }

        public string Description => "Counting suspicious rule";
        public Severity Severity => Severity.Medium;
        public string RuleId { get; }
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            IsSuspiciousCallCount++;
            return method.Name == _matchMethodName;
        }

        public string GetFindingDescription(MethodDefinition containingMethod, MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex)
        {
            return $"Matched {method.Name}";
        }
    }

    private sealed class CountingContextualAndDirectRule : IScanRule
    {
        private readonly string _matchMethodName;
        private readonly bool _emitContextualFinding;

        public CountingContextualAndDirectRule(string matchMethodName, bool emitContextualFinding)
        {
            _matchMethodName = matchMethodName;
            _emitContextualFinding = emitContextualFinding;
        }

        public int IsSuspiciousCallCount { get; private set; }
        public int ContextualCallCount { get; private set; }

        public string Description => "Counting contextual rule";
        public Severity Severity => Severity.Medium;
        public string RuleId => "CountingContextualRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
        {
            IsSuspiciousCallCount++;
            return method.Name == _matchMethodName;
        }

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals)
        {
            ContextualCallCount++;

            if (!_emitContextualFinding || method.Name != _matchMethodName)
            {
                return Enumerable.Empty<ScanFinding>();
            }

            return new[] { new ScanFinding("context", "contextual", Severity.Medium) };
        }

        public string GetFindingDescription(MethodDefinition containingMethod, MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex)
        {
            return $"Matched {method.Name}";
        }
    }

    private sealed class NullSafeContextualRule : IScanRule
    {
        public bool ContextualReceivedNull { get; private set; }
        public bool SuppressReceivedNull { get; private set; }

        public string Description => "Null-safe contextual rule";
        public Severity Severity => Severity.Medium;
        public string RuleId => "NullSafeContextualRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method) => method.Name == "InvokePayload";

        public IEnumerable<ScanFinding> AnalyzeContextualPattern(MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex,
            MethodSignals methodSignals)
        {
            ContextualReceivedNull = methodSignals == null;
            return Enumerable.Empty<ScanFinding>();
        }

        public bool ShouldSuppressFinding(MethodReference method,
            Mono.Collections.Generic.Collection<Instruction> instructions, int instructionIndex, MethodSignals methodSignals,
            MethodSignals? typeSignals = null)
        {
            SuppressReceivedNull = methodSignals == null;
            return false;
        }
    }
}
