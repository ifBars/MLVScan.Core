using System.Linq;
using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class PropertyEventScannerTests
{
    [Fact]
    public void ScanProperties_WithGetterFinding_AddsPropertyContext()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true, EnableMultiSignalDetection = false };
        var scanner = new PropertyEventScanner(CreateMethodScanner(config), config);
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("PropertyScanner", new Version(1, 0, 0, 0)), "PropertyScanner", ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "HasProperty", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var getter = new MethodDefinition("get_Name", MethodAttributes.Public, module.TypeSystem.String);
        getter.Body = new MethodBody(getter);
        getter.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ldstr, "value"));
        getter.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(getter);

        var property = new PropertyDefinition("Name", PropertyAttributes.None, module.TypeSystem.String)
        {
            GetMethod = getter
        };
        type.Properties.Add(property);

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("found in property getter: Name");
    }

    [Fact]
    public void ScanEvents_WithAddHandlerFinding_AddsEventContext()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true, EnableMultiSignalDetection = false };
        var scanner = new PropertyEventScanner(CreateMethodScanner(config), config);
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("EventScanner", new Version(1, 0, 0, 0)), "EventScanner", ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "HasEvent", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var addMethod = new MethodDefinition("add_Clicked", MethodAttributes.Public, module.TypeSystem.Void);
        addMethod.Body = new MethodBody(addMethod);
        addMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(addMethod);

        var eventType = new TypeReference("System", "EventHandler", module, module.TypeSystem.CoreLibrary);
        var evt = new EventDefinition("Clicked", EventAttributes.None, eventType)
        {
            AddMethod = addMethod
        };
        type.Events.Add(evt);

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("found in event add: Clicked");
    }

    private static MethodScanner CreateMethodScanner(ScanConfig config)
    {
        var rules = new IScanRule[] { new AlwaysFindingRule() };
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, config, null);
        return new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, localVariableAnalyzer, exceptionHandlerAnalyzer, config);
    }

    private sealed class AlwaysFindingRule : IScanRule
    {
        public string Description => "Always finding";
        public Severity Severity => Severity.Medium;
        public string RuleId => "AlwaysFindingRule";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> AnalyzeInstructions(MethodDefinition method, Mono.Collections.Generic.Collection<Instruction> instructions, MethodSignals methodSignals)
            => new[] { new ScanFinding($"{method.DeclaringType?.FullName}.{method.Name}", "base finding", Severity.Medium, "snippet") };
    }
}
