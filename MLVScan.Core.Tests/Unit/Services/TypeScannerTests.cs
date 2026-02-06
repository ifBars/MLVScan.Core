using System.Linq;
using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class TypeScannerTests
{
    [Fact]
    public void ScanType_WithPendingReflectionAndTypeLevelTrigger_AddsCombinedReflectionFinding()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true, AnalyzePropertyAccessors = false };
        var rules = new IScanRule[] { new ReflectionRule(), new ProcessStartRule() };

        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, config, null);
        var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, localVariableAnalyzer, exceptionHandlerAnalyzer, config);
        var propertyEventScanner = new PropertyEventScanner(methodScanner, config);
        var typeScanner = new TypeScanner(methodScanner, signalTracker, reflectionDetector, snippetBuilder, propertyEventScanner, rules, config);

        var type = CreateTypeWithReflectionAndProcessMethods();

        var findings = typeScanner.ScanType(type).ToList();

        findings.Any(f => f.Description.Contains("combined with other suspicious patterns detected in this type")).Should().BeTrue();
        signalTracker.GetTypeSignals(type.FullName).Should().BeNull();
    }

    [Fact]
    public void ScanType_RecursivelyScansNestedTypes()
    {
        var config = new ScanConfig { EnableMultiSignalDetection = true, AnalyzePropertyAccessors = false };
        var rules = new IScanRule[] { new ProcessStartRule() };

        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, stringPatternDetector, snippetBuilder, config, null);
        var methodScanner = new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, localVariableAnalyzer, exceptionHandlerAnalyzer, config);
        var propertyEventScanner = new PropertyEventScanner(methodScanner, config);
        var typeScanner = new TypeScanner(methodScanner, signalTracker, reflectionDetector, snippetBuilder, propertyEventScanner, rules, config);

        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("NestedTypeScan", new Version(1, 0, 0, 0)), "NestedTypeScan", ModuleKind.Dll);
        var module = assembly.MainModule;
        var outer = new TypeDefinition("Test", "Outer", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(outer);
        var nested = new TypeDefinition("Test", "Inner", TypeAttributes.NestedPublic | TypeAttributes.Class, module.TypeSystem.Object);
        outer.NestedTypes.Add(nested);

        var nestedMethod = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        nestedMethod.Body = new MethodBody(nestedMethod);
        var processType = new TypeReference("System.Diagnostics", "Process", module, module.TypeSystem.CoreLibrary);
        var processStart = new MethodReference("Start", module.TypeSystem.Void, processType);
        nestedMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Call, processStart));
        nestedMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        nested.Methods.Add(nestedMethod);

        var findings = typeScanner.ScanType(outer).ToList();

        findings.Should().NotBeEmpty();
        findings.Any(f => f.Location.Contains("Inner.Run")).Should().BeTrue();
    }

    private static TypeDefinition CreateTypeWithReflectionAndProcessMethods()
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("TypeScan", new Version(1, 0, 0, 0)), "TypeScan", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "ScanType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var reflectMethod = new MethodDefinition("Reflect", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        reflectMethod.Body = new MethodBody(reflectMethod);
        var methodInfoType = new TypeReference("System.Reflection", "MethodInfo", module, module.TypeSystem.CoreLibrary);
        var invokeRef = new MethodReference("Invoke", module.TypeSystem.Object, methodInfoType);
        reflectMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Call, invokeRef));
        reflectMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(reflectMethod);

        var processMethod = new MethodDefinition("Execute", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        processMethod.Body = new MethodBody(processMethod);
        var processType = new TypeReference("System.Diagnostics", "Process", module, module.TypeSystem.CoreLibrary);
        var startRef = new MethodReference("Start", module.TypeSystem.Void, processType);
        processMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Call, startRef));
        processMethod.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        type.Methods.Add(processMethod);

        return type;
    }
}
