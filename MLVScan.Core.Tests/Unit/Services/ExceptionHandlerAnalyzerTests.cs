using FluentAssertions;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class ExceptionHandlerAnalyzerTests
{
    [Fact]
    public void Constructor_WithNullRules_ThrowsArgumentNullException()
    {
        var config = new ScanConfig();
        var tracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();

        var act = () => new ExceptionHandlerAnalyzer(null!, tracker, snippetBuilder, config);

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("rules");
    }

    [Fact]
    public void AnalyzeExceptionHandlers_WhenDisabled_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzeExceptionHandlers = false };
        var tracker = new SignalTracker(config);
        var analyzer = new ExceptionHandlerAnalyzer(new[] { new ExceptionRuleStub() }, tracker, new CodeSnippetBuilder(), config);
        var method = CreateMethodWithCatchCalling("System.Diagnostics.Process", "Start");

        var findings = analyzer.AnalyzeExceptionHandlers(method, method.Body.ExceptionHandlers, new MethodSignals(), method.DeclaringType!.FullName);

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeExceptionHandlers_WithSuspiciousCatchCall_AddsFindingAndMarksSignals()
    {
        var config = new ScanConfig { AnalyzeExceptionHandlers = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var analyzer = new ExceptionHandlerAnalyzer(new[] { new ExceptionRuleStub() }, tracker, new CodeSnippetBuilder(), config);
        var method = CreateMethodWithCatchCalling("System.Diagnostics.Process", "Start");
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeExceptionHandlers(method, method.Body.ExceptionHandlers, methodSignals, method.DeclaringType!.FullName).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("exception catch block");
        methodSignals.HasSuspiciousExceptionHandling.Should().BeTrue();
        methodSignals.HasTriggeredRuleOtherThan("SomeOtherRule").Should().BeTrue();
    }

    [Fact]
    public void AnalyzeExceptionHandlers_WithUncorrelatedPathLoad_RetainsLowContextualFinding()
    {
        var config = new ScanConfig { AnalyzeExceptionHandlers = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var analyzer = new ExceptionHandlerAnalyzer([new AssemblyDynamicLoadRule()], tracker,
            new CodeSnippetBuilder(), config);
        var method = CreateMethodWithCatchLoadingPath();

        var findings = analyzer.AnalyzeExceptionHandlers(method, method.Body.ExceptionHandlers,
            new MethodSignals(), method.DeclaringType!.FullName).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("AssemblyDynamicLoadRule");
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("exception catch block");
    }

    [Fact]
    public void AnalyzeExceptionHandlers_WithSuspiciousDownload_PropagatesReflectionCompanionSignal()
    {
        var config = new ScanConfig { AnalyzeExceptionHandlers = true, EnableMultiSignalDetection = true };
        var tracker = new SignalTracker(config);
        var analyzer = new ExceptionHandlerAnalyzer([new DataInfiltrationRule()], tracker,
            new CodeSnippetBuilder(), config);
        var method = CreateMethodWithCatchSuspiciousDownload();
        var methodSignals = new MethodSignals();

        var findings = analyzer.AnalyzeExceptionHandlers(method, method.Body.ExceptionHandlers,
            methodSignals, method.DeclaringType!.FullName).ToList();

        findings.Should().BeEmpty("the companion-gated download finding is not independently emitted");
        methodSignals.HasSuspiciousNetworkDownload.Should().BeTrue();
        tracker.GetTypeSignals(method.DeclaringType.FullName)!.HasSuspiciousNetworkDownload.Should().BeTrue();
    }

    private static MethodDefinition CreateMethodWithCatchCalling(string calledType, string calledMethod)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ExceptionUnitTestAssembly", new Version(1, 0, 0, 0)),
            "ExceptionUnitTestModule",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var type = new TypeDefinition("Test", "ExceptionType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();

        var ret = il.Create(OpCodes.Ret);
        var tryStart = il.Create(OpCodes.Nop);
        var tryEnd = il.Create(OpCodes.Leave_S, ret);
        var handlerStart = il.Create(OpCodes.Pop);
        var handlerEnd = il.Create(OpCodes.Leave_S, ret);

        il.Append(tryStart);
        il.Append(il.Create(OpCodes.Nop));
        il.Append(tryEnd);

        il.Append(handlerStart);

        var typeRef = new TypeReference(
            calledType[..calledType.LastIndexOf('.')],
            calledType[(calledType.LastIndexOf('.') + 1)..],
            module,
            module.TypeSystem.CoreLibrary);
        var methodRef = new MethodReference(calledMethod, module.TypeSystem.Void, typeRef);
        il.Append(il.Create(OpCodes.Call, methodRef));

        il.Append(handlerEnd);
        il.Append(ret);

        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = ret,
            CatchType = module.ImportReference(typeof(Exception))
        });

        return method;
    }

    private static MethodDefinition CreateMethodWithCatchLoadingPath()
    {
        var method = CreateMethodWithCatchCalling("System.Reflection.Assembly", "LoadFrom");
        var call = method.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Call && i.Operand is MethodReference reference && reference.Name == "LoadFrom");
        var loadFrom = (MethodReference)call.Operand;
        loadFrom.ReturnType = new TypeReference("System.Reflection", "Assembly", method.Module,
            method.Module.TypeSystem.CoreLibrary);
        loadFrom.Parameters.Add(new ParameterDefinition(method.Module.TypeSystem.String));
        var il = method.Body.GetILProcessor();
        il.InsertBefore(call, il.Create(OpCodes.Ldstr, "Plugins\\OptionalDependency.dll"));
        il.InsertAfter(call, il.Create(OpCodes.Pop));
        return method;
    }

    private static MethodDefinition CreateMethodWithCatchSuspiciousDownload()
    {
        var method = CreateMethodWithCatchCalling("System.Net.WebClient", "DownloadString");
        var call = method.Body.Instructions.Single(i =>
            i.OpCode == OpCodes.Call && i.Operand is MethodReference reference && reference.Name == "DownloadString");
        var downloadString = (MethodReference)call.Operand;
        downloadString.ReturnType = method.Module.TypeSystem.String;
        downloadString.Parameters.Add(new ParameterDefinition(method.Module.TypeSystem.String));
        var il = method.Body.GetILProcessor();
        il.InsertBefore(call, il.Create(OpCodes.Ldstr, "https://pastebin.com/raw/example"));
        il.InsertAfter(call, il.Create(OpCodes.Pop));
        return method;
    }

    private sealed class ExceptionRuleStub : IScanRule
    {
        public string Description => "Suspicious method call detected";
        public Severity Severity => Severity.High;
        public string RuleId => "ExceptionRuleStub";
        public bool RequiresCompanionFinding => false;

        public bool IsSuspicious(MethodReference method)
            => method.DeclaringType?.FullName == "System.Diagnostics.Process" && method.Name == "Start";
    }
}
