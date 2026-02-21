using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class CallGraphBuilderTests
{
    private class TestRule : IScanRule
    {
        public string RuleId => "TestRule";
        public string Description => "Test rule for call graph";
        public Severity Severity => Severity.High;
        public bool RequiresCompanionFinding => false;
        public IDeveloperGuidance? DeveloperGuidance => null;

        public bool IsSuspicious(MethodReference method) => false;
    }

    private MethodDefinition CreateTestMethod(string typeName, string methodName)
    {
        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();
        var type = new TypeDefinition("TestNamespace", typeName, TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition(methodName, MethodAttributes.Public, assembly.MainModule.TypeSystem.Void);
        type.Methods.Add(method);

        return method;
    }

    [Fact]
    public void Constructor_WithNullRules_ThrowsArgumentNullException()
    {
        var snippetBuilder = new CodeSnippetBuilder();

        var act = () => new CallGraphBuilder(null!, snippetBuilder);

        act.Should().Throw<ArgumentNullException>().WithParameterName("rules");
    }

    [Fact]
    public void Constructor_WithNullSnippetBuilder_ThrowsArgumentNullException()
    {
        var rules = new List<IScanRule> { new TestRule() };

        var act = () => new CallGraphBuilder(rules, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("snippetBuilder");
    }

    [Fact]
    public void Clear_RemovesAllTrackedData()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");
        builder.RegisterSuspiciousDeclaration(method, rules[0], "code", "description");

        builder.Clear();

        builder.SuspiciousDeclarationCount.Should().Be(0);
        builder.CallSiteCount.Should().Be(0);
    }

    [Fact]
    public void RegisterSuspiciousDeclaration_IncrementsCount()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");

        builder.RegisterSuspiciousDeclaration(method, rules[0], "code snippet", "Test description");

        builder.SuspiciousDeclarationCount.Should().Be(1);
    }

    [Fact]
    public void RegisterSuspiciousDeclaration_SameMethodTwice_OnlyRegistersOnce()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");

        builder.RegisterSuspiciousDeclaration(method, rules[0], "code1", "desc1");
        builder.RegisterSuspiciousDeclaration(method, rules[0], "code2", "desc2");

        builder.SuspiciousDeclarationCount.Should().Be(1);
    }

    [Fact]
    public void RegisterCallSite_IncrementsCount()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var callerMethod = CreateTestMethod("CallerType", "CallerMethod");
        var calledMethod = CreateTestMethod("CalleeType", "CalleeMethod");

        builder.RegisterCallSite(callerMethod, calledMethod, 10, "call snippet");

        builder.CallSiteCount.Should().Be(1);
    }

    [Fact]
    public void RegisterCallSite_SameCallSiteTwice_OnlyRegistersOnce()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var callerMethod = CreateTestMethod("CallerType", "CallerMethod");
        var calledMethod = CreateTestMethod("CalleeType", "CalleeMethod");

        builder.RegisterCallSite(callerMethod, calledMethod, 10, "snippet1");
        builder.RegisterCallSite(callerMethod, calledMethod, 10, "snippet2");

        builder.CallSiteCount.Should().Be(1);
    }

    [Fact]
    public void RegisterCallSite_DifferentOffsets_RegistersBoth()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var callerMethod = CreateTestMethod("CallerType", "CallerMethod");
        var calledMethod = CreateTestMethod("CalleeType", "CalleeMethod");

        builder.RegisterCallSite(callerMethod, calledMethod, 10, "snippet1");
        builder.RegisterCallSite(callerMethod, calledMethod, 20, "snippet2");

        builder.CallSiteCount.Should().Be(2);
    }

    [Fact]
    public void IsSuspiciousMethod_NotRegistered_ReturnsFalse()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");

        builder.IsSuspiciousMethod(method).Should().BeFalse();
    }

    [Fact]
    public void IsSuspiciousMethod_Registered_ReturnsTrue()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");
        builder.RegisterSuspiciousDeclaration(method, rules[0], "code", "description");

        builder.IsSuspiciousMethod(method).Should().BeTrue();
    }

    [Fact]
    public void BuildCallChainFindings_NoDeclarations_ReturnsEmpty()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var findings = builder.BuildCallChainFindings();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void BuildCallChainFindings_DeclarationWithoutCalls_CreatesStandaloneFinding()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "SuspiciousMethod");
        builder.RegisterSuspiciousDeclaration(method, rules[0], "code", "P/Invoke declaration");

        var findings = builder.BuildCallChainFindings().ToList();

        findings.Should().HaveCount(1);
        findings[0].Description.Should().Contain("no callers detected");
    }

    [Fact]
    public void BuildCallChainFindings_DeclarationWithCalls_CreatesCallChainFinding()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var suspiciousMethod = CreateTestMethod("MaliciousType", "DangerousMethod");
        var callerMethod = CreateTestMethod("CallerType", "InnocentMethod");

        builder.RegisterSuspiciousDeclaration(suspiciousMethod, rules[0], "dangerous code", "P/Invoke declaration");
        builder.RegisterCallSite(callerMethod, suspiciousMethod, 42, "call snippet");

        var findings = builder.BuildCallChainFindings().ToList();

        findings.Should().HaveCount(1);
        findings[0].CallChain.Should().NotBeNull();
        findings[0].CallChain!.Nodes.Should().HaveCount(2);
    }

    [Fact]
    public void BuildCallChainFindings_MultipleCalls_IncludesAllCallSites()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var suspiciousMethod = CreateTestMethod("MaliciousType", "DangerousMethod");
        var caller1 = CreateTestMethod("Caller1", "Method1");
        var caller2 = CreateTestMethod("Caller2", "Method2");

        builder.RegisterSuspiciousDeclaration(suspiciousMethod, rules[0], "dangerous code", "P/Invoke declaration");
        builder.RegisterCallSite(caller1, suspiciousMethod, 10, "call1");
        builder.RegisterCallSite(caller2, suspiciousMethod, 20, "call2");

        var findings = builder.BuildCallChainFindings().ToList();

        findings.Should().HaveCount(1);
        findings[0].CallChain.Should().NotBeNull();
        findings[0].CallChain!.Nodes.Should().HaveCount(3); // 2 callers + 1 suspicious declaration
    }

    [Fact]
    public void BuildCallChainFindings_SetsRuleMetadata()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");
        builder.RegisterSuspiciousDeclaration(method, rules[0], "code", "description");

        var findings = builder.BuildCallChainFindings().ToList();

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("TestRule");
    }

    [Fact]
    public void IsLikelyEntryPoint_MelonLoaderMethod_ReturnsTrue()
    {
        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();
        var type = new TypeDefinition("Test", "TestMod", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("OnMelonAwake", MethodAttributes.Public, assembly.MainModule.TypeSystem.Void);
        type.Methods.Add(method);

        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var suspiciousMethod = CreateTestMethod("Test", "Suspicious");
        builder.RegisterSuspiciousDeclaration(suspiciousMethod, rules[0], "code", "desc");
        builder.RegisterCallSite(method, suspiciousMethod, 0, "snippet");

        var findings = builder.BuildCallChainFindings().ToList();
        findings[0].CallChain!.Nodes[0].Description.Should().Contain("Entry point");
    }

    [Fact]
    public void IsLikelyEntryPoint_UnityMethod_ReturnsTrue()
    {
        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();
        var type = new TypeDefinition("Test", "TestBehaviour", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("Awake", MethodAttributes.Public, assembly.MainModule.TypeSystem.Void);
        type.Methods.Add(method);

        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var suspiciousMethod = CreateTestMethod("Test", "Suspicious");
        builder.RegisterSuspiciousDeclaration(suspiciousMethod, rules[0], "code", "desc");
        builder.RegisterCallSite(method, suspiciousMethod, 0, "snippet");

        var findings = builder.BuildCallChainFindings().ToList();
        findings[0].CallChain!.Nodes[0].Description.Should().Contain("Entry point");
    }

    [Fact]
    public void IsLikelyEntryPoint_StaticConstructor_ReturnsTrue()
    {
        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();
        var type = new TypeDefinition("Test", "TestClass", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition(".cctor", MethodAttributes.Static, assembly.MainModule.TypeSystem.Void);
        type.Methods.Add(method);

        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var graphBuilder = new CallGraphBuilder(rules, snippetBuilder);

        var suspiciousMethod = CreateTestMethod("Test", "Suspicious");
        graphBuilder.RegisterSuspiciousDeclaration(suspiciousMethod, rules[0], "code", "desc");
        graphBuilder.RegisterCallSite(method, suspiciousMethod, 0, "snippet");

        var findings = graphBuilder.BuildCallChainFindings().ToList();
        findings[0].CallChain!.Nodes[0].Description.Should().Contain("Entry point");
    }

    [Fact]
    public void IsMethodSuspiciousByRule_RuleReturnsFalse_ReturnsFalse()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = MethodReferenceFactory.Create("Test.Type", "Method");

        builder.IsMethodSuspiciousByRule(method).Should().BeFalse();
    }

    [Fact]
    public void IsMethodSuspiciousByRule_RuleReturnsTrue_ReturnsTrue()
    {
        var suspiciousRule = new DllImportRule();
        var rules = new List<IScanRule> { suspiciousRule };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        // Create a P/Invoke method that the DllImportRule will flag
        var assemblyBuilder = TestAssemblyBuilder.Create();
        var assembly = assemblyBuilder.Build();
        var type = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class);
        assembly.MainModule.Types.Add(type);

        var method = new MethodDefinition("VirtualAlloc",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            assembly.MainModule.TypeSystem.IntPtr);

        var moduleRef = new ModuleReference("kernel32.dll");
        assembly.MainModule.ModuleReferences.Add(moduleRef);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "VirtualAlloc", moduleRef);
        type.Methods.Add(method);

        builder.IsMethodSuspiciousByRule(method).Should().BeTrue();
    }

    [Fact]
    public void SuspiciousDeclarationCount_InitiallyZero()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        builder.SuspiciousDeclarationCount.Should().Be(0);
    }

    [Fact]
    public void CallSiteCount_InitiallyZero()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        builder.CallSiteCount.Should().Be(0);
    }

    [Fact]
    public void BuildCallChainFindings_ProcessedDeclarationNotReprocessed()
    {
        var rules = new List<IScanRule> { new TestRule() };
        var snippetBuilder = new CodeSnippetBuilder();
        var builder = new CallGraphBuilder(rules, snippetBuilder);

        var method = CreateTestMethod("TestType", "TestMethod");
        builder.RegisterSuspiciousDeclaration(method, rules[0], "code", "description");

        var findings1 = builder.BuildCallChainFindings().ToList();
        var findings2 = builder.BuildCallChainFindings().ToList();

        findings1.Should().HaveCount(1);
        findings2.Should().HaveCount(1);
    }
}
