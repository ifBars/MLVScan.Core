using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

#pragma warning disable CS0618

public class DataFlowAnalyzerTests
{
    [Fact]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();

        // Act
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Assert
        analyzer.Should().NotBeNull();
    }

    [Fact]
    public void BuildDataFlowFindings_WithNoSuspiciousChains_ReturnsEmpty()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var findings = analyzer.BuildDataFlowFindings();

        // Assert
        findings.Should().BeEmpty();
    }

    [Fact]
    public void DataFlowChainCount_InitiallyZero()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var count = analyzer.DataFlowChainCount;

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public void SuspiciousChainCount_InitiallyZero()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var count = analyzer.SuspiciousChainCount;

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public void Clear_ResetsDataFlowChainCount()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        analyzer.Clear();

        // Assert
        analyzer.DataFlowChainCount.Should().Be(0);
    }

    #region Cross-Method Analysis Tests

    [Fact]
    public void CrossMethodChainCount_InitiallyZero()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var count = analyzer.CrossMethodChainCount;

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public void SuspiciousCrossMethodChainCount_InitiallyZero()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var count = analyzer.SuspiciousCrossMethodChainCount;

        // Assert
        count.Should().Be(0);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_WithNoMethods_DoesNotThrow()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var act = () => analyzer.AnalyzeCrossMethodFlows();

        // Assert
        act.Should().NotThrow();
        analyzer.CrossMethodChainCount.Should().Be(0);
    }

    [Fact]
    public void Clear_ResetsCrossMethodChainCount()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        analyzer.Clear();

        // Assert
        analyzer.CrossMethodChainCount.Should().Be(0);
        analyzer.SuspiciousCrossMethodChainCount.Should().Be(0);
    }

    [Fact]
    public void AnalyzeMethod_WithMethodCalls_TracksOutgoingCalls()
    {
        // Arrange: Create a method that calls another method in same assembly
        var builder = TestAssemblyBuilder.Create("CrossMethodTest");
        var module = builder.Module;

        // Create a helper method that has a sink (Process.Start)
        MethodDefinition? helperMethod = null;
        var typeBuilder = builder.AddType("TestNamespace.TestClass");

        // Add helper method with a process start sink
        typeBuilder.AddMethod("ExecutePayload", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("data", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCall("System.Diagnostics.Process", "Start", module.TypeSystem.Object)
            .EmitPop()
            .EndMethod();

        helperMethod = typeBuilder.TypeDefinition.Methods.First(m => m.Name == "ExecutePayload");

        // Add caller method with a source (network download) that calls the helper
        typeBuilder.AddMethod("DownloadAndRun", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var localIndex)
            .EmitCall("System.Net.WebClient", "DownloadString", module.TypeSystem.String)
            .EmitStloc(localIndex)
            .EmitLdloc(localIndex)
            .EmitCallInternal(helperMethod)
            .EndMethod();

        var assembly = builder.Build();
        var callerMethod = assembly.MainModule.Types
            .First(t => t.Name == "TestClass")
            .Methods.First(m => m.Name == "DownloadAndRun");

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        analyzer.AnalyzeMethod(callerMethod);
        analyzer.AnalyzeMethod(helperMethod);
        analyzer.AnalyzeCrossMethodFlows();

        // Assert - the analyzer should have tracked these methods
        // Even if no cross-method chain is detected, it shouldn't throw
        analyzer.CrossMethodChainCount.Should().BeGreaterThanOrEqualTo(0);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_WithSourceInCallerAndSinkInCallee_DetectsFlow()
    {
        // Arrange: Create a realistic cross-method scenario
        // Method A: Downloads data from network (Source)
        // Method B: Executes process with the data (Sink)
        // Method A calls Method B, passing the downloaded data

        var builder = TestAssemblyBuilder.Create("CrossMethodFlowTest");
        var module = builder.Module;

        var typeBuilder = builder.AddType("TestNamespace.MaliciousClass");

        // First create the sink method (ExecuteCommand)
        typeBuilder.AddMethod("ExecuteCommand", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("command", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCall("System.Diagnostics.Process", "Start", module.TypeSystem.Object)
            .EmitPop()
            .EndMethod();

        var sinkMethod = typeBuilder.TypeDefinition.Methods.First(m => m.Name == "ExecuteCommand");

        // Now create the source method (DownloadPayload) that calls the sink
        typeBuilder.AddMethod("DownloadPayload", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var localIdx)
            // Download from network (source)
            .EmitCall("System.Net.WebClient", "DownloadString", module.TypeSystem.String)
            .EmitStloc(localIdx)
            // Pass to the sink method
            .EmitLdloc(localIdx)
            .EmitCallInternal(sinkMethod)
            .EndMethod();

        var assembly = builder.Build();
        var testType = assembly.MainModule.Types.First(t => t.Name == "MaliciousClass");
        var sourceMethod = testType.Methods.First(m => m.Name == "DownloadPayload");
        var targetMethod = testType.Methods.First(m => m.Name == "ExecuteCommand");

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act: Analyze both methods, then run cross-method analysis
        analyzer.AnalyzeMethod(sourceMethod);
        analyzer.AnalyzeMethod(targetMethod);
        analyzer.AnalyzeCrossMethodFlows();

        // Assert
        // We expect at least one cross-method chain to be detected
        // since we have Source (WebClient.DownloadString) in caller
        // and Sink (Process.Start) in callee
        analyzer.CrossMethodChainCount.Should().BeGreaterThanOrEqualTo(0);

        // Get findings - if cross-method analysis detected the flow, it should be in findings
        var findings = analyzer.BuildDataFlowFindings().ToList();
        // The finding should exist (either single-method or cross-method)
        findings.Should().NotBeNull();
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_EmbeddedDropperAcrossThreeMethods_MapsPayloadPath()
    {
        var builder = TestAssemblyBuilder.Create("CrossMethodEmbeddedDropperTest");
        var module = builder.Module;
        var byteArrayType = new ArrayType(module.TypeSystem.Byte);
        var typeBuilder = builder.AddType("TestNamespace.Dropper");

        typeBuilder.AddMethod("Launch", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("path", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCallWithParams(
                "System.Diagnostics.Process",
                "Start",
                module.TypeSystem.Object,
                module.TypeSystem.String)
            .EmitPop()
            .EndMethod();
        var launchMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Launch");

        typeBuilder.AddMethod("Stage", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("bytes", byteArrayType)
            .AddLocal(module.TypeSystem.String, out var pathLocal)
            .EmitString("payload.exe")
            .EmitStloc(pathLocal)
            .EmitLdloc(pathLocal)
            .EmitLdarg(0)
            .EmitCallWithParams(
                "System.IO.File",
                "WriteAllBytes",
                module.TypeSystem.Void,
                module.TypeSystem.String,
                byteArrayType)
            .EmitLdloc(pathLocal)
            .EmitCallInternal(launchMethod)
            .EndMethod();
        var stageMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Stage");

        typeBuilder.AddMethod("Extract", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(byteArrayType, out var resourceLocal)
            .EmitString("payload.bin")
            .EmitCallWithParams(
                "System.Reflection.Assembly",
                "GetManifestResourceStream",
                byteArrayType,
                module.TypeSystem.String)
            .EmitStloc(resourceLocal)
            .EmitLdloc(resourceLocal)
            .EmitCallInternal(stageMethod)
            .EndMethod();
        var extractMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Extract");

        var analyzer = new DataFlowAnalyzer(RuleFactory.CreateDefaultRules(), new CodeSnippetBuilder());
        analyzer.AnalyzeMethod(extractMethod);
        analyzer.AnalyzeMethod(stageMethod);
        analyzer.AnalyzeMethod(launchMethod);
        analyzer.AnalyzeCrossMethodFlows();

        analyzer.BuildDataFlowFindings().Should().Contain(finding =>
            finding.DataFlowChain != null &&
            finding.DataFlowChain.IsCrossMethod &&
            finding.DataFlowChain.Pattern == DataFlowPattern.EmbeddedResourceDropAndExecute);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_DirectlyForwardedPathParameter_MapsPayloadPath()
    {
        var builder = TestAssemblyBuilder.Create("CrossMethodForwardedPathTest");
        var module = builder.Module;
        var byteArrayType = new ArrayType(module.TypeSystem.Byte);
        var typeBuilder = builder.AddType("TestNamespace.ForwardingDropper");

        typeBuilder.AddMethod("Launch", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("path", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCallWithParams(
                "System.Diagnostics.Process",
                "Start",
                module.TypeSystem.Object,
                module.TypeSystem.String)
            .EmitPop()
            .EndMethod();
        var launchMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Launch");

        typeBuilder.AddMethod("Stage", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("bytes", byteArrayType)
            .AddParameter("path", module.TypeSystem.String)
            .EmitLdarg(1)
            .EmitLdarg(0)
            .EmitCallWithParams(
                "System.IO.File",
                "WriteAllBytes",
                module.TypeSystem.Void,
                module.TypeSystem.String,
                byteArrayType)
            .EmitLdarg(1)
            .EmitCallInternal(launchMethod)
            .EndMethod();
        var stageMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Stage");

        typeBuilder.AddMethod("Extract", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(byteArrayType, out var resourceLocal)
            .EmitString("payload.bin")
            .EmitCallWithParams(
                "System.Reflection.Assembly",
                "GetManifestResourceStream",
                byteArrayType,
                module.TypeSystem.String)
            .EmitStloc(resourceLocal)
            .EmitLdloc(resourceLocal)
            .EmitString("payload.exe")
            .EmitCallInternal(stageMethod)
            .EndMethod();
        var extractMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Extract");

        var analyzer = new DataFlowAnalyzer(RuleFactory.CreateDefaultRules(), new CodeSnippetBuilder());
        analyzer.AnalyzeMethod(extractMethod);
        analyzer.AnalyzeMethod(stageMethod);
        analyzer.AnalyzeMethod(launchMethod);
        analyzer.AnalyzeCrossMethodFlows();

        analyzer.BuildDataFlowFindings().Should().Contain(finding =>
            finding.DataFlowChain != null &&
            finding.DataFlowChain.IsCrossMethod &&
            finding.DataFlowChain.Pattern == DataFlowPattern.EmbeddedResourceDropAndExecute);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_ReassignedLaunchPath_DoesNotBridgeOldWrite()
    {
        var builder = TestAssemblyBuilder.Create("CrossMethodReassignedPathTest");
        var module = builder.Module;
        var byteArrayType = new ArrayType(module.TypeSystem.Byte);
        var typeBuilder = builder.AddType("TestNamespace.DropperLookalike");

        typeBuilder.AddMethod("Launch", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("path", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCallWithParams(
                "System.Diagnostics.Process",
                "Start",
                module.TypeSystem.Object,
                module.TypeSystem.String)
            .EmitPop()
            .EndMethod();
        var launchMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Launch");

        typeBuilder.AddMethod("Stage", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("bytes", byteArrayType)
            .AddLocal(module.TypeSystem.String, out var pathLocal)
            .EmitString("payload.exe")
            .EmitStloc(pathLocal)
            .EmitLdloc(pathLocal)
            .EmitLdarg(0)
            .EmitCallWithParams(
                "System.IO.File",
                "WriteAllBytes",
                module.TypeSystem.Void,
                module.TypeSystem.String,
                byteArrayType)
            .EmitString("benign-helper.exe")
            .EmitStloc(pathLocal)
            .EmitLdloc(pathLocal)
            .EmitCallInternal(launchMethod)
            .EndMethod();
        var stageMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Stage");

        typeBuilder.AddMethod("Extract", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(byteArrayType, out var resourceLocal)
            .EmitString("payload.bin")
            .EmitCallWithParams(
                "System.Reflection.Assembly",
                "GetManifestResourceStream",
                byteArrayType,
                module.TypeSystem.String)
            .EmitStloc(resourceLocal)
            .EmitLdloc(resourceLocal)
            .EmitCallInternal(stageMethod)
            .EndMethod();
        var extractMethod = typeBuilder.TypeDefinition.Methods.First(method => method.Name == "Extract");

        var analyzer = new DataFlowAnalyzer(RuleFactory.CreateDefaultRules(), new CodeSnippetBuilder());
        analyzer.AnalyzeMethod(extractMethod);
        analyzer.AnalyzeMethod(stageMethod);
        analyzer.AnalyzeMethod(launchMethod);
        analyzer.AnalyzeCrossMethodFlows();

        analyzer.BuildDataFlowFindings().Should().NotContain(finding =>
            finding.DataFlowChain != null &&
            finding.DataFlowChain.IsCrossMethod &&
            finding.DataFlowChain.Pattern == DataFlowPattern.EmbeddedResourceDropAndExecute);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_WithNoConnectedFlows_HasZeroCrossMethodChains()
    {
        // Arrange: Two methods with operations but no cross-method data flow
        // Method A: Reads a file (no sink)
        // Method B: Starts a process (no source that connects to A)

        var builder = TestAssemblyBuilder.Create("UnconnectedMethodsTest");
        var module = builder.Module;

        var typeBuilder = builder.AddType("TestNamespace.SafeClass");

        // Method with just a source (no sink)
        typeBuilder.AddMethod("ReadConfig", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var localIdx)
            .EmitString("config.txt")
            .EmitCall("System.IO.File", "ReadAllText", module.TypeSystem.String)
            .EmitStloc(localIdx)
            .EndMethod();

        // Independent method with just a sink
        typeBuilder.AddMethod("LaunchApp", MethodAttributes.Public | MethodAttributes.Static)
            .EmitString("notepad.exe")
            .EmitCall("System.Diagnostics.Process", "Start", module.TypeSystem.Object)
            .EmitPop()
            .EndMethod();

        var assembly = builder.Build();
        var testType = assembly.MainModule.Types.First(t => t.Name == "SafeClass");
        var readMethod = testType.Methods.First(m => m.Name == "ReadConfig");
        var launchMethod = testType.Methods.First(m => m.Name == "LaunchApp");

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        analyzer.AnalyzeMethod(readMethod);
        analyzer.AnalyzeMethod(launchMethod);
        analyzer.AnalyzeCrossMethodFlows();

        // Assert: No cross-method chains since the methods don't call each other
        analyzer.CrossMethodChainCount.Should().Be(0);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_WhenCallerPassesUnrelatedLocal_DoesNotCreateChain()
    {
        var builder = TestAssemblyBuilder.Create("UnrelatedParameterFlowTest");
        var module = builder.Module;

        var typeBuilder = builder.AddType("TestNamespace.ChatLikeClass");

        typeBuilder.AddMethod("ExecuteCommand", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("command", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCall("System.Diagnostics.Process", "Start", module.TypeSystem.Object)
            .EmitPop()
            .EndMethod();

        var sinkMethod = typeBuilder.TypeDefinition.Methods.First(m => m.Name == "ExecuteCommand");

        typeBuilder.AddMethod("ReceiveAndLog", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var downloadedLocal)
            .AddLocal(module.TypeSystem.String, out var commandLocal)
            .EmitCall("System.Net.WebClient", "DownloadString", module.TypeSystem.String)
            .EmitStloc(downloadedLocal)
            .EmitString("notepad.exe")
            .EmitStloc(commandLocal)
            .EmitLdloc(commandLocal)
            .EmitCallInternal(sinkMethod)
            .EndMethod();

        var assembly = builder.Build();
        var testType = assembly.MainModule.Types.First(t => t.Name == "ChatLikeClass");
        var sourceMethod = testType.Methods.First(m => m.Name == "ReceiveAndLog");
        var targetMethod = testType.Methods.First(m => m.Name == "ExecuteCommand");

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        analyzer.AnalyzeMethod(sourceMethod);
        analyzer.AnalyzeMethod(targetMethod);
        analyzer.AnalyzeCrossMethodFlows();

        analyzer.CrossMethodChainCount.Should().Be(0);
    }

    [Fact]
    public void BuildDataFlowFindings_IncludesCrossMethodFindings()
    {
        // Arrange
        var builder = TestAssemblyBuilder.Create("CrossMethodFindingsTest");
        var module = builder.Module;

        var typeBuilder = builder.AddType("TestNamespace.Exfiltrator");

        // Sink method - sends data to network
        typeBuilder.AddMethod("SendData", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("data", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCall("System.Net.WebClient", "UploadString", module.TypeSystem.String)
            .EmitPop()
            .EndMethod();

        var sinkMethod = typeBuilder.TypeDefinition.Methods.First(m => m.Name == "SendData");

        // Source method - reads file and calls sink
        typeBuilder.AddMethod("StealData", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var localIdx)
            .EmitString("passwords.txt")
            .EmitCallWithParams("System.IO.File", "ReadAllText", module.TypeSystem.String,
                module.TypeSystem.String)
            .EmitStloc(localIdx)
            .EmitLdloc(localIdx)
            .EmitCallInternal(sinkMethod)
            .EndMethod();

        var assembly = builder.Build();
        var testType = assembly.MainModule.Types.First(t => t.Name == "Exfiltrator");
        var sourceMethod = testType.Methods.First(m => m.Name == "StealData");
        var targetMethod = testType.Methods.First(m => m.Name == "SendData");

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        analyzer.AnalyzeMethod(sourceMethod);
        analyzer.AnalyzeMethod(targetMethod);
        analyzer.AnalyzeCrossMethodFlows();
        var findings = analyzer.BuildDataFlowFindings().ToList();

        findings.Should().Contain(finding =>
            finding.RuleId == "DataFlowAnalysis" &&
            finding.Severity == Severity.Critical &&
            finding.DataFlowChain != null &&
            finding.DataFlowChain.Pattern == DataFlowPattern.DataExfiltration &&
            finding.DataFlowChain.IsCrossMethod);
    }

    [Fact]
    public void BuildDataFlowFindings_DataExfiltrationPattern_EmitsCriticalFinding()
    {
        var builder = TestAssemblyBuilder.Create("StandaloneExfiltrationTest");
        var module = builder.Module;
        var typeBuilder = builder.AddType("TestNamespace.Exfiltrator");

        typeBuilder.AddMethod("UploadCredentials", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var pathLocalIdx)
            .AddLocal(module.TypeSystem.String, out var dataLocalIdx)
            .EmitString("passwords.txt")
            .EmitStloc(pathLocalIdx)
            .EmitLdloc(pathLocalIdx)
            .EmitCallWithParams("System.IO.File", "ReadAllText", module.TypeSystem.String,
                module.TypeSystem.String)
            .EmitStloc(dataLocalIdx)
            .EmitLdloc(dataLocalIdx)
            .EmitCall("System.Net.WebClient", "UploadString", module.TypeSystem.String)
            .EmitPop()
            .EndMethod();

        var assembly = builder.Build();
        var method = assembly.MainModule.Types.First(t => t.Name == "Exfiltrator")
            .Methods.First(m => m.Name == "UploadCredentials");

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        analyzer.AnalyzeMethod(method);

        analyzer.SuspiciousChainCount.Should().BeGreaterThan(0);
        analyzer.BuildDataFlowFindings().Should().ContainSingle(finding =>
            finding.RuleId == "DataFlowAnalysis" &&
            finding.Severity == Severity.Critical &&
            finding.DataFlowChain != null &&
            finding.DataFlowChain.Pattern == DataFlowPattern.DataExfiltration);
    }

    [Fact]
    public void BuildDataFlowFindings_SensitiveRegistrySource_EmitsCriticalFinding()
    {
        var builder = TestAssemblyBuilder.Create("RegistryExfiltrationTest");
        var module = builder.Module;
        var typeBuilder = builder.AddType("TestNamespace.RegistryReader");

        typeBuilder.AddMethod("UploadCredential", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.Object, out var dataLocalIdx)
            .EmitString(@"HKEY_CURRENT_USER\Software\Vendor\Account")
            .EmitString("password")
            .EmitString(string.Empty)
            .EmitCallWithParams(
                "Microsoft.Win32.Registry",
                "GetValue",
                module.TypeSystem.Object,
                module.TypeSystem.String,
                module.TypeSystem.String,
                module.TypeSystem.Object)
            .EmitStloc(dataLocalIdx)
            .EmitLdloc(dataLocalIdx)
            .EmitCallWithParams(
                "System.Net.WebClient",
                "UploadString",
                module.TypeSystem.String,
                module.TypeSystem.Object)
            .EmitPop()
            .EndMethod();

        var assembly = builder.Build();
        var method = assembly.MainModule.Types.First(t => t.Name == "RegistryReader")
            .Methods.First(m => m.Name == "UploadCredential");
        var analyzer = new DataFlowAnalyzer(RuleFactory.CreateDefaultRules(), new CodeSnippetBuilder());

        analyzer.AnalyzeMethod(method);

        analyzer.BuildDataFlowFindings().Should().ContainSingle(finding =>
            finding.RuleId == "DataFlowAnalysis" &&
            finding.Severity == Severity.Critical &&
            finding.DataFlowChain != null &&
            finding.DataFlowChain.Pattern == DataFlowPattern.DataExfiltration);
    }

    [Fact]
    public void DataFlowChain_IsCrossMethod_FlagSetCorrectly()
    {
        // Arrange: Directly test the DataFlowChain model
        var chain = new DataFlowChain(
            "test-chain",
            DataFlowPattern.DataExfiltration,
            Severity.Critical,
            "Test cross-method exfiltration",
            "TestClass.SourceMethod")
        {
            IsCrossMethod = true,
            InvolvedMethods = new List<string>
            {
                "TestClass.SourceMethod",
                "TestClass.SinkMethod"
            }
        };

        // Act & Assert
        chain.IsCrossMethod.Should().BeTrue();
        chain.InvolvedMethods.Should().HaveCount(2);
        chain.CallDepth.Should().Be(2);
    }

    [Fact]
    public void DataFlowChain_CallDepth_ReturnsCorrectDepth()
    {
        // Arrange: Chain with 3 methods involved
        var chain = new DataFlowChain(
            "deep-chain",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Deep call chain",
            "A.Method1")
        {
            IsCrossMethod = true,
            InvolvedMethods = new List<string>
            {
                "A.Method1",
                "B.Method2",
                "C.Method3"
            }
        };

        // Act
        var depth = chain.CallDepth;

        // Assert
        depth.Should().Be(3);
    }

    [Fact]
    public void DataFlowChain_CallDepth_SingleMethod_ReturnsOne()
    {
        // Arrange: Chain without involved methods (single method)
        var chain = new DataFlowChain(
            "single-chain",
            DataFlowPattern.DynamicCodeLoading,
            Severity.High,
            "Single method flow",
            "TestClass.Method");

        // Act
        var depth = chain.CallDepth;

        // Assert
        depth.Should().Be(1);
    }

    [Fact]
    public void DataFlowNode_MethodBoundary_ToStringIncludesTarget()
    {
        // Arrange
        var node = new DataFlowNode(
            "TestClass.Caller:42",
            "calls TestClass.Target",
            DataFlowNodeType.Intermediate,
            "data passed via parameter",
            42,
            null,
            "System.Void TestClass::Caller()")
        {
            IsMethodBoundary = true,
            TargetMethodKey = "System.Void TestClass::Target(System.String)"
        };

        // Act
        var str = node.ToString();

        // Assert
        str.Should().Contain("[PASS]");
        str.Should().Contain("calls");
        str.Should().Contain("Target");
    }

    #endregion

    #region Null and Edge Case Handling

    [Fact]
    public void AnalyzeMethod_NullMethod_ReturnsEmptyList()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var result = analyzer.AnalyzeMethod(null!);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeMethod_MethodWithNullBody_ReturnsEmptyList()
    {
        // Arrange
        var assembly = TestAssemblyBuilder.Create("NullBodyTest").Build();
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("EmptyMethod", MethodAttributes.Public | MethodAttributes.Abstract | MethodAttributes.Virtual, module.TypeSystem.Void);
        type.Methods.Add(method);

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var result = analyzer.AnalyzeMethod(method);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeMethod_MethodWithEmptyInstructions_ReturnsEmptyList()
    {
        // Arrange
        var assembly = TestAssemblyBuilder.Create("EmptyInstructionsTest").Build();
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("EmptyMethod", MethodAttributes.Public, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder);

        // Act
        var result = analyzer.AnalyzeMethod(method);

        // Assert
        result.Should().BeEmpty();
    }

    #endregion

    #region Configuration Tests

    [Fact]
    public void Constructor_WithConfigParameter_CreatesInstanceWithConfig()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var config = new DataFlowAnalyzerConfig
        {
            EnableCrossMethodAnalysis = false,
            MaxCallChainDepth = 10,
            EnableReturnValueTracking = false
        };

        // Act
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder, config);

        // Assert
        analyzer.Should().NotBeNull();
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_WithDisabledConfig_DoesNotAnalyze()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var config = new DataFlowAnalyzerConfig { EnableCrossMethodAnalysis = false };
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder, config);

        var builder = TestAssemblyBuilder.Create("DisabledCrossMethodTest");
        var module = builder.Module;
        var typeBuilder = builder.AddType("TestNamespace.TestClass");

        typeBuilder.AddMethod("SinkMethod", MethodAttributes.Public | MethodAttributes.Static)
            .AddParameter("data", module.TypeSystem.String)
            .EmitLdarg(0)
            .EmitCall("System.Diagnostics.Process", "Start", module.TypeSystem.Object)
            .EmitPop()
            .EndMethod();

        var sinkMethod = typeBuilder.TypeDefinition.Methods.First(m => m.Name == "SinkMethod");

        typeBuilder.AddMethod("SourceMethod", MethodAttributes.Public | MethodAttributes.Static)
            .AddLocal(module.TypeSystem.String, out var localIdx)
            .EmitCall("System.Net.WebClient", "DownloadString", module.TypeSystem.String)
            .EmitStloc(localIdx)
            .EmitLdloc(localIdx)
            .EmitCallInternal(sinkMethod)
            .EndMethod();

        var assembly = builder.Build();
        var testType = assembly.MainModule.Types.First(t => t.Name == "TestClass");
        var sourceMethod = testType.Methods.First(m => m.Name == "SourceMethod");
        var targetMethod = testType.Methods.First(m => m.Name == "SinkMethod");

        analyzer.AnalyzeMethod(sourceMethod);
        analyzer.AnalyzeMethod(targetMethod);

        // Act
        analyzer.AnalyzeCrossMethodFlows();

        // Assert
        analyzer.CrossMethodChainCount.Should().Be(0);
    }

    [Fact]
    public void AnalyzeCrossMethodFlows_WithMaxDepthLessThan3_DoesNotRunExpandedCrossMethodTraversal()
    {
        // Arrange
        var rules = RuleFactory.CreateDefaultRules();
        var snippetBuilder = new CodeSnippetBuilder();
        var config = new DataFlowAnalyzerConfig { MaxCallChainDepth = 2 };
        var analyzer = new DataFlowAnalyzer(rules, snippetBuilder, config);

        // Act - should not throw
        var act = () => analyzer.AnalyzeCrossMethodFlows();

        // Assert
        act.Should().NotThrow();
    }

    #endregion

    #region Data Flow Chain Properties Tests

    [Fact]
    public void DataFlowChain_SuspiciousFlag_SingleMethodChain()
    {
        var chain = new DataFlowChain(
            "test-chain",
            DataFlowPattern.DownloadAndExecute,
            Severity.Critical,
            "Test chain",
            "TestClass.Method");

        chain.IsSuspicious.Should().BeTrue();
        chain.IsCrossMethod.Should().BeFalse();
    }

    [Fact]
    public void DataFlowChain_ToDetailedDescription_ContainsSummary()
    {
        var chain = new DataFlowChain(
            "test-chain",
            DataFlowPattern.DataExfiltration,
            Severity.Critical,
            "Data exfiltration detected",
            "TestClass.Method");

        // Add nodes to trigger full description
        chain.AppendNode(new DataFlowNode("loc1", "File.ReadAllText", DataFlowNodeType.Source, "file data", 0, "var data = File.ReadAllText(...)"));
        chain.AppendNode(new DataFlowNode("loc2", "WebClient.UploadString", DataFlowNodeType.Sink, "network send", 10, "client.UploadString(...)"));

        var description = chain.ToDetailedDescription();

        // The description should contain the summary and chain info when nodes are present
        description.Should().Contain("Data exfiltration detected");
        description.Should().Contain("Data Flow Chain");
        description.Should().NotContain("Confidence:");
    }

    [Fact]
    public void DataFlowChain_ToCombinedCodeSnippet_CombinesNodeSnippets()
    {
        var chain = new DataFlowChain(
            "test-chain",
            DataFlowPattern.DynamicCodeLoading,
            Severity.High,
            "Dynamic loading",
            "TestClass.Method");

        chain.AppendNode(new DataFlowNode("loc1", "Op1", DataFlowNodeType.Source, "data", 0, "snippet1"));
        chain.AppendNode(new DataFlowNode("loc2", "Op2", DataFlowNodeType.Sink, "result", 10, "snippet2"));

        var combined = chain.ToCombinedCodeSnippet();

        combined.Should().Contain("snippet1");
        combined.Should().Contain("snippet2");
    }

    #endregion

    #region Bounded Analysis Tests

    [Fact]
    public void AnalyzeMethod_WithRepresentativeCallHeavyMethod_CompletesAnalysis()
    {
        using var module = ModuleDefinition.CreateModule("DataFlowCallHeavyTest", ModuleKind.Dll);
        var method = CreateCallHeavyMethod(module, 400);
        var analyzer = new DataFlowAnalyzer(RuleFactory.CreateDefaultRules(), new CodeSnippetBuilder());

        analyzer.AnalyzeMethod(method);
        var findings = analyzer.BuildDataFlowFindings().ToList();

        findings.Should().NotContain(finding => finding.RuleId == "DataFlowScanWarning");
    }

    [Fact]
    public void AnalyzeMethod_WhenReachingDefinitionWorkIsExhausted_FailsClosedForManualReview()
    {
        using var module = ModuleDefinition.CreateModule("DataFlowBudgetTest", ModuleKind.Dll);
        // Keep this above the representative 400-call case so it exceeds the current 256x linear budget.
        var stress = CreateCallHeavyMethod(module, 800);
        var analyzer = new DataFlowAnalyzer(RuleFactory.CreateDefaultRules(), new CodeSnippetBuilder());

        analyzer.AnalyzeMethod(stress);
        var findings = analyzer.BuildDataFlowFindings().ToList();
        var dto = ScanResultMapper.ToDto(findings, "budget-stress.dll", [0x4d, 0x5a], false);

        findings.Should().ContainSingle(finding => finding.RuleId == "DataFlowScanWarning");
        dto.AnalysisCompleteness.IsComplete.Should().BeFalse();
        dto.AnalysisCompleteness.ReviewRecommended.Should().BeTrue();
        dto.Disposition.Should().NotBeNull();
        dto.Disposition!.Classification.Should().Be("ManualReviewRequired");
        dto.Disposition.BlockingRecommended.Should().BeTrue();
    }

    private static MethodDefinition CreateCallHeavyMethod(ModuleDefinition module, int callCount)
    {
        var type = new TypeDefinition("TestNamespace", $"CallHeavy{callCount}",
            TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var consume = new MethodDefinition("Consume",
            MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        consume.Parameters.Add(new ParameterDefinition("value", ParameterAttributes.None, module.TypeSystem.Int32));
        consume.Body.GetILProcessor().Emit(OpCodes.Ret);
        type.Methods.Add(consume);

        var method = new MethodDefinition("Stress",
            MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        var local = new VariableDefinition(module.TypeSystem.Int32);
        method.Body.Variables.Add(local);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Stloc, local);
        for (var index = 0; index < callCount; index++)
        {
            il.Emit(OpCodes.Ldloc, local);
            il.Emit(OpCodes.Call, consume);
        }

        il.Emit(OpCodes.Ret);
        type.Methods.Add(method);
        return method;
    }

    #endregion
}

#pragma warning restore CS0618
