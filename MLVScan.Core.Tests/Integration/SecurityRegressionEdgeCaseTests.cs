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
}
