using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

public class FalsePositiveEdgeCaseTests
{
    [Fact]
    public void Scan_SafeExplorerFolderOpen_DoesNotEmitFindings()
    {
        var builder = TestAssemblyBuilder.Create("SafeExplorerOpen");
        var assembly = builder
            .AddType("Legit.ModTools")
            .AddMethod("OpenConfigFolder")
            .EmitString("explorer.exe")
            .EmitString(@"C:\Games\ScheduleI\Mods")
            .EmitCallWithParams(
                "System.Diagnostics.Process",
                "Start",
                builder.Module.TypeSystem.Object,
                builder.Module.TypeSystem.String,
                builder.Module.TypeSystem.String)
            .EmitPop()
            .EndMethod()
            .EndType()
            .Build();

        var findings = Scan(assembly, "SafeExplorerOpen.dll");

        findings.Should().BeEmpty("opening a known folder through explorer.exe is a supported benign pattern");
    }

    [Fact]
    public void Scan_ProcessStartInfoFolderShellOpen_WithoutArguments_DoesNotEmitFindings()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("SafeShellFolderOpen", new Version(1, 0, 0, 0)),
            "SafeShellFolderOpen",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "FolderOpener", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("OpenFolder", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, @"C:\Games\ScheduleI\Mods");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "Exists", module.TypeSystem.Boolean, module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldstr, @"C:\Games\ScheduleI\Mods");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, CreateType(module, "System.Diagnostics.ProcessStartInfo")));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var findings = Scan(assembly, "SafeShellFolderOpen.dll");

        findings.Should().BeEmpty("shell-opening a folder with UseShellExecute=true and no arguments should stay benign");
    }

    [Fact]
    public void Scan_ControlledKnownToolWithRedirectedOutput_DoesNotEscalateToBlockingSeverity()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("SafeToolRunner", new Version(1, 0, 0, 0)),
            "SafeToolRunner",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "MediaToolRunner", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("RunFfmpeg", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldstr, "ffmpeg.exe");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldstr, "-version");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_Arguments", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_CreateNoWindow", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_RedirectStandardOutput", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, CreateType(module, "System.Diagnostics.ProcessStartInfo")));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var findings = Scan(assembly, "SafeToolRunner.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "controlled execution of a known media tool with redirected output should not look like a payload launcher");
    }

    [Fact]
    public void Scan_BenignEncodedStringsAndMetadata_DoNotEmitFindings()
    {
        var assembly = TestAssemblyBuilder.Create("BenignEncodedContent")
            .AddAssemblyAttribute("AssemblyMetadataAttribute", "notes", "72-101-108-108-111-32-87-111-114-108-100")
            .AddType("Legit.Localization")
            .AddMethod("LoadText")
            .EmitString("72-101-108-108-111-32-87-111-114-108-100")
            .EndMethod()
            .EndType()
            .Build();

        var findings = Scan(assembly, "BenignEncodedContent.dll");

        findings.Should().BeEmpty("numeric encoding without suspicious decoded content should not be treated as malware");
    }

    [Fact]
    public void Scan_RegistryReadForInstallPath_DoesNotEscalateToBlockingSeverity()
    {
        var builder = TestAssemblyBuilder.Create("RegistryInstallPathLookup");
        var assembly = builder
            .AddType("Legit.TranslatorPathProbe")
            .AddMethod("FindInstall")
            .EmitString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\Product")
            .EmitString("InstallPath")
            .EmitString("")
            .EmitCallWithParams(
                "Microsoft.Win32.Registry",
                "GetValue",
                builder.Module.TypeSystem.Object,
                builder.Module.TypeSystem.String,
                builder.Module.TypeSystem.String,
                builder.Module.TypeSystem.Object)
            .EmitPop()
            .EndMethod()
            .EndType()
            .Build();

        var findings = Scan(assembly, "RegistryInstallPathLookup.dll");

        findings.Should().NotContain(f => f.Severity >= Severity.High,
            "read-only install path discovery should not be treated like persistence");
    }

    [Fact]
    public void Scan_TelemetryUploadDataFlow_DoesNotEmitStandaloneMalwareFinding()
    {
        var builder = TestAssemblyBuilder.Create("BenignTelemetryUpload");
        var module = builder.Module;
        var assembly = builder
            .AddType("Legit.Telemetry")
            .AddMethod("UploadDiagnostics")
            .AddLocal(module.TypeSystem.String, out var localIndex)
            .EmitString("diagnostics.json")
            .EmitCallWithParams("System.IO.File", "ReadAllText", module.TypeSystem.String, module.TypeSystem.String)
            .EmitStloc(localIndex)
            .EmitLdloc(localIndex)
            .EmitCallWithParams("System.Net.WebClient", "UploadString", module.TypeSystem.String, module.TypeSystem.String)
            .EmitPop()
            .EndMethod()
            .EndType()
            .Build();

        var findings = Scan(assembly, "BenignTelemetryUpload.dll");

        findings.Should().NotContain(f => f.RuleId == "DataFlowAnalysis",
            "plain data exfiltration-shaped telemetry should require stronger context before becoming a standalone malware finding");
    }

    [Fact]
    public void Scan_SafeReflectionLookupWithoutInvocation_DoesNotEmitFindings()
    {
        var builder = TestAssemblyBuilder.Create("SafeReflectionLookup");
        var assembly = builder
            .AddType("Legit.ApiProbe")
            .AddMethod("Probe")
            .EmitString("OptionalApi")
            .EmitCallWithParams("System.Type", "GetType", builder.Module.TypeSystem.Object, builder.Module.TypeSystem.String)
            .EmitPop()
            .EndMethod()
            .EndType()
            .Build();

        var findings = Scan(assembly, "SafeReflectionLookup.dll");

        findings.Should().BeEmpty("lookup-only reflection without invocation or companion signals should stay clean");
    }

    [Theory]
    [InlineData("Hello World")]
    [InlineData("72-101-108-108-111-32-87-111-114-108-100")]
    [InlineData("83-97-102-101`67-111-110-102-105-103")]
    public void EncodedStringLiteralRule_BenignDecodedContent_ReturnsNoFindings(string literal)
    {
        var method = CreateMethod("BenignLiteral");
        var rule = new EncodedStringLiteralRule();

        var findings = rule.AnalyzeStringLiteral(literal, method, 0).ToList();

        findings.Should().BeEmpty();
    }

    private static List<ScanFinding> Scan(AssemblyDefinition assembly, string virtualPath)
    {
        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        return new AssemblyScanner(RuleFactory.CreateDefaultRules()).Scan(stream, virtualPath).ToList();
    }

    private static MethodDefinition CreateMethod(string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("FalsePositiveLiteralRuleTest", new Version(1, 0, 0, 0)),
            "FalsePositiveLiteralRuleTest",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "LiteralHolder", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Emit(OpCodes.Ret);
        type.Methods.Add(method);
        return method;
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

    private static TypeReference CreateType(ModuleDefinition module, string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : "";
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
        return new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
    }
}
