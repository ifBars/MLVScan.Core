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
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfoLocal = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfoLocal);
        method.Body.InitLocals = true;
        var returnInstruction = il.Create(OpCodes.Ret);

        il.Emit(OpCodes.Ldstr, @"C:\Games\ScheduleI\Mods");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "Exists", module.TypeSystem.Boolean, module.TypeSystem.String));
        il.Emit(OpCodes.Brfalse_S, returnInstruction);

        il.Emit(OpCodes.Newobj, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void));
        il.Emit(OpCodes.Stloc, startInfoLocal);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldstr, @"C:\Games\ScheduleI\Mods");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Append(returnInstruction);

        var findings = Scan(assembly, "SafeShellFolderOpen.dll");

        findings.Should().BeEmpty("shell-opening a folder with UseShellExecute=true and no arguments should stay benign");
    }

    [Fact]
    public void Scan_EnsureDirectoryThenShellOpen_DoesNotEmitFindings()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("EnsureDirectoryShellOpen", new Version(1, 0, 0, 0)),
            "EnsureDirectoryShellOpen",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "FolderOpener", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("OpenFolder", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();
        var launchSetup = il.Create(OpCodes.Newobj,
            CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void));

        il.Emit(OpCodes.Ldstr, @"C:\Games\plugins.dll");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "Exists", module.TypeSystem.Boolean, module.TypeSystem.String));
        il.Emit(OpCodes.Brtrue_S, launchSetup);
        il.Emit(OpCodes.Ldstr, @"C:\Games\plugins.dll");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Append(launchSetup);
        il.Emit(OpCodes.Stloc, startInfo);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldstr, @"C:\Games\plugins.dll");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "EnsureDirectoryShellOpen.dll").Should().BeEmpty(
            "both the existing-directory and create-directory paths establish the exact folder target");
    }

    [Fact]
    public void Scan_IgnoredDirectoryExistsBeforeShellLaunch_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("IgnoredDirectoryCheck", new Version(1, 0, 0, 0)),
            "IgnoredDirectoryCheck",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfoLocal = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfoLocal);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, @"C:\payload.lnk");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "Exists", module.TypeSystem.Boolean, module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        EmitStartInfoConstruction(il, module, startInfoLocal, @"C:\payload.lnk");
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "IgnoredDirectoryCheck.dll").Should().NotBeEmpty(
            "discarding Directory.Exists must not validate a shell-launch target");
    }

    [Fact]
    public void Scan_BenignStartInfoBeforeStringLaunch_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("UnrelatedStringLaunch", new Version(1, 0, 0, 0)),
            "UnrelatedStringLaunch",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var benignStartInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(benignStartInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        EmitStartInfoConstruction(il, module, benignStartInfo, @"C:\BenignFolder");
        il.Emit(OpCodes.Ldstr, "powershell.exe");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "UnrelatedStringLaunch.dll").Should().NotBeEmpty(
            "a configured folder start-info must not suppress a direct string launch");
    }

    [Fact]
    public void Scan_DifferentStartInfoInstance_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("DifferentStartInfo", new Version(1, 0, 0, 0)),
            "DifferentStartInfo",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var launchedStartInfo = new VariableDefinition(processStartInfoType);
        var benignStartInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(launchedStartInfo);
        method.Body.Variables.Add(benignStartInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        EmitStartInfoConstruction(il, module, launchedStartInfo, "powershell.exe");
        il.Emit(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        EmitStartInfoConstruction(il, module, benignStartInfo, @"C:\BenignFolder");
        il.Emit(OpCodes.Ldloc, launchedStartInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "DifferentStartInfo.dll").Should().NotBeEmpty(
            "settings from another ProcessStartInfo instance must not suppress the launched instance");
    }

    [Fact]
    public void Scan_ReassignedStartInfoLocal_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ReassignedStartInfo", new Version(1, 0, 0, 0)),
            "ReassignedStartInfo",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        EmitStartInfoConstruction(il, module, startInfo, @"C:\BenignFolder");

        il.Emit(OpCodes.Ldstr, "powershell.exe");
        il.Emit(OpCodes.Newobj, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Stloc, startInfo);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "ReassignedStartInfo.dll").Should().NotBeEmpty(
            "settings from an earlier object stored in the same local must not suppress its replacement");
    }

    [Fact]
    public void Scan_SkippedDirectoryCreationBeforeShellLaunch_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("SkippedDirectoryValidation", new Version(1, 0, 0, 0)),
            "SkippedDirectoryValidation",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        EmitStartInfoConstruction(il, module, startInfo, @"C:\payload.exe");
        var launchInstruction = il.Create(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Brtrue_S, launchInstruction);
        il.Emit(OpCodes.Ldstr, @"C:\payload.exe");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Append(launchInstruction);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "SkippedDirectoryValidation.dll").Should().NotBeEmpty(
            "directory validation that does not dominate the launch must fail closed");
    }

    [Fact]
    public void Scan_SameNamedUnresolvedFieldsBeforeShellLaunch_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("AmbiguousFieldTargets", new Version(1, 0, 0, 0)),
            "AmbiguousFieldTargets",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var safeHolder = new TypeDefinition("Test", "SafeHolder", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        var payloadHolder = new TypeDefinition("Test", "PayloadHolder", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        var safePath = new FieldDefinition("Path", FieldAttributes.Public | FieldAttributes.Static, module.TypeSystem.String);
        var payloadPath = new FieldDefinition("Path", FieldAttributes.Public | FieldAttributes.Static, module.TypeSystem.String);
        safeHolder.Fields.Add(safePath);
        payloadHolder.Fields.Add(payloadPath);
        module.Types.Add(safeHolder);
        module.Types.Add(payloadHolder);

        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldsfld, safePath);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Newobj, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void));
        il.Emit(OpCodes.Stloc, startInfo);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldsfld, payloadPath);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "AmbiguousFieldTargets.dll").Should().NotBeEmpty(
            "lossy field displays must not be used as target identities");
    }

    [Fact]
    public void Scan_InstanceMethodParameterSlotsRemainDistinct_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("DistinctParameterSlots", new Version(1, 0, 0, 0)),
            "DistinctParameterSlots",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var method = new MethodDefinition("Launch", MethodAttributes.Public, module.TypeSystem.Void);
        var benignStartInfo = new ParameterDefinition("benign", ParameterAttributes.None, processStartInfoType);
        var launchedStartInfo = new ParameterDefinition("launched", ParameterAttributes.None, processStartInfoType);
        method.Parameters.Add(benignStartInfo);
        method.Parameters.Add(launchedStartInfo);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldarg, launchedStartInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "DistinctParameterSlots.dll").Should().NotBeEmpty(
            "the hidden this slot must not collide with explicit parameter identities");
    }

    [Fact]
    public void Scan_MultiArgumentCreateDirectoryThenShellOpen_DoesNotEmitFindings()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("MultiArgumentCreateDirectory", new Version(1, 0, 0, 0)),
            "MultiArgumentCreateDirectory",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "FolderOpener", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("OpenFolder", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, @"C:\Games\Mods");
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory",
            CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String, module.TypeSystem.Int32));
        il.Emit(OpCodes.Pop);
        EmitStartInfoConstruction(il, module, startInfo, @"C:\Games\Mods");
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "MultiArgumentCreateDirectory.dll").Should().BeEmpty(
            "directory validation must resolve the path argument rather than the final overload argument");
    }

    [Fact]
    public void Scan_ConditionalFileNameSetterBeforeShellLaunch_EmitsFinding()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ConditionalFileNameSetter", new Version(1, 0, 0, 0)),
            "ConditionalFileNameSetter",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, "payload.exe");
        il.Emit(OpCodes.Newobj, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Stloc, startInfo);
        var validationStart = il.Create(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Brtrue_S, validationStart);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldstr, @"C:\BenignFolder");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Append(validationStart);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "ConditionalFileNameSetter.dll").Should().NotBeEmpty(
            "a filename setter that does not dominate the launch must fail closed");
    }

    [Fact]
    public void Scan_ObjectInitializerFolderShellOpen_DoesNotEmitFindings()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("ObjectInitializerFolderOpen", new Version(1, 0, 0, 0)),
            "ObjectInitializerFolderOpen",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Legit", "FolderOpener", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("OpenFolder", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var processStartInfoType = CreateType(module, "System.Diagnostics.ProcessStartInfo");
        var startInfo = new VariableDefinition(processStartInfoType);
        method.Body.Variables.Add(startInfo);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();

        il.Emit(OpCodes.Ldstr, @"C:\Games\Mods");
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.IO.Directory", "CreateDirectory", CreateType(module, "System.IO.DirectoryInfo"), module.TypeSystem.String));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Newobj, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void));
        il.Emit(OpCodes.Dup);
        il.Emit(OpCodes.Ldstr, @"C:\Games\Mods");
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Dup);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
        il.Emit(OpCodes.Stloc, startInfo);
        il.Emit(OpCodes.Ldloc, startInfo);
        il.Emit(OpCodes.Call, CreateStaticMethod(module, "System.Diagnostics.Process", "Start", module.TypeSystem.Object, processStartInfoType));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        Scan(assembly, "ObjectInitializerFolderOpen.dll").Should().BeEmpty(
            "the stloc producer map must preserve the object created below initializer setters");
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
    public void Scan_TelemetryUploadDataFlow_EmitsNonBlockingAuditFinding()
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

        findings.Should().ContainSingle(f =>
            f.RuleId == "DataFlowAnalysis" && f.Severity == Severity.Medium,
            "plain upload-shaped telemetry should remain visible without becoming a blocking malware finding");

        var dto = ScanResultMapper.ToDto(findings, "BenignTelemetryUpload.dll", Array.Empty<byte>(), false);
        dto.Disposition.Should().NotBeNull();
        dto.Disposition!.Classification.Should().Be("Clean");
        dto.Disposition.BlockingRecommended.Should().BeFalse();
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

    private static void EmitStartInfoConstruction(
        ILProcessor il,
        ModuleDefinition module,
        VariableDefinition local,
        string fileName)
    {
        il.Emit(OpCodes.Newobj, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", ".ctor", module.TypeSystem.Void));
        il.Emit(OpCodes.Stloc, local);
        il.Emit(OpCodes.Ldloc, local);
        il.Emit(OpCodes.Ldstr, fileName);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_FileName", module.TypeSystem.Void, module.TypeSystem.String));
        il.Emit(OpCodes.Ldloc, local);
        il.Emit(OpCodes.Ldc_I4_1);
        il.Emit(OpCodes.Callvirt, CreateInstanceMethod(module, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute", module.TypeSystem.Void, module.TypeSystem.Boolean));
    }

    private static TypeReference CreateType(ModuleDefinition module, string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : "";
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
        return new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
    }
}
