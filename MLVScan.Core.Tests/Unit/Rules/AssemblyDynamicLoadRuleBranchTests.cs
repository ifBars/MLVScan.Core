using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
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

        refined.Should().ContainSingle();
        refined[0].Description.Should().Contain("Embedded assembly");
        refined[0].Description.Should().Contain(resourceName);
        refined[0].RiskScore.Should().NotBeNull();
        refined[0].RiskScore.Should().BeGreaterThan(50);
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
        il.Append(il.Create(OpCodes.Call, CreateMethodReference("System.Diagnostics", "Process", "Start", module, "System.String")));
        il.Append(il.Create(OpCodes.Ret));

        using var ms = new MemoryStream();
        assembly.Write(ms);
        return ms.ToArray();
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
