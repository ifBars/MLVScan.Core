using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities.DeepBehavior;
using MLVScan.Models;
using MLVScan.Services;
using MLVScan.Services.DeepBehavior;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.DeepBehavior;

public class ScriptHostLaunchAnalyzerTests
{
    [Fact]
    public void Analyze_WithScriptHostAndProcessStartRule_ReturnsHighFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "powershell -ExecutionPolicy Bypass -File script.ps1"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepScriptHostLaunchRule");
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Be("Deep correlation: script host launch chain detected.");
    }

    [Fact]
    public void Analyze_WithScriptHostAndEncodedIndicator_ReturnsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "powershell"));
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "-enc"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].RuleId.Should().Be("DeepScriptHostLaunchRule");
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("encoded/hidden argument indicators");
    }

    [Fact]
    public void Analyze_WithFromBase64StringIndicator_ReturnsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "cmd.exe /c calc"));
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "Convert.FromBase64String"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Analyze_WithCmdSlashCIndicator_ReturnsCriticalFinding()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "wscript"));
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "/c echo test"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Analyze_WithVariousScriptHosts_DetectsAll()
    {
        var scriptHosts = new[] { "powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32" };

        foreach (var host in scriptHosts)
        {
            var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
            var il = method.Body.GetILProcessor();
            il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, host));

            var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
            var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

            var context = new DeepBehaviorContext
            {
                Method = method,
                Signals = new MethodSignals(),
                MethodFindings =
                [
                    new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
                ]
            };

            var findings = analyzer.Analyze(context).ToList();
            findings.Should().ContainSingle($"Expected detection for {host}");
        }
    }

    [Fact]
    public void Analyze_WithoutScriptHost_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "notepad.exe"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WhenScriptHostAnalysisDisabled_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "powershell"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = false };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_WithoutProcessStartRule_ReturnsEmpty()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "powershell"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings = Array.Empty<ScanFinding>()
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_CaseInsensitiveScriptHostDetection()
    {
        var (_, method) = DeepBehaviorAssemblyFactory.CreateLoopAssembly();
        var il = method.Body.GetILProcessor();
        il.InsertBefore(il.Body.Instructions[0], il.Create(OpCodes.Ldstr, "POWERSHELL.EXE"));

        var config = new DeepBehaviorAnalysisConfig { EnableScriptHostLaunchAnalysis = true };
        var analyzer = new ScriptHostLaunchAnalyzer(config, new CodeSnippetBuilder());

        var context = new DeepBehaviorContext
        {
            Method = method,
            Signals = new MethodSignals(),
            MethodFindings =
            [
                new ScanFinding("Test.Type.Method:0", "process start", Severity.High) { RuleId = "ProcessStartRule" }
            ]
        };

        var findings = analyzer.Analyze(context).ToList();

        findings.Should().ContainSingle();
    }
}
