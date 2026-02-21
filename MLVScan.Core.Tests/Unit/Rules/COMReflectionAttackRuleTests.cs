using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

/// <summary>
/// Tests for COMReflectionAttackRule to achieve 100% code coverage.
/// </summary>
public class COMReflectionAttackRuleTests
{
    private readonly COMReflectionAttackRule _rule = new();

    [Fact]
    public void RuleId_ReturnsCOMReflectionAttackRule()
    {
        _rule.RuleId.Should().Be("COMReflectionAttackRule");
    }

    [Fact]
    public void Severity_ReturnsCritical()
    {
        _rule.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_ReturnsFalse()
    {
        // This rule analyzes instructions, not individual method references
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_NullMethodDef_ReturnsEmpty()
    {
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        var findings = _rule.AnalyzeInstructions(null!, instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_NullInstructions_ReturnsEmpty()
    {
        var methodDef = CreateMethodDefinition();

        var findings = _rule.AnalyzeInstructions(methodDef, null!, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_EmptyInstructions_ReturnsEmpty()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>();

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_NoComCalls_ReturnsEmpty()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "test"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Console", "WriteLine"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithCriticalProgID_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Shell.Application");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithWScriptShell_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "WScript.Shell"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("WScript.Shell");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithScheduleService_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Schedule.Service"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Schedule.Service");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithMMC20Application_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "MMC20.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("MMC20.Application");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithPartialShellMatch_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Explorer"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("Shell.Explorer");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithPartialWScriptMatch_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "WScript.Network"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        // WScript.Network triggers the partial match which causes command string detection
        findings[0].Description.Should().Contain("command execution");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithHighRiskProgID_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Scripting.FileSystemObject"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Scripting.FileSystemObject");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithADODBStream_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "ADODB.Stream"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("ADODB.Stream");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithXMLHTTP_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "MSXML2.XMLHTTP"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("MSXML2.XMLHTTP");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithWinHttpRequest_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "WinHttp.WinHttpRequest.5.1"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("WinHttp.WinHttpRequest.5.1");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithMicrosoftXMLHTTP_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Microsoft.XMLHTTP"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Microsoft.XMLHTTP");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithCommandString_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "cmd.exe /c dir"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("command execution");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithPowerShell_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "powershell -Command Get-Process"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithPwsh_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "pwsh -Command echo test"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithCmdC_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "/c calc.exe"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithCmdK_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "/k pause"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithWScript_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "wscript script.js"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithCScript_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "cscript script.vbs"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithMshta_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "mshta malicious.hta"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithRegsvr32_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "regsvr32 /s malicious.dll"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithTypeInvokeMember_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID")),
            Instruction.Create(OpCodes.Ldstr, "ShellExecute"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "InvokeMember"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("GetTypeFromProgID + Type.InvokeMember");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromCLSID_WithTypeInvokeMember_ReturnsCriticalFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, 0),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromCLSID")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "InvokeMember"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("GetTypeFromProgID + Type.InvokeMember");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromProgID_WithActivatorCreateInstance_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Activator", "CreateInstance"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Dynamic COM object instantiation");
    }

    [Fact]
    public void AnalyzeInstructions_GetTypeFromCLSID_WithActivatorCreateInstance_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldc_I4, 0),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromCLSID")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Activator", "CreateInstance"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("Dynamic COM object instantiation");
    }

    [Fact]
    public void AnalyzeInstructions_MarshalGetActiveObject_WithShellIndicator_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Runtime.InteropServices.Marshal", "GetActiveObject")),
            Instruction.Create(OpCodes.Ldstr, "ShellExecute")
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("running COM instance");
    }

    [Fact]
    public void AnalyzeInstructions_MarshalGetActiveObject_WithShell32Indicator_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "shell32"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Runtime.InteropServices.Marshal", "GetActiveObject"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeInstructions_MarshalGetActiveObject_WithRunIndicator_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Run"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Runtime.InteropServices.Marshal", "GetActiveObject"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeInstructions_MarshalGetActiveObject_WithExecIndicator_ReturnsHighFinding()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Exec"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Runtime.InteropServices.Marshal", "GetActiveObject"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void AnalyzeInstructions_UnknownProgID_NoSuspiciousStrings_ReturnsEmpty()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.Benign.ProgID"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_MarshalGetActiveObject_NoShellIndicators_ReturnsEmpty()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.Benign.Object"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Runtime.InteropServices.Marshal", "GetActiveObject"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals());

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_SnippetIncludesProgID()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].CodeSnippet.Should().Contain("ProgID: Shell.Application");
    }

    [Fact]
    public void AnalyzeInstructions_SnippetIncludesInvokeMember()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "InvokeMember"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].CodeSnippet.Should().Contain("Type.InvokeMember");
    }

    [Fact]
    public void AnalyzeInstructions_SnippetIncludesActivatorCreateInstance()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID")),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Activator", "CreateInstance"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].CodeSnippet.Should().Contain("Activator.CreateInstance");
    }

    [Fact]
    public void AnalyzeInstructions_SnippetIncludesSuspiciousStrings()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Some.ProgID"),
            Instruction.Create(OpCodes.Ldstr, "cmd.exe /c dir"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].CodeSnippet.Should().Contain("cmd.exe");
    }

    [Fact]
    public void AnalyzeInstructions_SnippetIncludesShellExecuteIndicator()
    {
        var methodDef = CreateMethodDefinition();
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "ShellExecute"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Runtime.InteropServices.Marshal", "GetActiveObject"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].CodeSnippet.Should().Contain("ShellExecute");
    }

    [Fact]
    public void AnalyzeInstructions_LocationIsCorrect()
    {
        var methodDef = CreateMethodDefinition("TestNamespace.TestClass", "TestMethod");
        var instructions = new Mono.Collections.Generic.Collection<Instruction>
        {
            Instruction.Create(OpCodes.Ldstr, "Shell.Application"),
            Instruction.Create(OpCodes.Call, CreateMethodReference("System.Type", "GetTypeFromProgID"))
        };

        var findings = _rule.AnalyzeInstructions(methodDef, instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Location.Should().Be("TestNamespace.TestClass.TestMethod");
    }

    private static MethodReference CreateMethodReference(string declaringTypeFullName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("Test", new Version(1, 0)), "Test", ModuleKind.Dll);
        var module = assembly.MainModule;
        var idx = declaringTypeFullName.LastIndexOf('.');
        var ns = idx > 0 ? declaringTypeFullName[..idx] : string.Empty;
        var type = idx > 0 ? declaringTypeFullName[(idx + 1)..] : declaringTypeFullName;
        return new MethodReference(methodName, module.TypeSystem.Void, new TypeReference(ns, type, module, module.TypeSystem.CoreLibrary));
    }

    private static MethodDefinition CreateMethodDefinition(string typeFullName = "TestClass", string methodName = "TestMethod")
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("Test", new Version(1, 0)), "Test", ModuleKind.Dll);
        var module = assembly.MainModule;
        var lastDot = typeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? typeFullName[..lastDot] : "";
        var type = lastDot > 0 ? typeFullName[(lastDot + 1)..] : typeFullName;
        var typeDef = new TypeDefinition(ns, type, TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(typeDef);
        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        method.Body.GetILProcessor().Append(Instruction.Create(OpCodes.Ret));
        typeDef.Methods.Add(method);
        return method;
    }
}
