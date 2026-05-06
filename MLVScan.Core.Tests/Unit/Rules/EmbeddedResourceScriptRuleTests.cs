using System.Text;
using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EmbeddedResourceScriptRuleTests
{
    private readonly EmbeddedResourceScriptRule _rule = new();

    [Fact]
    public void RuleMetadata_IsExpected()
    {
        _rule.RuleId.Should().Be("EmbeddedResourceScriptRule");
        _rule.Severity.Should().Be(Severity.High);
        _rule.RequiresCompanionFinding.Should().BeFalse();
        _rule.Description.Should().Contain("embedded script");
    }

    [Fact]
    public void PostAnalysisRefine_ReferencedPowerShellAntiAnalysisResource_ReturnsFinding()
    {
        AssemblyDefinition assembly = CreateAssemblyWithResource(
            "MelonBase",
            "%noise%powershell -NoLogo -NoProfile -Command \"if((Get-CimInstance Win32_VideoController | Where-Object {$_.Name -like '*Microsoft Remote Display Adapter*'}) -or ([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB) -lt 3)){exit 1}\"%noise%",
            referenceResource: true);

        List<ScanFinding> findings = _rule.PostAnalysisRefine(assembly.MainModule, Enumerable.Empty<ScanFinding>()).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].RuleId.Should().Be(_rule.RuleId);
        findings[0].Description.Should().Contain("anti-analysis");
        findings[0].Description.Should().Contain("MelonBase");
        findings[0].CodeSnippet.Should().Contain("Get-CimInstance");
        findings[0].BypassCompanionCheck.Should().BeTrue();
    }

    [Fact]
    public void PostAnalysisRefine_UnreferencedSuspiciousResource_ReturnsNoFinding()
    {
        AssemblyDefinition assembly = CreateAssemblyWithResource(
            "MelonBase",
            "powershell -NoProfile -Command Get-CimInstance Win32_ComputerSystem",
            referenceResource: false);

        List<ScanFinding> findings = _rule.PostAnalysisRefine(assembly.MainModule, Enumerable.Empty<ScanFinding>()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void PostAnalysisRefine_ReferencedBenignTextResource_ReturnsNoFinding()
    {
        AssemblyDefinition assembly = CreateAssemblyWithResource(
            "Readme",
            "This resource contains localization text and normal mod configuration.",
            referenceResource: true);

        List<ScanFinding> findings = _rule.PostAnalysisRefine(assembly.MainModule, Enumerable.Empty<ScanFinding>()).ToList();

        findings.Should().BeEmpty();
    }

    private static AssemblyDefinition CreateAssemblyWithResource(
        string resourceName,
        string resourceText,
        bool referenceResource)
    {
        TestAssemblyBuilder builder = TestAssemblyBuilder.Create("EmbeddedResourceScriptTest");
        builder.Module.Resources.Add(new EmbeddedResource(
            resourceName,
            ManifestResourceAttributes.Private,
            Encoding.UTF8.GetBytes(resourceText)));

        var methodBuilder = builder
            .AddType("Suspicious.ResourceLoader")
            .AddMethod("Load", MethodAttributes.Public | MethodAttributes.Static);

        if (referenceResource)
        {
            methodBuilder
                .EmitCall("System.Reflection.Assembly", "GetExecutingAssembly", builder.Module.TypeSystem.Object)
                .EmitString(resourceName)
                .EmitCallVirt("System.Reflection.Assembly", "GetManifestResourceStream", builder.Module.TypeSystem.Object);
        }

        methodBuilder.EndMethod().EndType();
        return builder.Build();
    }
}
