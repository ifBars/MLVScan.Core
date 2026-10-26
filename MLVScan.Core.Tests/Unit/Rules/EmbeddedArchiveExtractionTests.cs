using System.IO.Compression;
using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EmbeddedArchiveExtractionTests
{
    [Theory]
    [InlineData("helper.exe", true, 0, "Suspicious")]
    [InlineData("helper.cmd", true, 300, "Suspicious")]
    [InlineData("readme.txt", true, 0, "Clean")]
    [InlineData("helper.exe", false, 0, "Clean")]
    public void EmbeddedZip_RequiresExecutableContentAndStagingDestination(string entryName, bool temporary, int precedingEntries, string expected)
    {
        using var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("ArchiveProbe", new Version(1, 0)), "ArchiveProbe", ModuleKind.Dll);
        var module = assembly.MainModule;
        using var bytes = new MemoryStream();
        using (var archive = new ZipArchive(bytes, ZipArchiveMode.Create, true))
        {
            for (int index = 0; index < precedingEntries; index++)
            {
                archive.CreateEntry($"data-{index}.txt");
            }
            using var writer = new StreamWriter(archive.CreateEntry(entryName).Open());
            writer.Write("inert fixture content");
        }
        module.Resources.Add(new EmbeddedResource("assets.zip", ManifestResourceAttributes.Private, bytes.ToArray()));
        var type = new TypeDefinition("Probe", "Entry", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ldstr, "assets.zip");
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(System.Reflection.Assembly).GetMethod("GetManifestResourceStream", [typeof(string)])!));
        il.Emit(OpCodes.Newobj, module.ImportReference(typeof(ZipArchive).GetConstructor([typeof(Stream)])!));
        il.Emit(OpCodes.Ldstr, entryName);
        il.Emit(OpCodes.Callvirt, module.ImportReference(typeof(ZipArchive).GetMethod("GetEntry", [typeof(string)])!));
        if (temporary)
        {
            il.Emit(OpCodes.Call, module.ImportReference(typeof(Path).GetMethod("GetTempPath")!));
        }
        else
        {
            il.Emit(OpCodes.Ldstr, "C:/game/assets");
        }
        il.Emit(OpCodes.Ldstr, entryName);
        il.Emit(OpCodes.Call, module.ImportReference(typeof(Path).GetMethod("Combine", [typeof(string), typeof(string)])!));
        il.Emit(OpCodes.Call, module.ImportReference(typeof(ZipFileExtensions).GetMethod("ExtractToFile", [typeof(ZipArchiveEntry), typeof(string)])!));
        il.Emit(OpCodes.Ret);

        var findings = new EmbeddedArchivePayloadRule().PostAnalysisRefine(module, []).ToList();
        ScanResultMapper.ToDto(findings, "probe.dll", [], false).Disposition!.Classification.Should().Be(expected);
        if (temporary)
        {
            findings.Should().ContainSingle();
        }
        else
        {
            findings.Should().BeEmpty();
        }
    }
}
