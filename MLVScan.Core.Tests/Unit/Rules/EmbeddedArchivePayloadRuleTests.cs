using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EmbeddedArchivePayloadRuleTests
{
    private readonly EmbeddedArchivePayloadRule _rule = new();

    [Fact]
    public void PostAnalysisRefine_EmbeddedZipWrittenBesideConcealedProcess_ReturnsFinding()
    {
        using var assembly = CreateAssemblyWithEmbeddedArchive();
        var existing = new[]
        {
            new ScanFinding("Test.Loader.Run", "Controlled child process with redirected I/O", Severity.Medium, null)
            {
                RuleId = "ProcessStartRule"
            }
        };

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, existing).ToList();

        findings.Should().ContainSingle(finding =>
            finding.RuleId == "EmbeddedArchivePayloadRule" &&
            finding.Description.Contains("ZIP/JAR", StringComparison.Ordinal));
    }

    [Fact]
    public void PostAnalysisRefine_EmbeddedZipUsedAsOrdinaryAsset_ReturnsNoFinding()
    {
        using var assembly = CreateAssemblyWithEmbeddedArchive();

        var findings = _rule.PostAnalysisRefine(assembly.MainModule, []).ToList();

        findings.Should().BeEmpty();
    }

    private static AssemblyDefinition CreateAssemblyWithEmbeddedArchive()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("EmbeddedArchive", new Version(1, 0)),
            "EmbeddedArchive",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "Loader", TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);

        var archive = Enumerable.Repeat((byte)0x41, 512).ToArray();
        archive[0] = 0x50;
        archive[1] = 0x4b;
        archive[2] = 0x03;
        archive[3] = 0x04;
        var blobType = new TypeDefinition(
            string.Empty,
            "__StaticArrayInitTypeSize=512",
            TypeAttributes.NestedPrivate | TypeAttributes.Sealed | TypeAttributes.ExplicitLayout,
            new TypeReference("System", "ValueType", module, module.TypeSystem.CoreLibrary))
        {
            ClassSize = archive.Length,
            PackingSize = 1
        };
        type.NestedTypes.Add(blobType);
        var field = new FieldDefinition(
            "ArchiveBytes",
            FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA,
            blobType)
        {
            InitialValue = archive
        };
        type.Fields.Add(field);

        var method = new MethodDefinition(
            "Write",
            MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);
        var fileType = new TypeReference("System.IO", "File", module, module.TypeSystem.CoreLibrary);
        var write = new MethodReference("WriteAllBytes", module.TypeSystem.Void, fileType);
        method.Body.GetILProcessor().Emit(OpCodes.Ldstr, "payload.jar");
        method.Body.GetILProcessor().Emit(OpCodes.Call, write);
        method.Body.GetILProcessor().Emit(OpCodes.Ret);
        return assembly;
    }
}
