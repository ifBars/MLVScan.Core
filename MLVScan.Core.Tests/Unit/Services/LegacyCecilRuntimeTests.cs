using System.Runtime.Loader;
using FluentAssertions;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class LegacyCecilRuntimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FullScan_WithOldestSupportedCecil_CompletesWithoutChangingHostBindings(bool includeStaticData)
    {
        using var fixture = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("LegacyRuntimeSmoke", new Version(1, 0)), "LegacyRuntimeSmoke", ModuleKind.Dll);
        var module = fixture.MainModule;
        var type = new TypeDefinition("Example", "Plugin", TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void);
        method.Body.GetILProcessor().Emit(OpCodes.Ret);
        type.Methods.Add(method);
        if (includeStaticData)
        {
            type.Fields.Add(new FieldDefinition("Data", FieldAttributes.Private | FieldAttributes.Static |
                FieldAttributes.HasFieldRVA, module.TypeSystem.Int32) { InitialValue = [65, 66, 67, 0] });
        }
        using var bytes = new MemoryStream();
        fixture.Write(bytes);

        var hostCecil = typeof(ModuleDefinition).Assembly;
        var context = new LegacyCecilContext(
            Path.Combine(AppContext.BaseDirectory, "Compatibility", "Mono.Cecil.dll"),
            typeof(AssemblyScanner).Assembly.Location);
        try
        {
            // Only trusted test/Core assemblies are loaded. The synthetic input is parsed as
            // bytes by Cecil; neither fixtures nor real sample assemblies are runtime-loaded.
            var isolatedTests = context.LoadFromAssemblyPath(typeof(LegacyCecilRuntimeTests).Assembly.Location);
            var scan = isolatedTests.GetType(typeof(LegacyCecilRuntimeTests).FullName!)!
                .GetMethod(nameof(ScanFixtureWithPinnedCecil))!;
            for (int repeat = 0; repeat < 2; repeat++)
            {
                var outcome = (string)scan.Invoke(null, [bytes.ToArray()])!;
                outcome.Should().Be("0.10.4.0|True|Clean|0");
            }
        }
        finally
        {
            context.Unload();
        }

        typeof(ModuleDefinition).Assembly.Should().BeSameAs(hostCecil);
        hostCecil.GetName().Version.Should().Be(new Version(0, 11, 6, 0));
    }

    // Invoked inside the isolated context so Core and its Cecil dependency bind together there.
    public static string ScanFixtureWithPinnedCecil(byte[] bytes)
    {
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules());
        using var input = new MemoryStream(bytes, writable: false);
        var findings = scanner.Scan(input, "LegacyRuntimeSmoke.dll").ToList();
        var result = ScanResultMapper.ToDto(findings, "LegacyRuntimeSmoke.dll", bytes, false);
        return $"{typeof(ModuleDefinition).Assembly.GetName().Version}|{result.AnalysisCompleteness.IsComplete}|" +
            $"{result.Disposition!.Classification}|{result.AnalysisCompleteness.Reasons.Count}";
    }

    private sealed class LegacyCecilContext(string cecilPath, string corePath)
        : AssemblyLoadContext(isCollectible: true)
    {
        protected override System.Reflection.Assembly? Load(System.Reflection.AssemblyName name) => name.Name switch
        {
            "Mono.Cecil" => LoadFromAssemblyPath(cecilPath),
            "MLVScan.Core" => LoadFromAssemblyPath(corePath),
            _ => null
        };
    }
}
