using FluentAssertions;
using MLVScan.Services;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class CecilCompatibilityTests
{
    private sealed class LegacyCecilResolver(AssemblyDefinition legacy) : DefaultAssemblyResolver
    {
        public override AssemblyDefinition Resolve(AssemblyNameReference name, ReaderParameters parameters)
        {
            return name.Name == "Mono.Cecil"
                ? legacy
                : base.Resolve(name, parameters);
        }
    }

    [Fact]
    public void CoreCecilMemberReferences_AreAvailableInOldestSupportedRuntime()
    {
        // Hosts can supply an older Cecil than the package used to compile Core.
        // Inspect metadata only: do not load another Cecil into the test process.
        using var legacy = AssemblyDefinition.ReadAssembly(
            Path.Combine(AppContext.BaseDirectory, "Compatibility", "Mono.Cecil.dll"));
        using var resolver = new LegacyCecilResolver(legacy);
        legacy.Name.Version.Should().Be(new Version(0, 10, 4, 0));
        using var core = AssemblyDefinition.ReadAssembly(typeof(AssemblyScanner).Assembly.Location,
            new ReaderParameters { AssemblyResolver = resolver });

        // The resolver pins Cecil references regardless of the compile-time version.
        var references = core.MainModule.GetMemberReferences()
            .Where(member => member.DeclaringType.Scope is AssemblyNameReference { Name: "Mono.Cecil" })
            .ToArray();
        references.Should().NotBeEmpty();
        var missing = references
            .Where(member => member switch
            {
                MethodReference method => method.Resolve() is null,
                FieldReference field => field.Resolve() is null,
                _ => false
            })
            .Select(member => member.FullName)
            .ToArray();

        missing.Should().BeEmpty("Core must not call APIs missing from Cecil 0.10.4");
    }
}
