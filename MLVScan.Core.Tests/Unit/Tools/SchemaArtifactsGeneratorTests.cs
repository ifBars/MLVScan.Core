using FluentAssertions;
using MLVScan.Tools.SchemaGen;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Tools;

public sealed class SchemaArtifactsGeneratorTests
{
    [Fact]
    public void GeneratedArtifacts_AreInSyncWithCheckedInFiles()
    {
        var repositoryRoot = SchemaArtifactsGenerator.FindRepositoryRoot(AppContext.BaseDirectory);

        Action verify = () => SchemaArtifactsGenerator.VerifyArtifacts(repositoryRoot);

        verify.Should().NotThrow();
    }
}
