using System.Text;
using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
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

    [Fact]
    public void FindRepositoryRoot_WhenSolutionFileIsMissing_ThrowsDirectoryNotFoundException()
    {
        using var tempDirectory = new TemporaryDirectory();

        Action findRoot = () => SchemaArtifactsGenerator.FindRepositoryRoot(tempDirectory.RootPath);

        findRoot.Should()
            .Throw<DirectoryNotFoundException>()
            .WithMessage("*Unable to locate the MLVScan.Core repository root*");
    }

    [Fact]
    public void WriteArtifacts_CreatesFilesThatVerifySuccessfully()
    {
        using var repository = CreateTemporaryRepository();

        SchemaArtifactsGenerator.WriteArtifacts(repository.RootPath);

        foreach (var artifact in SchemaArtifactsGenerator.GetArtifacts())
        {
            File.Exists(Path.Combine(repository.RootPath, artifact.RelativePath)).Should().BeTrue();
        }

        Action verify = () => SchemaArtifactsGenerator.VerifyArtifacts(repository.RootPath);

        verify.Should().NotThrow();
    }

    [Fact]
    public void NormalizeLineEndings_ConvertsToLfAndAppendsTrailingNewline()
    {
        var normalizeLineEndings = typeof(SchemaArtifactsGenerator).GetMethod(
            "NormalizeLineEndings",
            global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Static)!;

        var normalized = (string)normalizeLineEndings.Invoke(null, ["line1\r\nline2\rline3"])!;

        normalized.Should().Be("line1\nline2\nline3\n");
    }

    [Fact]
    public void VerifyArtifacts_WhenArtifactIsMissing_ThrowsWithMissingArtifactMessage()
    {
        using var repository = CreateTemporaryRepository();
        SchemaArtifactsGenerator.WriteArtifacts(repository.RootPath);

        var missingArtifact = SchemaArtifactsGenerator.GetArtifacts()[0];
        File.Delete(Path.Combine(repository.RootPath, missingArtifact.RelativePath));

        Action verify = () => SchemaArtifactsGenerator.VerifyArtifacts(repository.RootPath);

        verify.Should()
            .Throw<InvalidOperationException>()
            .WithMessage($"*Missing artifact: {missingArtifact.RelativePath}*");
    }

    [Fact]
    public void VerifyArtifacts_WhenArtifactIsOutOfDate_ThrowsWithOutOfDateArtifactMessage()
    {
        using var repository = CreateTemporaryRepository();
        SchemaArtifactsGenerator.WriteArtifacts(repository.RootPath);

        var staleArtifact = SchemaArtifactsGenerator.GetArtifacts()[1];
        var artifactPath = Path.Combine(repository.RootPath, staleArtifact.RelativePath);
        File.AppendAllText(artifactPath, "// stale");

        Action verify = () => SchemaArtifactsGenerator.VerifyArtifacts(repository.RootPath);

        verify.Should()
            .Throw<InvalidOperationException>()
            .WithMessage($"*Out-of-date artifact: {staleArtifact.RelativePath}*");
    }

    private static TemporaryDirectory CreateTemporaryRepository()
    {
        var tempDirectory = new TemporaryDirectory();
        File.WriteAllText(Path.Combine(tempDirectory.RootPath, "MLVScan.Core.sln"), string.Empty);
        return tempDirectory;
    }
}
