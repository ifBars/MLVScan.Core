using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Tools.SchemaGen;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Tools;

public sealed class SchemaGeneratorCliTests
{
    [Fact]
    public void Run_WithVerifyAndExplicitRepositoryRoot_WritesSuccessMessage()
    {
        using var repository = CreateTemporaryRepository();
        SchemaArtifactsGenerator.WriteArtifacts(repository.RootPath);
        using var output = new StringWriter();

        var exitCode = SchemaGeneratorCli.Run(
            new[] { "--verify", "--repo-root", repository.RootPath },
            output,
            Path.Combine(repository.RootPath, "nested"));

        exitCode.Should().Be(0);
        output.ToString().Should().Contain("Schema artifacts are up to date.");
    }

    [Fact]
    public void Run_WithoutRepositoryRootArgument_ResolvesFromBaseDirectoryAndWritesArtifacts()
    {
        using var repository = CreateTemporaryRepository();
        using var output = new StringWriter();
        var baseDirectory = Path.Combine(repository.RootPath, "artifacts", "bin", "Debug");
        Directory.CreateDirectory(baseDirectory);

        var exitCode = SchemaGeneratorCli.Run(Array.Empty<string>(), output, baseDirectory);

        exitCode.Should().Be(0);
        output.ToString().Should().Contain(repository.RootPath);

        foreach (var artifact in SchemaArtifactsGenerator.GetArtifacts())
        {
            File.Exists(Path.Combine(repository.RootPath, artifact.RelativePath)).Should().BeTrue();
        }
    }

    [Fact]
    public void ProgramMain_WithVerifyArgument_ReturnsSuccess()
    {
        var repositoryRoot = SchemaArtifactsGenerator.FindRepositoryRoot(AppContext.BaseDirectory);
        var originalOut = Console.Out;
        using var output = new StringWriter();

        try
        {
            Console.SetOut(output);

            var exitCode = Program.Main(["--verify", "--repo-root", repositoryRoot]);

            exitCode.Should().Be(0);
            output.ToString().Should().Contain("Schema artifacts are up to date.");
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    private static TemporaryDirectory CreateTemporaryRepository()
    {
        var tempDirectory = new TemporaryDirectory();
        File.WriteAllText(Path.Combine(tempDirectory.RootPath, "MLVScan.Core.sln"), string.Empty);
        return tempDirectory;
    }
}
