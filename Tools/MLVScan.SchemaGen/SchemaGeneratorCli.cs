namespace MLVScan.Tools.SchemaGen;

public static class SchemaGeneratorCli
{
    public static int Run(IReadOnlyList<string> arguments, TextWriter output, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);

        var verifyOnly = arguments.Any(static argument => string.Equals(argument, "--verify", StringComparison.Ordinal));
        var repositoryRootArgument = GetRepositoryRootArgument(arguments);
        var repositoryRoot = repositoryRootArgument ?? SchemaArtifactsGenerator.FindRepositoryRoot(baseDirectory);

        if (verifyOnly)
        {
            SchemaArtifactsGenerator.VerifyArtifacts(repositoryRoot);
            output.WriteLine("Schema artifacts are up to date.");
            return 0;
        }

        SchemaArtifactsGenerator.WriteArtifacts(repositoryRoot);
        output.WriteLine($"Generated schema artifacts in '{repositoryRoot}'.");
        return 0;
    }

    private static string? GetRepositoryRootArgument(IReadOnlyList<string> arguments)
    {
        for (var index = 0; index < arguments.Count - 1; index++)
        {
            if (string.Equals(arguments[index], "--repo-root", StringComparison.Ordinal))
            {
                return Path.GetFullPath(arguments[index + 1]);
            }
        }

        return null;
    }
}
