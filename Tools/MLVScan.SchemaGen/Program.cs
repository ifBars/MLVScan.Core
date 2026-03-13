using MLVScan.Tools.SchemaGen;

var verifyOnly = args.Any(static argument => string.Equals(argument, "--verify", StringComparison.Ordinal));
var repositoryRootArgument = GetRepositoryRootArgument(args);
var repositoryRoot = repositoryRootArgument ?? SchemaArtifactsGenerator.FindRepositoryRoot(AppContext.BaseDirectory);

if (verifyOnly)
{
    SchemaArtifactsGenerator.VerifyArtifacts(repositoryRoot);
    Console.WriteLine("Schema artifacts are up to date.");
    return;
}

SchemaArtifactsGenerator.WriteArtifacts(repositoryRoot);
Console.WriteLine($"Generated schema artifacts in '{repositoryRoot}'.");

static string? GetRepositoryRootArgument(IReadOnlyList<string> arguments)
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
