using System.Text;
using MLVScan.Models.Dto;

namespace MLVScan.Tools.SchemaGen;

public static class SchemaArtifactsGenerator
{
    private static readonly IReadOnlyList<string> ArtifactPaths =
    [
        Path.Combine("schema", "mlvscan-result.schema.json"),
        Path.Combine("schema", "generated", "mlvscan-schema.ts"),
        Path.Combine("MLVScan.WASM", "npm", "src", "generated", "mlvscan-schema.ts")
    ];

    public static GeneratedSchemaArtifacts Generate()
    {
        var objectTypes = TypeDiscovery.CollectSchemaObjectTypes(typeof(ScanResultDto));
        var stringUnions = TypeDiscovery.CollectStringUnions(objectTypes);
        var jsonSchema = new JsonSchemaBuilder(objectTypes).Build();
        var typeScriptDefinitions = NormalizeLineEndings(new TypeScriptDefinitionBuilder(objectTypes, stringUnions).Build());

        return new GeneratedSchemaArtifacts(jsonSchema, typeScriptDefinitions);
    }

    public static IReadOnlyList<GeneratedArtifact> GetArtifacts()
    {
        var generatedArtifacts = Generate();

        return
        [
            new GeneratedArtifact(ArtifactPaths[0], generatedArtifacts.JsonSchema),
            new GeneratedArtifact(ArtifactPaths[1], generatedArtifacts.TypeScriptDefinitions),
            new GeneratedArtifact(ArtifactPaths[2], generatedArtifacts.TypeScriptDefinitions)
        ];
    }

    public static string FindRepositoryRoot(string startDirectory)
    {
        var currentDirectory = new DirectoryInfo(Path.GetFullPath(startDirectory));

        while (currentDirectory != null)
        {
            if (File.Exists(Path.Combine(currentDirectory.FullName, "MLVScan.Core.sln")))
            {
                return currentDirectory.FullName;
            }

            currentDirectory = currentDirectory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"Unable to locate the MLVScan.Core repository root from '{startDirectory}'.");
    }

    public static void WriteArtifacts(string repositoryRoot)
    {
        foreach (var artifact in GetArtifacts())
        {
            var fullPath = Path.Combine(repositoryRoot, artifact.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            File.WriteAllText(fullPath, NormalizeLineEndings(artifact.Contents), new UTF8Encoding(false));
        }
    }

    public static void VerifyArtifacts(string repositoryRoot)
    {
        var mismatches = new List<string>();

        foreach (var artifact in GetArtifacts())
        {
            var fullPath = Path.Combine(repositoryRoot, artifact.RelativePath);

            if (!File.Exists(fullPath))
            {
                mismatches.Add($"Missing artifact: {artifact.RelativePath}");
                continue;
            }

            var actual = NormalizeLineEndings(File.ReadAllText(fullPath));
            var expected = NormalizeLineEndings(artifact.Contents);

            if (!string.Equals(actual, expected, StringComparison.Ordinal))
            {
                mismatches.Add($"Out-of-date artifact: {artifact.RelativePath}");
            }
        }

        if (mismatches.Count > 0)
        {
            throw new InvalidOperationException(
                "Schema artifacts are out of sync. Run the schema generator.\n" + string.Join("\n", mismatches));
        }
    }

    private static string NormalizeLineEndings(string content)
    {
        var normalized = content.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", "\n", StringComparison.Ordinal);

        return normalized.EndsWith("\n", StringComparison.Ordinal) ? normalized : normalized + "\n";
    }
}
