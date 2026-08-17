using FluentAssertions;
using Xunit;

namespace MLVScan.Core.Tests.Integration;

public sealed class ReleaseWorkflowSecurityTests
{
    [Theory]
    [InlineData("auto-release.yml")]
    [InlineData("publish-nuget.yml")]
    [InlineData("publish-npm.yml")]
    public void ReleaseWorkflow_UsesValidatedEnvironmentValuesAndNonPersistentCheckout(string workflowName)
    {
        var workflow = ReadWorkflow(workflowName);

        workflow.Should().Contain("persist-credentials: false");
        workflow.Should().Contain("Invalid semantic version");
        workflow.Should().NotContain("PAT_TOKEN");
        workflow.Should().NotContain("VERSION=\"${{");
        workflow.Should().NotContain("PackageVersion=${{");
        workflow.Should().NotContain("npm version ${{");
    }

    [Theory]
    [InlineData("publish-nuget.yml", "NUGET_API_KEY")]
    [InlineData("publish-npm.yml", "NPM_TOKEN")]
    public void PublishWorkflow_ExposesRegistryCredentialOnlyInIsolatedPublishJob(
        string workflowName,
        string credentialName)
    {
        var workflow = ReadWorkflow(workflowName);
        int publishJob = workflow.IndexOf("\n  publish:\n", StringComparison.Ordinal);
        string secretReference = $"secrets.{credentialName}";

        publishJob.Should().BeGreaterThan(0);
        workflow.IndexOf("\n    permissions: {}\n", publishJob, StringComparison.Ordinal)
            .Should().BeGreaterThan(publishJob);
        workflow[..publishJob].Should().NotContain(secretReference);
        workflow[publishJob..].Should().Contain(secretReference);
    }

    private static string ReadWorkflow(string workflowName)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Directory.Build.props")))
            directory = directory.Parent;

        directory.Should().NotBeNull("the test must run beneath the repository root");
        return File.ReadAllText(Path.Combine(directory!.FullName, ".github", "workflows", workflowName))
            .Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
