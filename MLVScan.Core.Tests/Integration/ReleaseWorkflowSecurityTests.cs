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

    [Fact]
    public void NuGetPublishWorkflow_UsesTrustedPublishingOnlyInIsolatedPublishJob()
    {
        var workflow = ReadWorkflow("publish-nuget.yml");
        int publishJob = workflow.IndexOf("\n  publish:\n", StringComparison.Ordinal);

        publishJob.Should().BeGreaterThan(0);
        workflow[..publishJob].Should().NotContain("id-token: write");
        workflow[publishJob..].Should().Contain("id-token: write");
        workflow.Should().NotContain("secrets.NUGET_API_KEY");
        workflow[publishJob..].Should().Contain("uses: nuget/login@v1");
        workflow[publishJob..].Should().Contain("steps.nuget-login.outputs.NUGET_API_KEY");
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
