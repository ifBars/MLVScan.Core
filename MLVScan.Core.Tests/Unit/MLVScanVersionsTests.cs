using System.Text.RegularExpressions;
using System.Text.Json;
using System.Xml.Linq;
using FluentAssertions;
using MLVScan;
using Xunit;

namespace MLVScan.Core.Tests.Unit;

public class MLVScanVersionsTests
{
    [Fact]
    public void SchemaVersion_IsNotEmpty()
    {
        MLVScanVersions.SchemaVersion.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void SchemaVersion_IsValidSemver()
    {
        var parts = MLVScanVersions.SchemaVersion.Split('.');

        parts.Should().HaveCount(3, "schema version should follow semver format (major.minor.patch)");
        foreach (var part in parts)
        {
            int.TryParse(part, out _).Should().BeTrue("all parts should be numeric");
        }
    }

    [Fact]
    public void CoreVersion_IsNotEmpty()
    {
        MLVScanVersions.CoreVersion.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void CoreVersion_MatchesDeclaredCoreConstant()
    {
#pragma warning disable CS0618
        MLVScanVersions.CoreVersion.Should().Be(Constants.CoreVersion);
#pragma warning restore CS0618
    }

    [Fact]
    public void CoreVersion_IsValidSemverOrFallback()
    {
        var version = MLVScanVersions.CoreVersion;

        // Should either be a valid semver or the fallback "0.0.0"
        var parts = version.Split('.');
        parts.Length.Should().BeGreaterThanOrEqualTo(3, "version should have at least major.minor.patch");
    }

    [Fact]
    public void CoreVersion_Property_IsStableAcrossCalls()
    {
        var version1 = MLVScanVersions.CoreVersion;
        var version2 = MLVScanVersions.CoreVersion;

        version1.Should().Be(version2);
    }

    [Fact]
    public void GetVersionString_ContainsCoreVersion()
    {
        MLVScanVersions.GetVersionString().Should().Be($"MLVScan.Core v{MLVScanVersions.CoreVersion}");
    }

    [Fact]
    public void SchemaVersion_Property_ReturnsExpectedConstant()
    {
        MLVScanVersions.SchemaVersion.Should().Be("1.2.0");
    }

    [Fact]
    public void LegacyGetterMethods_RemainCompatible()
    {
#pragma warning disable CS0618
        MLVScanVersions.GetCoreVersion().Should().Be(MLVScanVersions.CoreVersion);
        MLVScanVersions.GetSchemaVersion().Should().Be(MLVScanVersions.SchemaVersion);
#pragma warning restore CS0618
    }

    [Fact]
    public void CoreVersion_IsConsistentAcrossMultipleCalls()
    {
        var version1 = MLVScanVersions.CoreVersion;
        var version2 = MLVScanVersions.CoreVersion;

        version1.Should().Be(version2);
    }

    [Fact]
    public void CoreVersion_BeginsWithThreeNumericSegments()
    {
        var match = Regex.Match(MLVScanVersions.CoreVersion, @"^\d+\.\d+\.\d+");

        match.Success.Should().BeTrue();
    }

    [Fact]
    public void CoreVersion_MatchesDirectoryBuildPropsVersion()
    {
        var propsVersion = ReadDirectoryBuildPropsVersion();

        MLVScanVersions.CoreVersion.Should().Be(propsVersion);
    }

    [Fact]
    public void CoreVersion_MatchesWasmNpmPackageVersion()
    {
        var propsVersion = ReadDirectoryBuildPropsVersion();
        var packageVersion = ReadJsonStringProperty(
            FindRepositoryPath("MLVScan.WASM", "npm", "package.json"),
            "version");

        packageVersion.Should().Be(propsVersion);
    }

    [Fact]
    public void CoreVersion_MatchesWasmNpmPackageLockRootVersions()
    {
        var propsVersion = ReadDirectoryBuildPropsVersion();
        var packageLockPath = FindRepositoryPath("MLVScan.WASM", "npm", "package-lock.json");
        using var document = JsonDocument.Parse(File.ReadAllText(packageLockPath));

        document.RootElement.GetProperty("version").GetString().Should().Be(propsVersion);
        document.RootElement
            .GetProperty("packages")
            .GetProperty("")
            .GetProperty("version")
            .GetString()
            .Should()
            .Be(propsVersion);
    }

    private static string ReadDirectoryBuildPropsVersion()
    {
        var propsVersion = XDocument.Load(FindRepositoryFile("Directory.Build.props"))
            .Root?
            .Elements("PropertyGroup")
            .Elements("Version")
            .Select(element => element.Value.Trim())
            .FirstOrDefault();

        propsVersion.Should().NotBeNullOrWhiteSpace();
        return propsVersion!;
    }

    private static string ReadJsonStringProperty(string path, string propertyName)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var value = document.RootElement.GetProperty(propertyName).GetString();

        value.Should().NotBeNullOrWhiteSpace();
        return value!;
    }

    private static string FindRepositoryFile(string fileName)
        => FindRepositoryPath(fileName);

    private static string FindRepositoryPath(params string[] pathSegments)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(pathSegments).ToArray());
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find {Path.Combine(pathSegments)} from {AppContext.BaseDirectory}.");
    }
}
