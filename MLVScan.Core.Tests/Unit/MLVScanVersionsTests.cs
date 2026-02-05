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
    public void CoreVersion_IsValidSemverOrFallback()
    {
        var version = MLVScanVersions.CoreVersion;
        
        // Should either be a valid semver or the fallback "0.0.0"
        var parts = version.Split('.');
        parts.Length.Should().BeGreaterThanOrEqualTo(3, "version should have at least major.minor.patch");
    }

    [Fact]
    public void GetCoreVersion_ReturnsSameAsCoreVersionProperty()
    {
        MLVScanVersions.GetCoreVersion().Should().Be(MLVScanVersions.CoreVersion);
    }

    [Fact]
    public void GetSchemaVersion_ReturnsSameAsSchemaVersionConstant()
    {
        MLVScanVersions.GetSchemaVersion().Should().Be(MLVScanVersions.SchemaVersion);
    }

    [Fact]
    public void GetSchemaVersion_Returns_1_0_0()
    {
        MLVScanVersions.GetSchemaVersion().Should().Be("1.0.0");
    }

    [Fact]
    public void CoreVersion_IsConsistentAcrossMultipleCalls()
    {
        var version1 = MLVScanVersions.CoreVersion;
        var version2 = MLVScanVersions.CoreVersion;
        var version3 = MLVScanVersions.GetCoreVersion();

        version1.Should().Be(version2);
        version1.Should().Be(version3);
    }
}
