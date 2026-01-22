using FluentAssertions;
using MLVScan;
using Xunit;

namespace MLVScan.Core.Tests.Unit;

public class ConstantsTests
{
    [Fact]
    public void CoreVersion_IsNotNullOrEmpty()
    {
        Constants.CoreVersion.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void CoreVersion_HasExpectedFormat()
    {
        var version = Constants.CoreVersion;
        version.Should().MatchRegex(@"^\d+\.\d+\.\d+$", "version should be in format X.Y.Z");
    }

    [Fact]
    public void GetVersionString_ContainsPrefix()
    {
        var versionString = Constants.GetVersionString();
        
        versionString.Should().StartWith("MLVScan.Core v");
    }

    [Fact]
    public void GetVersionString_ContainsCoreVersion()
    {
        var versionString = Constants.GetVersionString();
        
        versionString.Should().Contain(Constants.CoreVersion);
    }

    [Fact]
    public void GetVersionString_ReturnsExpectedFormat()
    {
        var versionString = Constants.GetVersionString();
        
        versionString.Should().Be($"MLVScan.Core v{Constants.CoreVersion}");
    }
}
