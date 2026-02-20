using FluentAssertions;
using MLVScan.Models.CrossAssembly;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Models.CrossAssembly;

/// <summary>
/// Tests for CrossAssembly model enums to ensure values are stable and correctly defined.
/// </summary>
public class CrossAssemblyEnumTests
{
    #region QuarantinePolicy Tests

    [Fact]
    public void QuarantinePolicy_HasExpectedValues()
    {
        var values = Enum.GetValues(typeof(QuarantinePolicy)).Cast<int>().ToList();

        values.Should().ContainInOrder(0, 1, 2);
        values.Count.Should().Be(3);
    }

    [Theory]
    [InlineData(QuarantinePolicy.CallerOnly, 0, "CallerOnly")]
    [InlineData(QuarantinePolicy.CallerAndCallee, 1, "CallerAndCallee")]
    [InlineData(QuarantinePolicy.DependencyCluster, 2, "DependencyCluster")]
    public void QuarantinePolicy_ValueHasExpectedNameAndOrdinal(QuarantinePolicy policy, int expectedValue, string expectedName)
    {
        ((int)policy).Should().Be(expectedValue);
        policy.ToString().Should().Be(expectedName);
    }

    [Fact]
    public void QuarantinePolicy_CallerOnly_IsDefault()
    {
        var defaultPolicy = default(QuarantinePolicy);
        defaultPolicy.Should().Be(QuarantinePolicy.CallerOnly);
        ((int)defaultPolicy).Should().Be(0);
    }

    [Theory]
    [InlineData(QuarantinePolicy.CallerOnly, false)]
    [InlineData(QuarantinePolicy.CallerAndCallee, true)]
    [InlineData(QuarantinePolicy.DependencyCluster, true)]
    public void QuarantinePolicy_IncludesCallee_ReturnsExpected(QuarantinePolicy policy, bool expectedIncludesCallee)
    {
        var includesCallee = policy == QuarantinePolicy.CallerAndCallee || policy == QuarantinePolicy.DependencyCluster;
        includesCallee.Should().Be(expectedIncludesCallee);
    }

    [Theory]
    [InlineData(QuarantinePolicy.CallerOnly, false)]
    [InlineData(QuarantinePolicy.CallerAndCallee, false)]
    [InlineData(QuarantinePolicy.DependencyCluster, true)]
    public void QuarantinePolicy_IncludesFullCluster_ReturnsExpected(QuarantinePolicy policy, bool expectedIncludesCluster)
    {
        var includesCluster = policy == QuarantinePolicy.DependencyCluster;
        includesCluster.Should().Be(expectedIncludesCluster);
    }

    #endregion

    #region AssemblyArtifactRole Tests

    [Fact]
    public void AssemblyArtifactRole_HasExpectedValues()
    {
        var values = Enum.GetValues(typeof(AssemblyArtifactRole)).Cast<int>().ToList();

        values.Should().ContainInOrder(0, 1, 2, 3, 4, 5);
        values.Count.Should().Be(6);
    }

    [Theory]
    [InlineData(AssemblyArtifactRole.Unknown, 0, "Unknown")]
    [InlineData(AssemblyArtifactRole.Mod, 1, "Mod")]
    [InlineData(AssemblyArtifactRole.Plugin, 2, "Plugin")]
    [InlineData(AssemblyArtifactRole.UserLib, 3, "UserLib")]
    [InlineData(AssemblyArtifactRole.Patcher, 4, "Patcher")]
    [InlineData(AssemblyArtifactRole.ExternalReference, 5, "ExternalReference")]
    public void AssemblyArtifactRole_ValueHasExpectedNameAndOrdinal(AssemblyArtifactRole role, int expectedValue, string expectedName)
    {
        ((int)role).Should().Be(expectedValue);
        role.ToString().Should().Be(expectedName);
    }

    [Fact]
    public void AssemblyArtifactRole_Unknown_IsDefault()
    {
        var defaultRole = default(AssemblyArtifactRole);
        defaultRole.Should().Be(AssemblyArtifactRole.Unknown);
        ((int)defaultRole).Should().Be(0);
    }

    [Theory]
    [InlineData(AssemblyArtifactRole.Unknown, false)]
    [InlineData(AssemblyArtifactRole.Mod, true)]
    [InlineData(AssemblyArtifactRole.Plugin, true)]
    [InlineData(AssemblyArtifactRole.UserLib, true)]
    [InlineData(AssemblyArtifactRole.Patcher, true)]
    [InlineData(AssemblyArtifactRole.ExternalReference, false)]
    public void AssemblyArtifactRole_IsLocalArtifact_ReturnsExpected(AssemblyArtifactRole role, bool expectedIsLocal)
    {
        var isLocal = role != AssemblyArtifactRole.Unknown && role != AssemblyArtifactRole.ExternalReference;
        isLocal.Should().Be(expectedIsLocal);
    }

    [Theory]
    [InlineData(AssemblyArtifactRole.Patcher, true)]
    [InlineData(AssemblyArtifactRole.Mod, false)]
    [InlineData(AssemblyArtifactRole.Plugin, false)]
    [InlineData(AssemblyArtifactRole.UserLib, false)]
    [InlineData(AssemblyArtifactRole.ExternalReference, false)]
    [InlineData(AssemblyArtifactRole.Unknown, false)]
    public void AssemblyArtifactRole_IsPatcher_ReturnsExpected(AssemblyArtifactRole role, bool expectedIsPatcher)
    {
        var isPatcher = role == AssemblyArtifactRole.Patcher;
        isPatcher.Should().Be(expectedIsPatcher);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void QuarantinePolicy_CanBeUsedInDictionary()
    {
        var policyMap = new Dictionary<QuarantinePolicy, string>
        {
            [QuarantinePolicy.CallerOnly] = "Minimal",
            [QuarantinePolicy.CallerAndCallee] = "Standard",
            [QuarantinePolicy.DependencyCluster] = "Aggressive"
        };

        policyMap.Should().HaveCount(3);
        policyMap[QuarantinePolicy.CallerOnly].Should().Be("Minimal");
        policyMap[QuarantinePolicy.DependencyCluster].Should().Be("Aggressive");
    }

    [Fact]
    public void AssemblyArtifactRole_CanBeUsedInDictionary()
    {
        var roleMap = new Dictionary<AssemblyArtifactRole, int>
        {
            [AssemblyArtifactRole.Mod] = 100,
            [AssemblyArtifactRole.Plugin] = 80,
            [AssemblyArtifactRole.UserLib] = 60,
            [AssemblyArtifactRole.Patcher] = 95,
            [AssemblyArtifactRole.ExternalReference] = 20
        };

        roleMap.Should().HaveCount(5);
        roleMap[AssemblyArtifactRole.Patcher].Should().Be(95);
        roleMap[AssemblyArtifactRole.ExternalReference].Should().Be(20);
    }

    [Fact]
    public void Enums_CanBeParsedFromString()
    {
        Enum.TryParse<QuarantinePolicy>("CallerAndCallee", out var policy).Should().BeTrue();
        policy.Should().Be(QuarantinePolicy.CallerAndCallee);

        Enum.TryParse<AssemblyArtifactRole>("Patcher", out var role).Should().BeTrue();
        role.Should().Be(AssemblyArtifactRole.Patcher);
    }

    [Fact]
    public void Enums_ParsingInvalidValue_ReturnsFalse()
    {
        Enum.TryParse<QuarantinePolicy>("InvalidPolicy", out _).Should().BeFalse();
        Enum.TryParse<AssemblyArtifactRole>("InvalidRole", out _).Should().BeFalse();
    }

    #endregion
}
