using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class RegistryRuleTests
{
    private readonly RegistryRule _rule = new();

    [Fact]
    public void RuleId_ReturnsRegistryRule()
    {
        _rule.RuleId.Should().Be("RegistryRule");
    }

    [Fact]
    public void Severity_ReturnsCritical()
    {
        _rule.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Theory]
    [InlineData("Microsoft.Win32.Registry", "GetValue", true)]
    [InlineData("Microsoft.Win32.RegistryKey", "SetValue", true)]
    [InlineData("Microsoft.Win32.RegistryHive", "Open", true)]
    [InlineData("System.Object", "RegCreateKeyEx", true)]
    [InlineData("System.Object", "RegOpenKey", true)]
    [InlineData("System.Object", "RegSetValue", true)]
    [InlineData("System.Object", "RegGetValue", true)]
    [InlineData("System.Object", "RegDeleteKey", true)]
    [InlineData("System.Object", "RegQueryValue", true)]
    [InlineData("System.IO.File", "Write", false)]
    [InlineData("System.String", "Concat", false)]
    public void IsSuspicious_VariousMethods_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var methodRef = MethodReferenceFactory.Create(typeName, methodName);

        var result = _rule.IsSuspicious(methodRef);

        result.Should().Be(expected);
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullDeclaringType_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.CreateWithNullType("RegSetValue");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }
}
