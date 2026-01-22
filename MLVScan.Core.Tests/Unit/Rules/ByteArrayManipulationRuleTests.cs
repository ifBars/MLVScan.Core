using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ByteArrayManipulationRuleTests
{
    private readonly ByteArrayManipulationRule _rule = new();

    [Fact]
    public void RuleId_ReturnsByteArrayManipulationRule()
    {
        _rule.RuleId.Should().Be("ByteArrayManipulationRule");
    }

    [Fact]
    public void Severity_ReturnsLow()
    {
        _rule.Severity.Should().Be(Severity.Low);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void Description_IsNotEmpty()
    {
        _rule.Description.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.Remediation.Should().NotBeNullOrWhiteSpace();
        _rule.DeveloperGuidance.IsRemediable.Should().BeTrue();
        _rule.DeveloperGuidance.AlternativeApis.Should().NotBeNull();
        _rule.DeveloperGuidance.AlternativeApis.Should().Contain("UnityEngine.AudioClip.LoadWAVData");
        _rule.DeveloperGuidance.AlternativeApis.Should().Contain("UnityEngine.Texture2D.LoadImage");
    }

    [Theory]
    [InlineData("System.Convert", "FromBase64String", true)]
    [InlineData("System.Convert", "FromBase64CharArray", true)]
    [InlineData("System.IO.MemoryStream", ".ctor", true)]
    [InlineData("System.Convert", "ToBase64String", false)]
    [InlineData("System.BitConverter", "ToInt32", false)]
    [InlineData("System.BitConverter", "GetBytes", false)]
    [InlineData("System.IO.FileStream", ".ctor", false)]
    [InlineData("System.String", "GetBytes", false)]
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
        var methodRef = MethodReferenceFactory.CreateWithNullType("FromBase64String");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_ConvertFromBase64String_ReturnsTrue()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64String");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_MemoryStreamConstructor_ReturnsTrue()
    {
        var methodRef = MethodReferenceFactory.Create("System.IO.MemoryStream", ".ctor");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_UnityAudioClipMethod_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("UnityEngine.AudioClip", "LoadWAVData");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_UnityTexture2DMethod_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("UnityEngine.Texture2D", "LoadImage");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_SystemTextEncodingGetBytes_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Text.Encoding", "GetBytes");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_ByteArrayCopy_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Array", "Copy");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_BufferBlockCopy_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("System.Buffer", "BlockCopy");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void Description_ContainsByteArray()
    {
        _rule.Description.Should().Contain("byte array");
    }

    [Fact]
    public void Description_ContainsManipulation()
    {
        _rule.Description.Should().Contain("manipulation");
    }

    [Fact]
    public void IsSuspicious_FromBase64CharArray_ReturnsTrue()
    {
        var methodRef = MethodReferenceFactory.Create("System.Convert", "FromBase64CharArray");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_MemoryStreamFromCustomNamespace_WithCtorName_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("MyApp.CustomMemoryStream", ".ctor");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_ConvertFromCustomNamespace_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.Create("MyApp.Convert", "FromBase64String");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }
}
