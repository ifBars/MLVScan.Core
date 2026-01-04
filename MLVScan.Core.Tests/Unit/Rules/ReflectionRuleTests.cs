using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ReflectionRuleTests
{
    private readonly ReflectionRule _rule = new();

    [Fact]
    public void RuleId_ReturnsReflectionRule()
    {
        _rule.RuleId.Should().Be("ReflectionRule");
    }

    [Fact]
    public void Severity_ReturnsHigh()
    {
        _rule.Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsTrue()
    {
        // ReflectionRule requires companion findings to reduce false positives
        _rule.RequiresCompanionFinding.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Reflection.MethodInfo", "Invoke", true)]
    [InlineData("System.Reflection.MethodBase", "Invoke", true)]
    [InlineData("System.Reflection.MethodInfo", "GetParameters", false)]
    [InlineData("System.Reflection.Assembly", "Load", false)]
    [InlineData("System.Type", "GetMethod", false)]
    [InlineData("System.Activator", "CreateInstance", false)]
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
        var methodRef = MethodReferenceFactory.CreateWithNullType("Invoke");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_NoMethodBody_ReturnsEmpty()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("TestMethod")
                .EndMethodNoRet()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();
        method.Body = null;

        var signals = new MethodSignals();
        signals.MarkRuleTriggered("OtherRule");

        var findings = _rule.AnalyzeInstructions(method, null!, signals);

        findings.Should().BeEmpty();
    }
}
