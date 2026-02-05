using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class Shell32RuleTests
{
    private readonly Shell32Rule _rule = new();

    [Fact]
    public void RuleId_ReturnsShell32Rule()
    {
        _rule.RuleId.Should().Be("Shell32Rule");
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
    [InlineData("Shell.Application", "Execute", true)]
    [InlineData("Shell32.Shell", "Open", true)]
    [InlineData("MyNamespace.Shell32Helper", "DoSomething", true)]
    [InlineData("System.Object", "ShellExecute", true)]
    [InlineData("System.Object", "ShellExec", true)]
    [InlineData("System.Type", "GetTypeFromProgID", false)] // Context-dependent - needs string param analysis
    [InlineData("System.Type", "InvokeMember", false)] // Context-dependent - needs string param analysis
    [InlineData("System.Diagnostics.Process", "Start", false)]
    [InlineData("System.IO.File", "Open", false)]
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
        var methodRef = MethodReferenceFactory.CreateWithNullType("ShellExecute");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_GetTypeFromProgIdWithShellParameter_ReturnsTrue()
    {
        var methodRef = CreateMethodWithParameterNames("System.Type", "GetTypeFromProgID", "Shell.Application");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_InvokeMemberWithExecuteParameter_ReturnsTrue()
    {
        var methodRef = CreateMethodWithParameterNames("System.Type", "InvokeMember", "ShellExecute");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    [Fact]
    public void IsSuspicious_ProcessStartWithCmdParameter_ReturnsTrue()
    {
        var methodRef = CreateMethodWithParameterNames("System.Diagnostics.Process", "Start", "cmd.exe");

        _rule.IsSuspicious(methodRef).Should().BeTrue();
    }

    private static MethodReference CreateMethodWithParameterNames(string declaringTypeFullName, string methodName, params string[] paramNames)
    {
        var methodRef = MethodReferenceFactory.Create(declaringTypeFullName, methodName);
        foreach (var paramName in paramNames)
        {
            methodRef.Parameters.Add(new ParameterDefinition(paramName, ParameterAttributes.None, new TypeReference("System", "String", methodRef.Module, methodRef.Module.TypeSystem.CoreLibrary)));
        }

        return methodRef;
    }
}
