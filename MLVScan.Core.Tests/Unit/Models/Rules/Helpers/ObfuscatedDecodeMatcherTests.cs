using System.Reflection;
using FluentAssertions;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;
using MethodAttributes = Mono.Cecil.MethodAttributes;

namespace MLVScan.Core.Tests.Unit.Models.Rules.Helpers;

public class ObfuscatedDecodeMatcherTests
{
    private static readonly Assembly CoreAssembly = typeof(MLVScan.Models.ScanFinding).Assembly;
    private static readonly Type MatcherType = CoreAssembly.GetType("MLVScan.Models.Rules.Helpers.ObfuscatedDecodeMatcher")!;

    private static readonly MethodInfo TryGetDecodeCallScoreMethod =
        MatcherType.GetMethod("TryGetDecodeCallScore", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo TryGetDangerLiteralMarkerMethod =
        MatcherType.GetMethod("TryGetDangerLiteralMarker", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsHexLikeLiteralMethod =
        MatcherType.GetMethod("IsHexLikeLiteral", BindingFlags.Static | BindingFlags.Public)!;

    #region TryGetDecodeCallScore - String Reversal Tests

    [Theory]
    [InlineData("CustomHelper", "ReverseString", "System.String")]
    [InlineData("MyUtils", "reverse", "System.String")]
    [InlineData("Obfuscator", "REVERSE", "System.String")]
    public void TryGetDecodeCallScore_ReverseMethods_ReturnsTrue(string typeName, string methodName, string returnType)
    {
        var methodRef = CreateMethodReference(typeName, methodName, returnType);
        var result = InvokeTryGetDecodeCallScore(methodRef, typeName, methodName);

        result.success.Should().BeTrue();
        result.score.Should().BeGreaterThan(0);
        result.reason.Should().Contain("reversal");
        result.isStrongDecodePrimitive.Should().BeTrue();
    }

    [Fact]
    public void TryGetDecodeCallScore_ArrayReverse_ReturnsTrue()
    {
        var methodRef = CreateMethodReference("System.Array", "Reverse", "System.Void");
        var result = InvokeTryGetDecodeCallScore(methodRef, "System.Array", "Reverse");

        result.success.Should().BeTrue();
        result.score.Should().Be(7);
        result.reason.Should().Contain("array reversal");
        result.isStrongDecodePrimitive.Should().BeTrue();
    }

    [Fact]
    public void TryGetDecodeCallScore_EnumerableReverse_ReturnsTrue()
    {
        var methodRef = CreateMethodReference("System.Linq.Enumerable", "Reverse", "System.Collections.Generic.IEnumerable`1");
        var result = InvokeTryGetDecodeCallScore(methodRef, "System.Linq.Enumerable", "Reverse");

        result.success.Should().BeTrue();
        result.score.Should().Be(7);
        result.reason.Should().Contain("sequence reversal");
        result.isStrongDecodePrimitive.Should().BeTrue();
    }

    #endregion

    #region TryGetDecodeCallScore - String Concat Tests

    [Fact]
    public void TryGetDecodeCallScore_StringConcatWithManyParams_ReturnsTrue()
    {
        var module = CreateTestModule();
        var methodRef = new MethodReference("Concat", module.TypeSystem.String,
            new TypeReference("System", "String", module, module));
        
        methodRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        methodRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        methodRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        methodRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

        var result = InvokeTryGetDecodeCallScore(methodRef, "System.String", "Concat");

        result.success.Should().BeTrue();
        result.score.Should().Be(6);
        result.reason.Should().Contain("multi-string concatenation");
        result.isStrongDecodePrimitive.Should().BeTrue();
    }

    #endregion

    #region TryGetDangerLiteralMarker - Reversed Strings Tests

    [Fact]
    public void TryGetDangerLiteralMarker_ReversedCmdExe_ReturnsTrue()
    {
        var result = InvokeTryGetDangerLiteralMarker("exe.dmc");

        result.success.Should().BeTrue();
        result.marker.Should().Contain("cmd.exe");
        result.marker.Should().Contain("reversed");
    }

    [Fact]
    public void TryGetDangerLiteralMarker_ReversedPowershell_ReturnsTrue()
    {
        var result = InvokeTryGetDangerLiteralMarker("llehsrewop");

        result.success.Should().BeTrue();
        result.marker.Should().Contain("powershell");
    }

    [Fact]
    public void TryGetDangerLiteralMarker_DirectMatch_ReturnsTrue()
    {
        var result = InvokeTryGetDangerLiteralMarker("cmd.exe");

        result.success.Should().BeTrue();
        result.marker.Should().Be("cmd.exe");
    }

    [Fact]
    public void TryGetDangerLiteralMarker_NonSuspicious_ReturnsFalse()
    {
        var result = InvokeTryGetDangerLiteralMarker("harmless.txt");

        result.success.Should().BeFalse();
        result.marker.Should().BeEmpty();
    }

    #endregion

    #region IsHexLikeLiteral - Threshold Tests

    [Fact]
    public void IsHexLikeLiteral_TwelveChars_ReturnsTrue()
    {
        var result = InvokeIsHexLikeLiteral("50726f636573");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsHexLikeLiteral_FourteenChars_ReturnsTrue()
    {
        var result = InvokeIsHexLikeLiteral("50726f63657373");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsHexLikeLiteral_TenChars_ReturnsFalse()
    {
        var result = InvokeIsHexLikeLiteral("50726f6365");

        result.Should().BeFalse();
    }

    #endregion

    #region Helper Methods

    private static (bool success, int score, string reason, bool isStrongDecodePrimitive) InvokeTryGetDecodeCallScore(
        MethodReference calledMethod, string typeName, string methodName)
    {
        object?[] parameters = { calledMethod, typeName, methodName, 0, null, false };
        var result = (bool)TryGetDecodeCallScoreMethod.Invoke(null, parameters)!;

        return (result, (int)parameters[3]!, (string)parameters[4]!, (bool)parameters[5]!);
    }

    private static (bool success, string marker) InvokeTryGetDangerLiteralMarker(string literal)
    {
        object?[] parameters = { literal, null };
        var result = (bool)TryGetDangerLiteralMarkerMethod.Invoke(null, parameters)!;

        return (result, (string)parameters[1]!);
    }

    private static bool InvokeIsHexLikeLiteral(string literal)
    {
        return (bool)IsHexLikeLiteralMethod.Invoke(null, new object[] { literal })!;
    }

    private static MethodReference CreateMethodReference(string typeName, string methodName, string returnTypeName)
    {
        var module = CreateTestModule();
        var returnType = new TypeReference("", returnTypeName, module, module);
        var declaringType = new TypeReference("", typeName, module, module);
        return new MethodReference(methodName, returnType, declaringType);
    }

    private static ModuleDefinition CreateTestModule()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("TestAssembly", new Version(1, 0)),
            "TestModule",
            ModuleKind.Dll);
        return assembly.MainModule;
    }

    #endregion
}
