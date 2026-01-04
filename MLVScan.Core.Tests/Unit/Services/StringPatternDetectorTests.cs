using FluentAssertions;
using MLVScan.Services;
using MLVScan.Core.Tests.TestUtilities;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class StringPatternDetectorTests
{
    private readonly StringPatternDetector _detector = new();

    [Fact]
    public void HasAssemblyLoadingInMethod_WithAssemblyLoad_ReturnsTrue()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("LoadAssembly")
                    .EmitString("TestAssembly")
                    .EmitCall("System.Reflection.Assembly", "Load")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        var result = _detector.HasAssemblyLoadingInMethod(method, method.Body.Instructions);

        result.Should().BeTrue();
    }

    [Fact]
    public void HasAssemblyLoadingInMethod_WithLoadFrom_ReturnsTrue()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("LoadFromFile")
                    .EmitString("test.dll")
                    .EmitCall("System.Reflection.Assembly", "LoadFrom")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        var result = _detector.HasAssemblyLoadingInMethod(method, method.Body.Instructions);

        result.Should().BeTrue();
    }

    [Fact]
    public void HasAssemblyLoadingInMethod_NoAssemblyLoading_ReturnsFalse()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("SafeMethod")
                    .EmitString("Hello")
                    .EmitCall("System.Console", "WriteLine")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        var result = _detector.HasAssemblyLoadingInMethod(method, method.Body.Instructions);

        result.Should().BeFalse();
    }

    [Fact]
    public void HasSuspiciousStringPatterns_WithPowershellString_ReturnsTrue()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("SuspiciousMethod")
                    .EmitString("powershell.exe")
                    .EmitCall("System.Diagnostics.Process", "Start")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        // Check near the first instruction (index 0)
        var result = _detector.HasSuspiciousStringPatterns(method, method.Body.Instructions, 0);

        result.Should().BeTrue();
    }

    [Fact]
    public void HasSuspiciousStringPatterns_WithCmdExeString_ReturnsTrue()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("RunCmd")
                    .EmitString("cmd.exe")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        var result = _detector.HasSuspiciousStringPatterns(method, method.Body.Instructions, 0);

        result.Should().BeTrue();
    }

    [Fact]
    public void HasSuspiciousStringPatterns_WithBase64Call_ReturnsTrue()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("DecodeData")
                    .EmitString("SGVsbG8=")
                    .EmitCall("System.Convert", "FromBase64String")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        var result = _detector.HasSuspiciousStringPatterns(method, method.Body.Instructions, 1);

        result.Should().BeTrue();
    }

    [Fact]
    public void HasSuspiciousStringPatterns_SafeMethod_ReturnsFalse()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("SafeMethod")
                    .EmitString("Hello World")
                    .EmitCall("System.Console", "WriteLine")
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First();

        var result = _detector.HasSuspiciousStringPatterns(method, method.Body.Instructions, 0);

        result.Should().BeFalse();
    }

    [Fact]
    public void HasSuspiciousStringPatterns_WithEncodedString_ReturnsTrue()
    {
        // Create encoded "powershell" = 112-111-119-101-114-115-104-101-108-108
        var encodedPowershell = "112-111-119-101-114-115-104-101-108-108";
        
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestType")
                .AddMethod("EncodedMethod")
                    .EmitString(encodedPowershell)
                .EndMethod()
            .EndType()
            .Build();

        var type = assembly.MainModule.Types.First(t => t.Name == "TestType");
        var method = type.Methods.First(m => m.Name == "EncodedMethod");

        var result = _detector.HasSuspiciousStringPatterns(method, method.Body.Instructions, 0);

        result.Should().BeTrue();
    }
}
