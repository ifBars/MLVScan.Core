using FluentAssertions;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class SuspiciousLocalVariableRuleTests
{
    private readonly SuspiciousLocalVariableRule _rule = new();

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        var methodRef = CreateMethodReference("System.String", "Concat");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_NoLocalVariables_ReturnsEmpty()
    {
        var method = CreateMethodWithLocals();

        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, new MethodSignals()).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_WithSuspiciousLocals_ReturnsFindingWithTruncatedDescription()
    {
        var method = CreateMethodWithLocals(
            "System.Diagnostics.Process",
            "System.Runtime.InteropServices.Marshal",
            "System.Net.WebClient",
            "System.Net.Http.HttpClient",
            "System.String");

        var findings = _rule.AnalyzeInstructions(method, method.Body!.Instructions, new MethodSignals()).ToList();

        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("System.Diagnostics.Process");
        findings[0].Description.Should().Contain("and 1 more");
        findings[0].CodeSnippet.Should().Contain("Suspicious local variable types detected");
    }

    private static MethodReference CreateMethodReference(string declaringTypeFullName, string methodName)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("LocalRuleMethodRefFactory", new Version(1, 0, 0, 0)),
            "LocalRuleMethodRefFactory",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var lastDot = declaringTypeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? declaringTypeFullName[..lastDot] : string.Empty;
        var typeName = lastDot > 0 ? declaringTypeFullName[(lastDot + 1)..] : declaringTypeFullName;
        var typeRef = new TypeReference(ns, typeName, module, module.TypeSystem.CoreLibrary);
        return new MethodReference(methodName, module.TypeSystem.Void, typeRef);
    }

    private static MethodDefinition CreateMethodWithLocals(params string[] localTypeNames)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("LocalRuleAssembly", new Version(1, 0, 0, 0)),
            "LocalRuleAssembly",
            ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "LocalType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        foreach (var fullName in localTypeNames)
        {
            var lastDot = fullName.LastIndexOf('.');
            var ns = lastDot > 0 ? fullName[..lastDot] : string.Empty;
            var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
            method.Body.Variables.Add(new VariableDefinition(new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary)));
        }

        var il = method.Body.GetILProcessor();
        il.Append(il.Create(OpCodes.Ret));
        return method;
    }
}
