using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules;

public class EncodedStringPipelineRuleTests
{
    private readonly EncodedStringPipelineRule _rule = new();

    [Fact]
    public void RuleMetadata_IsExpected()
    {
        _rule.RuleId.Should().Be("EncodedStringPipelineRule");
        _rule.Description.Should().Be("Detected encoded string to char decoding pipeline (ASCII number or invisible Unicode pattern).");
        _rule.Severity.Should().Be(Severity.High);
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_AlwaysReturnsFalse()
    {
        _rule.IsSuspicious(MethodReferenceFactory.Create("TestClass", "TestMethod")).Should().BeFalse();
    }

    [Fact]
    public void AnalyzeInstructions_DetectsSelectStringCharAndConcatCharPattern()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        findings.Should().HaveCount(1);
        findings[0].Location.Should().Be("TestNamespace.TestClass.TestMethod");
        findings[0].Severity.Should().Be(Severity.High);
        findings[0].Description.Should().Contain("encoded string to char decoding pipeline");
    }

    [Fact]
    public void AnalyzeInstructions_DetectsFullPatternWithInt32ParseAndConvU2()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Ldstr, "123");
        context.Emit(OpCodes.Call, CreateParseMethod(context.Module, context.Module.TypeSystem.String));
        context.Emit(OpCodes.Conv_U2);
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        findings.Should().HaveCount(1);
        findings[0].Location.Should().Be("TestNamespace.TestClass.TestMethod");
        findings[0].CodeSnippet.Should().Contain("call");
        findings[0].CodeSnippet.Should().Contain("conv.u2");
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, true, true)]
    public void AnalyzeInstructions_DetectsOnlyWhenSelectAndConcatMatch(bool includeSelect, bool includeConcat, bool expectedFinding)
    {
        var context = CreateContext();

        if (includeSelect)
        {
            context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        }

        if (includeConcat)
        {
            context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        }

        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        if (expectedFinding)
        {
            findings.Should().HaveCount(1);
        }
        else
        {
            findings.Should().BeEmpty();
        }
    }

    [Fact]
    public void AnalyzeInstructions_DoesNotDetect_WhenSelectNotStringCharGeneric()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.Int32, context.Module.TypeSystem.String));
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        Analyze(context.Method).Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_DoesNotDetect_WhenConcatNotCharGeneric()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.String));
        context.Emit(OpCodes.Ret);

        Analyze(context.Method).Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_DoesNotDetect_WhenSelectAfterConcat()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        Analyze(context.Method).Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_DetectsInt32Parse_WithCorrectSignature()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateParseMethod(context.Module, context.Module.TypeSystem.String));
        context.Emit(OpCodes.Conv_U2);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        Analyze(context.Method).Should().HaveCount(1);
    }

    [Fact]
    public void AnalyzeInstructions_DoesNotHighlightParse_WhenInt32ParseHasWrongSignature()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateParseMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Int32));
        context.Emit(OpCodes.Conv_U2);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        findings.Should().HaveCount(1);
        findings[0].CodeSnippet!
            .Split('\n')
            .Where(static line => line.TrimStart().StartsWith(">>>", StringComparison.Ordinal))
            .Should()
            .NotContain(line => line.Contains("Parse", StringComparison.Ordinal));
    }

    [Fact]
    public void AnalyzeInstructions_ChecksConvU2ProximityToParse()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateParseMethod(context.Module, context.Module.TypeSystem.String));
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Conv_U2);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        findings.Should().HaveCount(1);
        findings[0].CodeSnippet.Should().Contain("conv.u2");
    }

    [Fact]
    public void AnalyzeInstructions_IncludesContextInCodeSnippet()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Ldstr, "context");
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Pop);
        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        findings.Should().HaveCount(1);
        findings[0].CodeSnippet.Should().Contain(">>>");
        findings[0].CodeSnippet.Should().Contain("nop");
    }

    [Fact]
    public void AnalyzeInstructions_HandlesEmptyInstructions()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Ret);

        Analyze(context.Method).Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_HandlesExceptionGracefully()
    {
        var context = CreateContext();
        var malformedMethod = new MethodReference("TestMethod", context.Module.TypeSystem.Void)
        {
            DeclaringType = null!
        };

        context.Emit(OpCodes.Call, malformedMethod);
        context.Emit(OpCodes.Ret);

        Analyze(context.Method).Should().BeEmpty();
    }

    [Fact]
    public void AnalyzeInstructions_CodeSnippetHighlightsKeyInstructions()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Ldstr, "123");
        context.Emit(OpCodes.Call, CreateParseMethod(context.Module, context.Module.TypeSystem.String));
        context.Emit(OpCodes.Conv_U2);
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateSelectMethod(context.Module, context.Module.TypeSystem.String, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Nop);
        context.Emit(OpCodes.Call, CreateConcatMethod(context.Module, context.Module.TypeSystem.Char));
        context.Emit(OpCodes.Ret);

        var snippet = Analyze(context.Method).Single().CodeSnippet!;
        var lines = snippet.Split('\n');

        lines.Should().Contain(line => line.TrimStart().StartsWith(">>>", StringComparison.Ordinal) && line.Contains("Parse", StringComparison.Ordinal));
        lines.Should().Contain(line => line.TrimStart().StartsWith(">>>", StringComparison.Ordinal) && line.Contains("conv.u2", StringComparison.Ordinal));
        lines.Should().Contain(line => line.TrimStart().StartsWith(">>>", StringComparison.Ordinal) && line.Contains("Select", StringComparison.Ordinal));
        lines.Should().Contain(line => line.TrimStart().StartsWith(">>>", StringComparison.Ordinal) && line.Contains("Concat", StringComparison.Ordinal));
    }

    [Fact]
    public void AnalyzeInstructions_DetectsInvisibleUnicodeDecodePipeline()
    {
        var context = CreateContext();
        context.Emit(OpCodes.Call, CreateConvertToUtf32Method(context.Module));
        context.Emit(OpCodes.Call, CreateIsSurrogatePairMethod(context.Module));
        context.Emit(OpCodes.Ldc_I4, 65024);
        context.Emit(OpCodes.Ldc_I4, 65039);
        context.Emit(OpCodes.Ldc_I4, 917760);
        context.Emit(OpCodes.Ldc_I4, 917999);
        context.Emit(OpCodes.Callvirt, CreateListAddMethod(context.Module));
        context.Emit(OpCodes.Callvirt, CreateEncodingGetStringMethod(context.Module));
        context.Emit(OpCodes.Ret);

        var findings = Analyze(context.Method);

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Description.Should().Contain("variation-selector Unicode decode pipeline");
        findings[0].CodeSnippet.Should().Contain("ConvertToUtf32");
        findings[0].CodeSnippet.Should().Contain("GetString");
    }

    private List<ScanFinding> Analyze(MethodDefinition method)
    {
        return _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();
    }

    private static PipelineContext CreateContext()
    {
        var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
        var module = assembly.MainModule;
        var type = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };

        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        return new PipelineContext(module, method, method.Body.GetILProcessor());
    }

    private static MethodReference CreateSelectMethod(ModuleDefinition module, TypeReference sourceType, TypeReference resultType)
    {
        var enumerableType = CreateTypeReference(module, "System.Linq.Enumerable");
        var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
        var genericMethod = new GenericInstanceMethod(selectMethod);
        genericMethod.GenericArguments.Add(sourceType);
        genericMethod.GenericArguments.Add(resultType);
        return genericMethod;
    }

    private static MethodReference CreateConcatMethod(ModuleDefinition module, TypeReference elementType)
    {
        var stringType = CreateTypeReference(module, "System.String");
        var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
        var genericMethod = new GenericInstanceMethod(concatMethod);
        genericMethod.GenericArguments.Add(elementType);
        return genericMethod;
    }

    private static MethodReference CreateParseMethod(ModuleDefinition module, params TypeReference[] parameterTypes)
    {
        var int32Type = CreateTypeReference(module, "System.Int32");
        var parseMethod = new MethodReference("Parse", module.TypeSystem.Int32, int32Type);
        foreach (var parameterType in parameterTypes)
        {
            parseMethod.Parameters.Add(new ParameterDefinition(parameterType));
        }

        return parseMethod;
    }

    private static MethodReference CreateConvertToUtf32Method(ModuleDefinition module)
    {
        var charType = CreateTypeReference(module, "System.Char");
        var method = new MethodReference("ConvertToUtf32", module.TypeSystem.Int32, charType);
        method.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Int32));
        return method;
    }

    private static MethodReference CreateIsSurrogatePairMethod(ModuleDefinition module)
    {
        var charType = CreateTypeReference(module, "System.Char");
        var method = new MethodReference("IsSurrogatePair", module.TypeSystem.Boolean, charType);
        method.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Int32));
        return method;
    }

    private static MethodReference CreateEncodingGetStringMethod(ModuleDefinition module)
    {
        var encodingType = CreateTypeReference(module, "System.Text.Encoding");
        var method = new MethodReference("GetString", module.TypeSystem.String, encodingType);
        method.Parameters.Add(new ParameterDefinition(new ArrayType(module.TypeSystem.Byte)));
        return method;
    }

    private static MethodReference CreateListAddMethod(ModuleDefinition module)
    {
        var listType = new TypeReference("System.Collections.Generic", "List`1", module, module.TypeSystem.CoreLibrary);
        var genericType = new GenericInstanceType(listType);
        genericType.GenericArguments.Add(module.TypeSystem.Byte);
        var method = new MethodReference("Add", module.TypeSystem.Void, genericType)
        {
            HasThis = true
        };
        method.Parameters.Add(new ParameterDefinition(module.TypeSystem.Byte));
        return method;
    }

    private static TypeReference CreateTypeReference(ModuleDefinition module, string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : string.Empty;
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;
        return new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);
    }

    private sealed record PipelineContext(ModuleDefinition Module, MethodDefinition Method, ILProcessor Processor)
    {
        public void Emit(OpCode opCode)
        {
            Processor.Append(Processor.Create(opCode));
        }

        public void Emit(OpCode opCode, string value)
        {
            Processor.Append(Processor.Create(opCode, value));
        }

        public void Emit(OpCode opCode, MethodReference method)
        {
            Processor.Append(Processor.Create(opCode, method));
        }

        public void Emit(OpCode opCode, int value)
        {
            Processor.Append(Processor.Create(opCode, value));
        }
    }
}
