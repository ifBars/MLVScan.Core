using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules
{
    public class EncodedStringPipelineRuleTests
    {
        private readonly EncodedStringPipelineRule _rule;

        public EncodedStringPipelineRuleTests()
        {
            _rule = new EncodedStringPipelineRule();
        }

        [Fact]
        public void RuleId_ReturnsExpectedValue()
        {
            _rule.RuleId.Should().Be("EncodedStringPipelineRule");
        }

        [Fact]
        public void Description_ReturnsExpectedValue()
        {
            _rule.Description.Should().Be("Detected encoded string to char decoding pipeline (ASCII number parsing pattern).");
        }

        [Fact]
        public void Severity_ReturnsHigh()
        {
            _rule.Severity.Should().Be(Severity.High);
        }

        [Fact]
        public void RequiresCompanionFinding_ReturnsFalse()
        {
            _rule.RequiresCompanionFinding.Should().BeFalse();
        }

        [Fact]
        public void IsSuspicious_AlwaysReturnsFalse()
        {
            // This rule analyzes IL patterns, not method references
            var method = MethodReferenceFactory.Create("TestClass", "TestMethod");
            _rule.IsSuspicious(method).Should().BeFalse();
        }

        [Fact]
        public void AnalyzeInstructions_DetectsSelectStringCharAndConcatCharPattern()
        {
            // Arrange: Create a method with Select<String,Char> → Concat<Char> pattern
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            // Create Select<String,Char> method
            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            // Create Concat<Char> method
            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().HaveCount(1);
            findings[0].Location.Should().Be("TestNamespace.TestClass.TestMethod");
            findings[0].Severity.Should().Be(Severity.High);
            findings[0].Description.Should().Contain("encoded string to char decoding pipeline");
        }

        [Fact]
        public void AnalyzeInstructions_DetectsFullPatternWithInt32ParseAndConvU2()
        {
            // Arrange: Create method with Int32::Parse → conv.u2 → Select<String,Char> → Concat<Char>
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            // Create Int32.Parse(String) method
            var int32Type = new TypeReference("System", "Int32", module, module.TypeSystem.CoreLibrary);
            var parseMethod = new MethodReference("Parse", module.TypeSystem.Int32, int32Type);
            parseMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

            // Create Select<String,Char> method
            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            // Create Concat<Char> method
            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Ldstr, "123"));
            processor.Append(processor.Create(OpCodes.Call, parseMethod));
            processor.Append(processor.Create(OpCodes.Conv_U2)); // convert to char
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().HaveCount(1);
            findings[0].Location.Should().Be("TestNamespace.TestClass.TestMethod");
            findings[0].CodeSnippet.Should().Contain("call");
            findings[0].CodeSnippet.Should().Contain("conv.u2");
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenOnlySelectPresent()
        {
            // Arrange
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenOnlyConcatPresent()
        {
            // Arrange
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenSelectNotStringCharGeneric()
        {
            // Arrange: Select<int, string> instead of Select<String, Char>
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.Int32);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenConcatNotCharGeneric()
        {
            // Arrange: Concat<String> instead of Concat<Char>
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.String);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenSelectAfterConcat()
        {
            // Arrange: Wrong order - Concat before Select
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_DetectsInt32Parse_WithCorrectSignature()
        {
            // Arrange: Int32.Parse with String parameter
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var int32Type = new TypeReference("System", "Int32", module, module.TypeSystem.CoreLibrary);
            var parseMethod = new MethodReference("Parse", module.TypeSystem.Int32, int32Type);
            parseMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, parseMethod));
            processor.Append(processor.Create(OpCodes.Conv_U2));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().HaveCount(1);
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenInt32ParseHasWrongSignature()
        {
            // Arrange: Int32.Parse with multiple parameters (different overload)
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var int32Type = new TypeReference("System", "Int32", module, module.TypeSystem.CoreLibrary);
            var parseMethod = new MethodReference("Parse", module.TypeSystem.Int32, int32Type);
            parseMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
            parseMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.Int32)); // Wrong signature

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, parseMethod));
            processor.Append(processor.Create(OpCodes.Conv_U2));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert - Still detects because Select+Concat is present, but won't highlight Parse in >>> markers
            findings.Should().HaveCount(1);
            // The snippet contains "Parse" text but it's not highlighted with >>> since it has wrong signature
            var highlightedLines = findings[0].CodeSnippet!.Split('\n').Where(l => l.TrimStart().StartsWith(">>>"));
            highlightedLines.Should().NotContain(line => line.Contains("Parse"));
        }

        [Fact]
        public void AnalyzeInstructions_ChecksConvU2ProximityToParse()
        {
            // Arrange: conv.u2 must be within 3 instructions after Parse
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var int32Type = new TypeReference("System", "Int32", module, module.TypeSystem.CoreLibrary);
            var parseMethod = new MethodReference("Parse", module.TypeSystem.Int32, int32Type);
            parseMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, parseMethod));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Conv_U2)); // At index parseIndex+3 (still within range)
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().HaveCount(1);
            findings[0].CodeSnippet.Should().Contain("conv.u2");
        }

        [Fact]
        public void AnalyzeInstructions_IncludesContextInCodeSnippet()
        {
            // Arrange
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Ldstr, "context"));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Pop));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().HaveCount(1);
            findings[0].CodeSnippet.Should().Contain(">>>");
            findings[0].CodeSnippet.Should().Contain("nop");
        }

        [Fact]
        public void AnalyzeInstructions_HandlesEmptyInstructions()
        {
            // Arrange
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_HandlesExceptionGracefully()
        {
            // Arrange: Method with malformed instruction that might cause NullReferenceException
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            // Create a valid method reference but with null DeclaringType
            var methodRef = new MethodReference("TestMethod", module.TypeSystem.Void);
            methodRef.DeclaringType = null!; // This will cause NullReferenceException when accessing DeclaringType.FullName

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Call, methodRef));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act - should not throw, rule has try-catch
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_CodeSnippetHighlightsKeyInstructions()
        {
            // Arrange
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            var module = assembly.MainModule;
            var testType = new TypeDefinition("TestNamespace", "TestClass", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition("TestMethod", MethodAttributes.Public, module.TypeSystem.Void);
            testType.Methods.Add(method);
            method.Body = new MethodBody(method);

            var int32Type = new TypeReference("System", "Int32", module, module.TypeSystem.CoreLibrary);
            var parseMethod = new MethodReference("Parse", module.TypeSystem.Int32, int32Type);
            parseMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));

            var enumerableType = new TypeReference("System.Linq", "Enumerable", module, module.TypeSystem.CoreLibrary);
            var selectMethod = new MethodReference("Select", module.TypeSystem.Object, enumerableType);
            var genericSelect = new GenericInstanceMethod(selectMethod);
            genericSelect.GenericArguments.Add(module.TypeSystem.String);
            genericSelect.GenericArguments.Add(module.TypeSystem.Char);

            var stringType = new TypeReference("System", "String", module, module.TypeSystem.CoreLibrary);
            var concatMethod = new MethodReference("Concat", module.TypeSystem.String, stringType);
            var genericConcat = new GenericInstanceMethod(concatMethod);
            genericConcat.GenericArguments.Add(module.TypeSystem.Char);

            var processor = method.Body.GetILProcessor();
            processor.Append(processor.Create(OpCodes.Ldstr, "123"));
            processor.Append(processor.Create(OpCodes.Call, parseMethod));
            processor.Append(processor.Create(OpCodes.Conv_U2));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericSelect));
            processor.Append(processor.Create(OpCodes.Nop));
            processor.Append(processor.Create(OpCodes.Call, genericConcat));
            processor.Append(processor.Create(OpCodes.Ret));

            var signals = new MethodSignals();

            // Act
            var findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, signals).ToList();

            // Assert
            findings.Should().HaveCount(1);
            var snippet = findings[0].CodeSnippet;
            snippet.Should().NotBeNull();
            var lines = snippet!.Split('\n');

            // Check that key instructions are highlighted with ">>>"
            lines.Should().Contain(line => line.TrimStart().StartsWith(">>>") && line.Contains("Parse"));
            lines.Should().Contain(line => line.TrimStart().StartsWith(">>>") && line.Contains("conv.u2"));
            lines.Should().Contain(line => line.TrimStart().StartsWith(">>>") && line.Contains("Select"));
            lines.Should().Contain(line => line.TrimStart().StartsWith(">>>") && line.Contains("Concat"));
        }
    }
}
