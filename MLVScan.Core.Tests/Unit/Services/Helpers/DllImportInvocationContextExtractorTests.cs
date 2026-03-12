using System.Reflection;
using FluentAssertions;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using FieldAttributes = Mono.Cecil.FieldAttributes;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using TypeAttributes = Mono.Cecil.TypeAttributes;
using CecilMethodBody = Mono.Cecil.Cil.MethodBody;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services.Helpers;

/// <summary>
/// Unit tests for DllImportInvocationContextExtractor helper methods.
/// Note: Full integration tests for TryBuildContext require actual assembly scanning
/// since MethodReference.Resolve() requires properly linked assembly definitions.
/// These tests focus on the helper methods and public API surface.
/// </summary>
public class DllImportInvocationContextExtractorTests
{
    private static readonly Assembly CoreAssembly = typeof(MLVScan.Models.ScanFinding).Assembly;
    private static readonly Type ExtractorType = CoreAssembly.GetType("MLVScan.Services.Helpers.DllImportInvocationContextExtractor")!;

    private static readonly MethodInfo NormalizeDisplayValueMethod =
        ExtractorType.GetMethod("NormalizeDisplayValue", BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo TryBuildContextMethod =
        ExtractorType.GetMethod("TryBuildContext", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsNativeExecutionPInvokeMethod =
        ExtractorType.GetMethod("IsNativeExecutionPInvoke", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo TryBuildPreCallBehaviorHintMethod =
        ExtractorType.GetMethod("TryBuildPreCallBehaviorHint", BindingFlags.Static | BindingFlags.NonPublic)!;

    private static readonly MethodInfo TryExtractScriptExtensionFromGuidFormatLiteralMethod =
        ExtractorType.GetMethod("TryExtractScriptExtensionFromGuidFormatLiteral", BindingFlags.Static | BindingFlags.NonPublic)!;

    #region NormalizeDisplayValue Tests

    [Fact]
    public void NormalizeDisplayValue_WithNull_ReturnsUnknownMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "" });

        result.Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void NormalizeDisplayValue_WithEmptyString_ReturnsUnknownMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "   " });

        result.Should().Be("<unknown/non-literal>");
    }

    [Fact]
    public void NormalizeDisplayValue_WithNormalString_ReturnsQuotedValue()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "test.exe" });

        result.Should().Be("\"test.exe\"");
    }

    [Fact]
    public void NormalizeDisplayValue_WithLongString_ReturnsTruncatedValue()
    {
        var longString = new string('a', 200);

        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { longString });

        ((string)result!).Length.Should().BeLessThan(160);
        ((string)result).Should().EndWith("\"");
    }

    [Fact]
    public void NormalizeDisplayValue_WithNewlines_ReturnsNormalizedString()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "line1\r\nline2\nline3" });

        ((string)result!).Should().NotContain("\r");
        ((string)result).Should().NotContain("\n");
    }

    [Fact]
    public void NormalizeDisplayValue_WithInteger_ReturnsIntegerString()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "42" });

        result.Should().Be("42");
    }

    [Fact]
    public void NormalizeDisplayValue_WithAlreadyQuotedString_ReturnsQuotedString()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "\"already quoted\"" });

        result.Should().Be("\"already quoted\"");
    }

    [Fact]
    public void NormalizeDisplayValue_WithUnknownMarker_ReturnsMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "<unknown>" });

        result.Should().Be("<unknown>");
    }

    [Fact]
    public void NormalizeDisplayValue_WithLocalMarker_ReturnsMarker()
    {
        var result = NormalizeDisplayValueMethod.Invoke(null, new object[] { "<local V_0>" });

        result.Should().Be("<local V_0>");
    }

    #endregion

    #region TryBuildContext Tests

    [Fact]
    public void TryBuildContext_WithShellExecuteExFieldsAndDropperPattern_ReturnsOrderedContextAndHint()
    {
        var (callerMethod, calledMethod, callIndex) = CreateShellExecuteCaller("ShellExecuteExW", includeFieldValues: true,
            includeResourceLoad: true, includeFileWrite: true);

        var result = (string?)TryBuildContextMethod.Invoke(null, new object[]
        {
            callerMethod,
            calledMethod,
            callerMethod.Body.Instructions,
            callIndex
        });

        result.Should().NotBeNull();
        result.Should().Contain("Invocation context:");
        result.Should().Contain("lpVerb=\"open\"");
        result.Should().Contain("lpFile=\"%TEMP%/<guid>.cmd\"");
        result.Should().Contain("lpParameters=\"/c ping\"");
        result.Should().Contain("lpDirectory=\"C:\\Temp\"");
        result.Should().Contain("nShow=1");
        result.Should().Contain("Pre-call behavior: embedded resource is materialized and written to disk");
        result.Should().Contain("temp script dropper pattern");

        result!.IndexOf("lpVerb", StringComparison.Ordinal).Should()
            .BeLessThan(result.IndexOf("lpFile", StringComparison.Ordinal));
        result.IndexOf("lpFile", StringComparison.Ordinal).Should()
            .BeLessThan(result.IndexOf("lpParameters", StringComparison.Ordinal));
        result.IndexOf("lpParameters", StringComparison.Ordinal).Should()
            .BeLessThan(result.IndexOf("lpDirectory", StringComparison.Ordinal));
        result.IndexOf("lpDirectory", StringComparison.Ordinal).Should()
            .BeLessThan(result.IndexOf("nShow", StringComparison.Ordinal));
    }

    [Fact]
    public void TryBuildContext_WithShellExecuteAndNoContextSignals_ReturnsNull()
    {
        var (callerMethod, calledMethod, callIndex) = CreateShellExecuteCaller("ShellExecuteW", includeFieldValues: false,
            includeResourceLoad: false, includeFileWrite: false);

        var result = (string?)TryBuildContextMethod.Invoke(null, new object[]
        {
            callerMethod,
            calledMethod,
            callerMethod.Body.Instructions,
            callIndex
        });

        result.Should().BeNull();
    }

    [Fact]
    public void TryBuildContext_WithNonShellExecutePInvoke_ReturnsNull()
    {
        var (callerMethod, calledMethod, callIndex) = CreateShellExecuteCaller("GetCurrentProcess", includeFieldValues: true,
            includeResourceLoad: true, includeFileWrite: true);

        var result = (string?)TryBuildContextMethod.Invoke(null, new object[]
        {
            callerMethod,
            calledMethod,
            callerMethod.Body.Instructions,
            callIndex
        });

        result.Should().BeNull();
    }

    #endregion

    #region TryBuildPreCallBehaviorHint Tests

    [Fact]
    public void TryBuildPreCallBehaviorHint_WithResourceAndFileWrite_ReturnsTempDropperHint()
    {
        var method = CreateBehaviorHintMethod(includeResourceLoad: true, includeFileWrite: true, includeTempSignals: true);
        var arguments = new object[] { method.Body.Instructions, method.Body.Instructions.Count, string.Empty };

        var success = (bool)TryBuildPreCallBehaviorHintMethod.Invoke(null, arguments)!;

        success.Should().BeTrue();
        arguments[2].Should().Be("Pre-call behavior: embedded resource is materialized and written to disk (temp script dropper pattern)");
    }

    [Fact]
    public void TryBuildPreCallBehaviorHint_WithResourceOnly_ReturnsResourceHint()
    {
        var method = CreateBehaviorHintMethod(includeResourceLoad: true, includeFileWrite: false, includeTempSignals: false);
        var arguments = new object[] { method.Body.Instructions, method.Body.Instructions.Count, string.Empty };

        var success = (bool)TryBuildPreCallBehaviorHintMethod.Invoke(null, arguments)!;

        success.Should().BeTrue();
        arguments[2].Should().Be("Pre-call behavior: embedded resource access observed");
    }

    [Fact]
    public void TryBuildPreCallBehaviorHint_WithFileWriteOnly_ReturnsFileWriteHint()
    {
        var method = CreateBehaviorHintMethod(includeResourceLoad: false, includeFileWrite: true, includeTempSignals: false);
        var arguments = new object[] { method.Body.Instructions, method.Body.Instructions.Count, string.Empty };

        var success = (bool)TryBuildPreCallBehaviorHintMethod.Invoke(null, arguments)!;

        success.Should().BeTrue();
        arguments[2].Should().Be("Pre-call behavior: file write observed before native execution");
    }

    [Fact]
    public void TryBuildPreCallBehaviorHint_WithoutSignals_ReturnsFalse()
    {
        var method = CreateBehaviorHintMethod(includeResourceLoad: false, includeFileWrite: false, includeTempSignals: false);
        var arguments = new object[] { method.Body.Instructions, method.Body.Instructions.Count, string.Empty };

        var success = (bool)TryBuildPreCallBehaviorHintMethod.Invoke(null, arguments)!;

        success.Should().BeFalse();
        arguments[2].Should().Be(string.Empty);
    }

    #endregion

    #region Script Extension Extraction Tests

    [Theory]
    [InlineData("{0}.cmd", true, ".cmd")]
    [InlineData("{0}.bat", true, ".bat")]
    [InlineData("{0}.ps1", true, ".ps1")]
    [InlineData("payload.cmd", false, "")]
    [InlineData("{0}.txt", false, "")]
    public void TryExtractScriptExtensionFromGuidFormatLiteral_ReturnsExpectedResult(
        string literal,
        bool expectedSuccess,
        string expectedExtension)
    {
        var arguments = new object[] { literal, string.Empty };

        var success = (bool)TryExtractScriptExtensionFromGuidFormatLiteralMethod.Invoke(null, arguments)!;

        success.Should().Be(expectedSuccess);
        arguments[1].Should().Be(expectedExtension);
    }

    #endregion

    #region IsNativeExecutionPInvoke - Direct Testing

    [Fact]
    public void IsNativeExecutionPInvoke_WithShellExecutePInvokeMethod_ReturnsTrue()
    {
        var (_, calledMethod, _) = CreateShellExecuteCaller("ShellExecuteW", includeFieldValues: false,
            includeResourceLoad: false, includeFileWrite: false);

        var result = (bool)IsNativeExecutionPInvokeMethod.Invoke(null, new object[] { calledMethod })!;

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionPInvoke_WithNonExecutionPInvokeMethod_ReturnsFalse()
    {
        var (_, calledMethod, _) = CreateShellExecuteCaller("GetCurrentProcess", includeFieldValues: false,
            includeResourceLoad: false, includeFileWrite: false);

        var result = (bool)IsNativeExecutionPInvokeMethod.Invoke(null, new object[] { calledMethod })!;

        result.Should().BeFalse();
    }

    /// <summary>
    /// These tests use the DllImportRule directly to test IsNativeExecutionEntryPoint
    /// since IsNativeExecutionPInvoke in DllImportInvocationContextExtractor
    /// delegates to DllImportRule.IsNativeExecutionEntryPoint.
    /// </summary>
    [Fact]
    public void IsNativeExecutionEntryPoint_WithShellExecute_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecute");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithCreateProcess_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("createprocess");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithWinExec_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("winexec");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithShellExecuteEx_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecuteex");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithNonExecutionFunction_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("getlasterror");

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithVirtualAlloc_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("virtualalloc");

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithNull_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint(null!);

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithEmptyString_ReturnsFalse()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("");

        result.Should().BeFalse();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithCaseInsensitive_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("SHELLEXECUTE");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithPartialMatch_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecutea");

        result.Should().BeTrue();
    }

    [Fact]
    public void IsNativeExecutionEntryPoint_WithSubstring_ReturnsTrue()
    {
        var result = DllImportRule.IsNativeExecutionEntryPoint("shellexecuteexw");

        result.Should().BeTrue();
    }

    #endregion

    private static (MethodDefinition CallerMethod, MethodDefinition CalledMethod, int CallIndex) CreateShellExecuteCaller(
        string entryPoint,
        bool includeFieldValues,
        bool includeResourceLoad,
        bool includeFileWrite)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("DllImportExtractorTests", new Version(1, 0)),
            "DllImportExtractorTests", ModuleKind.Dll);
        var module = assembly.MainModule;

        var nativeType = new TypeDefinition("Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(nativeType);

        var moduleReference = new ModuleReference("shell32.dll");
        module.ModuleReferences.Add(moduleReference);

        var calledMethod = new MethodDefinition(
            entryPoint,
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            module.TypeSystem.Boolean);
        calledMethod.Parameters.Add(new ParameterDefinition(new ByReferenceType(CreateShellExecuteInfoType(module))));
        calledMethod.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, entryPoint, moduleReference);
        nativeType.Methods.Add(calledMethod);

        var callerType = new TypeDefinition("Test", "Caller", TypeAttributes.Public | TypeAttributes.Class,
            module.TypeSystem.Object);
        module.Types.Add(callerType);

        var callerMethod = new MethodDefinition("InvokeShell", MethodAttributes.Public | MethodAttributes.Static,
            module.TypeSystem.Void)
        {
            Body = new CecilMethodBody(null!)
        };
        callerMethod.Body = new CecilMethodBody(callerMethod);
        callerMethod.Body.InitLocals = true;
        callerType.Methods.Add(callerMethod);

        var shellExecuteInfoType = CreateShellExecuteInfoType(module);
        var infoLocal = new VariableDefinition(shellExecuteInfoType);
        var pathLocal = new VariableDefinition(module.TypeSystem.String);
        callerMethod.Body.Variables.Add(infoLocal);
        callerMethod.Body.Variables.Add(pathLocal);

        var processor = callerMethod.Body.GetILProcessor();
        var fields = CreateShellExecuteInfoFields(shellExecuteInfoType, module);

        if (includeResourceLoad)
        {
            processor.Append(processor.Create(OpCodes.Call,
                CreateMethodReference(module, "System.Reflection.Assembly", "GetManifestResourceStream", module.TypeSystem.Object, hasThis: false)));
            processor.Append(processor.Create(OpCodes.Pop));
        }

        if (includeFileWrite || includeFieldValues)
        {
            processor.Append(processor.Create(OpCodes.Call, CreateMethodReference(module, "System.IO.Path", "GetTempPath", module.TypeSystem.String)));
            processor.Append(processor.Create(OpCodes.Call, CreateMethodReference(module, "System.Guid", "NewGuid", module.ImportReference(typeof(Guid)))));
            processor.Append(processor.Create(OpCodes.Ldstr, "{0}.cmd"));
            processor.Append(processor.Create(OpCodes.Call,
                CreateMethodReference(module, "System.IO.Path", "Combine", module.TypeSystem.String)));
            processor.Append(processor.Create(OpCodes.Stloc_1));
        }

        if (includeFieldValues)
        {
            AppendFieldStore(processor, infoLocal, processor.Create(OpCodes.Ldstr, "open"), fields["lpVerb"]);
            AppendFieldStore(processor, infoLocal, processor.Create(OpCodes.Ldloc_1), fields["lpFile"]);
            AppendFieldStore(processor, infoLocal, processor.Create(OpCodes.Ldstr, "/c ping"), fields["lpParameters"]);
            AppendFieldStore(processor, infoLocal, processor.Create(OpCodes.Ldstr, @"C:\Temp"), fields["lpDirectory"]);
            AppendFieldStore(processor, infoLocal, processor.Create(OpCodes.Ldc_I4_1), fields["nShow"]);
        }

        if (includeFileWrite)
        {
            processor.Append(processor.Create(OpCodes.Call, CreateMethodReference(module, "System.IO.Path", "GetTempPath", module.TypeSystem.String)));
            processor.Append(processor.Create(OpCodes.Ldstr, "payload.cmd"));
            processor.Append(processor.Create(OpCodes.Call,
                CreateMethodReference(module, "System.IO.File", "WriteAllText", module.TypeSystem.Void)));
        }

        var callInstruction = processor.Create(OpCodes.Call, calledMethod);
        processor.Append(processor.Create(OpCodes.Ldloca_S, infoLocal));
        processor.Append(callInstruction);

        return (callerMethod, calledMethod, callerMethod.Body.Instructions.IndexOf(callInstruction));
    }

    private static MethodDefinition CreateBehaviorHintMethod(
        bool includeResourceLoad,
        bool includeFileWrite,
        bool includeTempSignals)
    {
        var assembly = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition("DllImportHintTests", new Version(1, 0)),
            "DllImportHintTests", ModuleKind.Dll);
        var module = assembly.MainModule;
        var type = new TypeDefinition("Test", "HintType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("HintMethod", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new CecilMethodBody(method);
        type.Methods.Add(method);

        var processor = method.Body.GetILProcessor();

        if (includeResourceLoad)
        {
            processor.Append(processor.Create(OpCodes.Call,
                CreateMethodReference(module, "System.Reflection.Assembly", "GetManifestResourceStream", module.TypeSystem.Object)));
            processor.Append(processor.Create(OpCodes.Pop));
        }

        if (includeTempSignals)
        {
            processor.Append(processor.Create(OpCodes.Call, CreateMethodReference(module, "System.IO.Path", "GetTempPath", module.TypeSystem.String)));
            processor.Append(processor.Create(OpCodes.Pop));
            processor.Append(processor.Create(OpCodes.Ldstr, "payload.ps1"));
            processor.Append(processor.Create(OpCodes.Pop));
        }

        if (includeFileWrite)
        {
            processor.Append(processor.Create(OpCodes.Call, CreateMethodReference(module, "System.IO.File", "WriteAllBytes", module.TypeSystem.Void)));
        }

        return method;
    }

    private static TypeDefinition CreateShellExecuteInfoType(ModuleDefinition module)
    {
        var existing = module.Types.FirstOrDefault(type => type.FullName == "Test.SHELLEXECUTEINFO");
        if (existing != null)
        {
            return existing;
        }

        var type = new TypeDefinition("Test", "SHELLEXECUTEINFO",
            TypeAttributes.Public | TypeAttributes.SequentialLayout | TypeAttributes.Sealed | TypeAttributes.AnsiClass,
            module.ImportReference(typeof(ValueType)));
        module.Types.Add(type);
        return type;
    }

    private static Dictionary<string, FieldDefinition> CreateShellExecuteInfoFields(TypeDefinition type, ModuleDefinition module)
    {
        if (type.Fields.Count > 0)
        {
            return type.Fields.ToDictionary(field => field.Name, field => field, StringComparer.OrdinalIgnoreCase);
        }

        var fields = new Dictionary<string, FieldDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["lpVerb"] = new FieldDefinition("lpVerb", FieldAttributes.Public, module.TypeSystem.String),
            ["lpFile"] = new FieldDefinition("lpFile", FieldAttributes.Public, module.TypeSystem.String),
            ["lpParameters"] = new FieldDefinition("lpParameters", FieldAttributes.Public, module.TypeSystem.String),
            ["lpDirectory"] = new FieldDefinition("lpDirectory", FieldAttributes.Public, module.TypeSystem.String),
            ["nShow"] = new FieldDefinition("nShow", FieldAttributes.Public, module.TypeSystem.Int32)
        };

        foreach (var field in fields.Values)
        {
            type.Fields.Add(field);
        }

        return fields;
    }

    private static void AppendFieldStore(ILProcessor processor, VariableDefinition local, Instruction valueInstruction,
        FieldDefinition field)
    {
        processor.Append(processor.Create(OpCodes.Ldloca_S, local));
        processor.Append(valueInstruction);
        processor.Append(processor.Create(OpCodes.Stfld, field));
    }

    private static MethodReference CreateMethodReference(ModuleDefinition module, string declaringTypeFullName, string methodName,
        TypeReference returnType, bool hasThis = false)
    {
        var lastDot = declaringTypeFullName.LastIndexOf('.');
        var ns = lastDot > 0 ? declaringTypeFullName[..lastDot] : string.Empty;
        var name = lastDot > 0 ? declaringTypeFullName[(lastDot + 1)..] : declaringTypeFullName;
        var declaringType = new TypeReference(ns, name, module, module.TypeSystem.CoreLibrary);

        return new MethodReference(methodName, returnType, declaringType)
        {
            HasThis = hasThis
        };
    }
}
