using System.Reflection;
using FluentAssertions;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using TypeAttributes = Mono.Cecil.TypeAttributes;

namespace MLVScan.Core.Tests.Unit.Models.Rules.Helpers;

public class ObfuscatedSinkMatcherTests
{
    private static readonly Assembly CoreAssembly = typeof(MLVScan.Models.ScanFinding).Assembly;
    private static readonly Type MatcherType = CoreAssembly.GetType("MLVScan.Models.Rules.Helpers.ObfuscatedSinkMatcher")!;

    private static readonly MethodInfo IsReflectionInvokeSinkMethod =
        MatcherType.GetMethod("IsReflectionInvokeSink", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsAssemblyLoadSinkMethod =
        MatcherType.GetMethod("IsAssemblyLoadSink", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsProcessSinkMethod =
        MatcherType.GetMethod("IsProcessSink", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsPotentialNativeExecutionSinkMethod =
        MatcherType.GetMethod("IsPotentialNativeExecutionSink", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsDynamicTargetResolutionMethod =
        MatcherType.GetMethod("IsDynamicTargetResolution", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsNetworkCallMethod =
        MatcherType.GetMethod("IsNetworkCall", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo IsFileWriteCallMethod =
        MatcherType.GetMethod("IsFileWriteCall", BindingFlags.Static | BindingFlags.Public)!;

    private static readonly MethodInfo ExtractFolderPathArgumentMethod =
        MatcherType.GetMethod("ExtractFolderPathArgument", BindingFlags.Static | BindingFlags.Public)!;

    #region IsReflectionInvokeSink Tests

    [Theory]
    [InlineData("System.Reflection.MethodInfo", "Invoke")]
    [InlineData("System.Reflection.MethodBase", "Invoke")]
    public void IsReflectionInvokeSink_MethodInfoOrBaseInvoke_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsReflectionInvokeSink(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Delegate", "DynamicInvoke")]
    public void IsReflectionInvokeSink_DelegateDynamicInvoke_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsReflectionInvokeSink(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Reflection.MethodInfo", "GetParameters")]
    [InlineData("System.Reflection.MethodBase", "GetMethodImplementationFlags")]
    [InlineData("System.Delegate", "Clone")]
    [InlineData("System.Object", "Invoke")]
    [InlineData("System.String", "DynamicInvoke")]
    public void IsReflectionInvokeSink_NonSinkMethods_ReturnsFalse(string typeName, string methodName)
    {
        var result = InvokeIsReflectionInvokeSink(typeName, methodName);
        result.Should().BeFalse();
    }

    #endregion

    #region IsAssemblyLoadSink Tests

    [Theory]
    [InlineData("System.Reflection.Assembly", "Load")]
    [InlineData("System.Reflection.Assembly", "LoadFrom")]
    [InlineData("System.Reflection.Assembly", "LoadFile")]
    [InlineData("System.Reflection.Assembly", "UnsafeLoadFrom")]
    public void IsAssemblyLoadSink_AssemblyLoadMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsAssemblyLoadSink(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.AppDomain", "Load")]
    public void IsAssemblyLoadSink_AppDomainLoad_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsAssemblyLoadSink(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext", "LoadFromAssemblyPath")]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext", "LoadFromStream")]
    [InlineData("MyAssemblyLoadContext", "LoadFromAssemblyPath")]
    public void IsAssemblyLoadSink_AssemblyLoadContextMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsAssemblyLoadSink(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Reflection.Assembly", "GetName")]
    [InlineData("System.AppDomain", "GetAssemblies")]
    [InlineData("System.Runtime.Loader.AssemblyLoadContext", "LoadFrom")]
    [InlineData("System.Object", "Load")]
    public void IsAssemblyLoadSink_NonSinkMethods_ReturnsFalse(string typeName, string methodName)
    {
        var result = InvokeIsAssemblyLoadSink(typeName, methodName);
        result.Should().BeFalse();
    }

    #endregion

    #region IsProcessSink Tests

    [Theory]
    [InlineData("System.Diagnostics.Process", "Start")]
    public void IsProcessSink_ProcessStart_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsProcessSink(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Diagnostics.Process", "Kill")]
    [InlineData("System.Diagnostics.Process", "GetProcesses")]
    [InlineData("System.Object", "Start")]
    [InlineData("System.String", "Start")]
    public void IsProcessSink_NonStartMethods_ReturnsFalse(string typeName, string methodName)
    {
        var result = InvokeIsProcessSink(typeName, methodName);
        result.Should().BeFalse();
    }

    #endregion

    #region IsPotentialNativeExecutionSink Tests

    [Theory]
    [InlineData("ShellExecute")]
    [InlineData("ShellExecuteEx")]
    [InlineData("CreateProcess")]
    [InlineData("CreateProcessAsUser")]
    [InlineData("shellExecute")]
    [InlineData("createprocess")]
    public void IsPotentialNativeExecutionSink_ShellOrCreateProcessMethods_ReturnsTrue(string methodName)
    {
        var calledMethod = CreateMethodReference("SomeType", methodName);
        var result = InvokeIsPotentialNativeExecutionSink(calledMethod, "SomeType", methodName);
        result.Should().BeTrue();
    }

    [Fact]
    public void IsPotentialNativeExecutionSink_PInvokeMethod_ReturnsTrue()
    {
        var module = CreateTestModule();
        var type = new TypeDefinition("Test", "PInvokeType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("ExternalMethod", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl, module.TypeSystem.Void);
        method.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CharSetAnsi, "ExternalMethod", new ModuleReference("test.dll"));
        type.Methods.Add(method);

        var result = InvokeIsPotentialNativeExecutionSink(method, "Test.PInvokeType", "ExternalMethod");
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Runtime.InteropServices.Marshal", "GetDelegateForFunctionPointer")]
    [InlineData("System.Runtime.InteropServices.Marshal", "GetFunctionPointerForDelegate")]
    public void IsPotentialNativeExecutionSink_MarshalMethods_ReturnsTrue(string typeName, string methodName)
    {
        var calledMethod = CreateMethodReference(typeName, methodName);
        var result = InvokeIsPotentialNativeExecutionSink(calledMethod, typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.String", "Substring")]
    [InlineData("System.Object", "ToString")]
    [InlineData("System.Runtime.InteropServices.Marshal", "Copy")]
    public void IsPotentialNativeExecutionSink_NonNativeMethods_ReturnsFalse(string typeName, string methodName)
    {
        var calledMethod = CreateMethodReference(typeName, methodName);
        var result = InvokeIsPotentialNativeExecutionSink(calledMethod, typeName, methodName);
        result.Should().BeFalse();
    }

    [Fact]
    public void IsPotentialNativeExecutionSink_UnresolvableMethod_DoesNotThrow()
    {
        var module = CreateTestModule();
        var methodRef = new MethodReference("NonExistent", module.TypeSystem.Void, new TypeReference("External", "Type", module, module));

        Action act = () => InvokeIsPotentialNativeExecutionSink(methodRef, "External.Type", "NonExistent");
        act.Should().NotThrow();
    }

    #endregion

    #region IsDynamicTargetResolution Tests

    [Theory]
    [InlineData("System.Type", "GetType")]
    [InlineData("System.Type", "GetMethod")]
    [InlineData("System.Type", "GetProperty")]
    [InlineData("System.Type", "GetField")]
    [InlineData("System.Type", "InvokeMember")]
    public void IsDynamicTargetResolution_TypeMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsDynamicTargetResolution(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Reflection.Assembly", "GetType")]
    [InlineData("System.Reflection.Assembly", "CreateInstance")]
    public void IsDynamicTargetResolution_AssemblyMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsDynamicTargetResolution(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Activator", "CreateInstance")]
    public void IsDynamicTargetResolution_ActivatorCreateInstance_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsDynamicTargetResolution(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Type", "ToString")]
    [InlineData("System.Reflection.Assembly", "GetName")]
    [InlineData("System.Activator", "CreateInstanceFrom")]
    [InlineData("System.Object", "GetType")]
    public void IsDynamicTargetResolution_NonResolutionMethods_ReturnsFalse(string typeName, string methodName)
    {
        var result = InvokeIsDynamicTargetResolution(typeName, methodName);
        result.Should().BeFalse();
    }

    #endregion

    #region IsNetworkCall Tests

    [Theory]
    [InlineData("System.Net.WebClient", "DownloadString")]
    [InlineData("System.Net.WebClient", "DownloadFile")]
    [InlineData("System.Net.WebClient", "DownloadData")]
    [InlineData("System.Net.WebClient", "UploadString")]
    [InlineData("System.Net.WebClient", "UploadFile")]
    [InlineData("System.Net.WebClient", "UploadData")]
    [InlineData("System.Net.WebClient", "OpenRead")]
    public void IsNetworkCall_WebClientMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsNetworkCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Net.Http.HttpClient", "GetString")]
    [InlineData("System.Net.Http.HttpClient", "GetByteArray")]
    [InlineData("System.Net.Http.HttpClient", "GetStream")]
    [InlineData("System.Net.Http.HttpClient", "PostAsync")]
    [InlineData("System.Net.Http.HttpClient", "SendAsync")]
    public void IsNetworkCall_HttpClientMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsNetworkCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Net.WebRequest", "Create")]
    [InlineData("System.Net.WebRequest", "GetRequestStream")]
    [InlineData("System.Net.WebRequest", "GetResponse")]
    public void IsNetworkCall_WebRequestMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsNetworkCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Net.Sockets.Socket", "Connect")]
    public void IsNetworkCall_SocketConnect_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsNetworkCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Net.WebClient", "Dispose")]
    [InlineData("System.Net.Http.HttpClient", "Dispose")]
    [InlineData("System.Net.WebRequest", "Abort")]
    [InlineData("System.Net.Sockets.Socket", "Close")]
    [InlineData("System.String", "DownloadString")]
    public void IsNetworkCall_NonNetworkMethods_ReturnsFalse(string typeName, string methodName)
    {
        var result = InvokeIsNetworkCall(typeName, methodName);
        result.Should().BeFalse();
    }

    #endregion

    #region IsFileWriteCall Tests

    [Theory]
    [InlineData("System.IO.File", "WriteAllText")]
    [InlineData("System.IO.File", "WriteAllBytes")]
    [InlineData("System.IO.File", "WriteAllLines")]
    [InlineData("System.IO.File", "AppendAllText")]
    [InlineData("System.IO.File", "AppendAllLines")]
    [InlineData("System.IO.File", "Create")]
    public void IsFileWriteCall_FileMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsFileWriteCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.IO.FileStream", "Write")]
    public void IsFileWriteCall_FileStreamWrite_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsFileWriteCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.IO.StreamWriter", "Write")]
    [InlineData("System.IO.StreamWriter", "WriteLine")]
    [InlineData("System.IO.StreamWriter", "WriteAsync")]
    public void IsFileWriteCall_StreamWriterMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsFileWriteCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.IO.BinaryWriter", "Write")]
    [InlineData("System.IO.BinaryWriter", "WriteAsync")]
    public void IsFileWriteCall_BinaryWriterMethods_ReturnsTrue(string typeName, string methodName)
    {
        var result = InvokeIsFileWriteCall(typeName, methodName);
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.IO.File", "ReadAllText")]
    [InlineData("System.IO.File", "Exists")]
    [InlineData("System.IO.FileStream", "Read")]
    [InlineData("System.IO.StreamWriter", "Flush")]
    [InlineData("System.IO.BinaryWriter", "Seek")]
    [InlineData("System.String", "Write")]
    public void IsFileWriteCall_NonWriteMethods_ReturnsFalse(string typeName, string methodName)
    {
        var result = InvokeIsFileWriteCall(typeName, methodName);
        result.Should().BeFalse();
    }

    #endregion

    #region ExtractFolderPathArgument Tests

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_ReturnsValue()
    {
        var (instructions, currentIndex) = CreateInstructionsWithLdcI4(42);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(42);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_S_ReturnsValue()
    {
        var (instructions, currentIndex) = CreateInstructionsWithLdcI4_S(100);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(100);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_0_ReturnsZero()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_0);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(0);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_1_ReturnsOne()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_1);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(1);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_2_ReturnsTwo()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_2);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(2);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_3_ReturnsThree()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_3);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(3);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_4_ReturnsFour()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_4);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(4);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_5_ReturnsFive()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_5);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(5);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_6_ReturnsSix()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_6);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(6);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_7_ReturnsSeven()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_7);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(7);
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcI4_8_ReturnsEight()
    {
        var (instructions, currentIndex) = CreateInstructionsWithOpCode(OpCodes.Ldc_I4_8);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().Be(8);
    }

    [Fact]
    public void ExtractFolderPathArgument_NoLdcInstruction_ReturnsNull()
    {
        var (instructions, currentIndex) = CreateInstructionsWithoutLdc();
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().BeNull();
    }

    [Fact]
    public void ExtractFolderPathArgument_LdcBeyondWindow_ReturnsNull()
    {
        var (instructions, currentIndex) = CreateInstructionsWithLdcTooFar(42);
        var result = InvokeExtractFolderPathArgument(instructions, currentIndex);
        result.Should().BeNull();
    }

    [Fact]
    public void ExtractFolderPathArgument_FirstInstruction_ReturnsNull()
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Nop);
        var instructions = method.Body.Instructions;

        var result = InvokeExtractFolderPathArgument(instructions, 0);
        result.Should().BeNull();
    }

    [Fact]
    public void ExtractFolderPathArgument_MultipleLdcInstructions_ReturnsMostRecent()
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldc_I4, 10);
        processor.Emit(OpCodes.Ldc_I4, 20);
        processor.Emit(OpCodes.Ldc_I4, 30);
        processor.Emit(OpCodes.Nop);

        var instructions = method.Body.Instructions;
        var result = InvokeExtractFolderPathArgument(instructions, 3);
        result.Should().Be(30);
    }

    [Fact]
    public void ExtractFolderPathArgument_NegativeSByte_ReturnsCorrectValue()
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldc_I4_S, (sbyte)-5);
        processor.Emit(OpCodes.Nop);

        var instructions = method.Body.Instructions;
        var result = InvokeExtractFolderPathArgument(instructions, 1);
        result.Should().Be(-5);
    }

    #endregion

    #region Helper Methods

    private static bool InvokeIsReflectionInvokeSink(string typeName, string methodName)
    {
        return (bool)IsReflectionInvokeSinkMethod.Invoke(null, new object[] { typeName, methodName })!;
    }

    private static bool InvokeIsAssemblyLoadSink(string typeName, string methodName)
    {
        return (bool)IsAssemblyLoadSinkMethod.Invoke(null, new object[] { typeName, methodName })!;
    }

    private static bool InvokeIsProcessSink(string typeName, string methodName)
    {
        return (bool)IsProcessSinkMethod.Invoke(null, new object[] { typeName, methodName })!;
    }

    private static bool InvokeIsPotentialNativeExecutionSink(MethodReference calledMethod, string typeName, string methodName)
    {
        return (bool)IsPotentialNativeExecutionSinkMethod.Invoke(null, new object[] { calledMethod, typeName, methodName })!;
    }

    private static bool InvokeIsDynamicTargetResolution(string typeName, string methodName)
    {
        return (bool)IsDynamicTargetResolutionMethod.Invoke(null, new object[] { typeName, methodName })!;
    }

    private static bool InvokeIsNetworkCall(string typeName, string methodName)
    {
        return (bool)IsNetworkCallMethod.Invoke(null, new object[] { typeName, methodName })!;
    }

    private static bool InvokeIsFileWriteCall(string typeName, string methodName)
    {
        return (bool)IsFileWriteCallMethod.Invoke(null, new object[] { typeName, methodName })!;
    }

    private static int? InvokeExtractFolderPathArgument(Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex)
    {
        return (int?)ExtractFolderPathArgumentMethod.Invoke(null, new object[] { instructions, currentIndex });
    }

    private static MethodReference CreateMethodReference(string typeName, string methodName)
    {
        return new MethodReference(methodName, new TypeReference("", "Void", null, null), new TypeReference("", typeName, null, null));
    }

    private static ModuleDefinition CreateTestModule()
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("TestAssembly", new Version(1, 0)),
            "TestModule",
            ModuleKind.Dll);
        return assembly.MainModule;
    }

    private static (Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex) CreateInstructionsWithLdcI4(int value)
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldc_I4, value);
        processor.Emit(OpCodes.Nop);

        return (method.Body.Instructions, 1);
    }

    private static (Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex) CreateInstructionsWithLdcI4_S(int value)
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldc_I4_S, (sbyte)value);
        processor.Emit(OpCodes.Nop);

        return (method.Body.Instructions, 1);
    }

    private static (Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex) CreateInstructionsWithOpCode(OpCode opCode)
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(opCode);
        processor.Emit(OpCodes.Nop);

        return (method.Body.Instructions, 1);
    }

    private static (Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex) CreateInstructionsWithoutLdc()
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Nop);
        processor.Emit(OpCodes.Nop);
        processor.Emit(OpCodes.Nop);

        return (method.Body.Instructions, 2);
    }

    private static (Mono.Collections.Generic.Collection<Instruction> instructions, int currentIndex) CreateInstructionsWithLdcTooFar(int value)
    {
        var module = CreateTestModule();
        var method = new MethodDefinition("Test", MethodAttributes.Public, module.TypeSystem.Void);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldc_I4, value);
        for (int i = 0; i < 10; i++)
        {
            processor.Emit(OpCodes.Nop);
        }

        return (method.Body.Instructions, 10);
    }

    #endregion
}
