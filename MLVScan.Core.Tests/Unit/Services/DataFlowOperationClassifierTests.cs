using FluentAssertions;
using MLVScan.Services.DataFlow;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class DataFlowOperationClassifierTests
{
    [Fact]
    public void IdentifyInterestingOperations_ProcessStartInfoOverload_UsesFileNameIdentity()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var startInfoType = CreateTypeReference(module, "System.Diagnostics", "ProcessStartInfo");
        var startInfoLocal = AddLocal(method, startInfoType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Stloc, startInfoLocal);

        var setFileName = CreateMethodReference(
            startInfoType, "set_FileName", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Callvirt, setFileName);

        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, startInfoType);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Should().BeEquivalentTo(fileWrite.PayloadPathIdentities);
    }

    [Fact]
    public void IdentifyInterestingOperations_InlineProcessStartInfoConstructor_UsesFileNameIdentity()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        var startInfoType = CreateTypeReference(module, "System.Diagnostics", "ProcessStartInfo");
        var constructor = CreateMethodReference(
            startInfoType, ".ctor", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Newobj, constructor);
        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, startInfoType);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Should().BeEquivalentTo(fileWrite.PayloadPathIdentities);
    }

    [Fact]
    public void IdentifyInterestingOperations_InstanceStart_IgnoresSetterForDifferentProcess()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var startInfoType = CreateTypeReference(module, "System.Diagnostics", "ProcessStartInfo");
        var configuredProcessLocal = AddLocal(method, processType);
        var startedProcessLocal = AddLocal(method, processType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Stloc, configuredProcessLocal);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Stloc, startedProcessLocal);

        var getStartInfo = CreateMethodReference(
            processType, "get_StartInfo", startInfoType, hasThis: true);
        var setFileName = CreateMethodReference(
            startInfoType, "set_FileName", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);

        il.Emit(OpCodes.Ldloc, configuredProcessLocal);
        il.Emit(OpCodes.Callvirt, getStartInfo);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Callvirt, setFileName);

        il.Emit(OpCodes.Ldloc, startedProcessLocal);
        il.Emit(OpCodes.Callvirt, getStartInfo);
        il.Emit(OpCodes.Ldstr, "benign-helper.exe");
        il.Emit(OpCodes.Callvirt, setFileName);

        var start = CreateMethodReference(
            processType, "Start", module.TypeSystem.Boolean, hasThis: true);
        il.Emit(OpCodes.Ldloc, startedProcessLocal);
        il.Emit(OpCodes.Callvirt, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().BeEmpty();
        processStart.PayloadPathIdentities.Should().ContainSingle(identity =>
            identity.Contains("BENIGN-HELPER.EXE", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_CreateProcessWithNullApplication_UsesCommandLineIdentity()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var applicationNameLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Stloc, applicationNameLocal);

        var nativeType = new TypeDefinition(
            "Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(nativeType);
        var nativeModule = new ModuleReference("kernel32.dll");
        module.ModuleReferences.Add(nativeModule);
        var createProcess = new MethodDefinition(
            "CreateProcessW",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            module.TypeSystem.Boolean);
        createProcess.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        createProcess.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        for (var index = 2; index < 10; index++)
        {
            createProcess.Parameters.Add(new ParameterDefinition(module.TypeSystem.Object));
        }
        createProcess.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "CreateProcessW", nativeModule);
        nativeType.Methods.Add(createProcess);

        il.Emit(OpCodes.Ldloc, applicationNameLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        for (var index = 2; index < 10; index++)
        {
            il.Emit(OpCodes.Ldnull);
        }
        il.Emit(OpCodes.Call, createProcess);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var createProcessOperation = operations.Single(operation =>
            operation.Operation.Contains("PInvoke.CreateProcess", StringComparison.OrdinalIgnoreCase));

        createProcessOperation.PayloadPathIdentities.Should().BeEquivalentTo(fileWrite.PayloadPathIdentities);
    }

    [Fact]
    public void IdentifyInterestingOperations_CreateProcessCommandWithArguments_ExtractsExecutableIdentity()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);

        var nativeType = new TypeDefinition(
            "Test", "NativeMethods", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(nativeType);
        var nativeModule = new ModuleReference("kernel32.dll");
        module.ModuleReferences.Add(nativeModule);
        var createProcess = new MethodDefinition(
            "CreateProcessW",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            module.TypeSystem.Boolean);
        createProcess.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        createProcess.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        for (var index = 2; index < 10; index++)
        {
            createProcess.Parameters.Add(new ParameterDefinition(module.TypeSystem.Object));
        }
        createProcess.PInvokeInfo = new PInvokeInfo(PInvokeAttributes.CallConvWinapi, "CreateProcessW", nativeModule);
        nativeType.Methods.Add(createProcess);

        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ldstr, "\"payload.exe\" /silent");
        for (var index = 2; index < 10; index++)
        {
            il.Emit(OpCodes.Ldnull);
        }
        il.Emit(OpCodes.Call, createProcess);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var createProcessOperation = operations.Single(operation =>
            operation.Operation.Contains("PInvoke.CreateProcess", StringComparison.OrdinalIgnoreCase));

        createProcessOperation.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().NotBeEmpty();
    }

    [Fact]
    public void IdentifyInterestingOperations_ConditionalPathReassignment_PreservesPossiblePayloadLink()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);

        var launch = Instruction.Create(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Brfalse_S, launch);
        il.Emit(OpCodes.Ldstr, "other.exe");
        il.Emit(OpCodes.Stloc, pathLocal);
        il.Append(launch);
        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, module.TypeSystem.String);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().NotBeEmpty();
        processStart.PayloadPathIdentities.Should().HaveCount(3);
    }

    [Fact]
    public void IdentifyInterestingOperations_ShellExecuteEx_IgnoresLpFileFromDifferentStruct()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var shellInfoType = new TypeDefinition(
            "Test", "SHELLEXECUTEINFO", TypeAttributes.Public | TypeAttributes.SequentialLayout |
                                               TypeAttributes.Sealed | TypeAttributes.AnsiClass,
            module.ImportReference(typeof(ValueType)));
        var lpFile = new FieldDefinition("lpFile", FieldAttributes.Public, module.TypeSystem.String);
        shellInfoType.Fields.Add(lpFile);
        module.Types.Add(shellInfoType);
        var launchedInfoLocal = AddLocal(method, shellInfoType);
        var unrelatedInfoLocal = AddLocal(method, shellInfoType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        il.Emit(OpCodes.Ldloca, launchedInfoLocal);
        il.Emit(OpCodes.Ldstr, "benign-helper.exe");
        il.Emit(OpCodes.Stfld, lpFile);
        il.Emit(OpCodes.Ldloca, unrelatedInfoLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Stfld, lpFile);

        var nativeType = new TypeDefinition(
            "Test", "ShellNativeMethods", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(nativeType);
        var nativeModule = new ModuleReference("shell32.dll");
        module.ModuleReferences.Add(nativeModule);
        var shellExecute = new MethodDefinition(
            "ShellExecuteExW",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            module.TypeSystem.Boolean);
        shellExecute.Parameters.Add(new ParameterDefinition(new ByReferenceType(shellInfoType)));
        shellExecute.PInvokeInfo = new PInvokeInfo(
            PInvokeAttributes.CallConvWinapi, "ShellExecuteExW", nativeModule);
        nativeType.Methods.Add(shellExecute);
        il.Emit(OpCodes.Ldloca, launchedInfoLocal);
        il.Emit(OpCodes.Call, shellExecute);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var shellStart = operations.Single(operation =>
            operation.Operation.Contains("PInvoke.ShellExecuteEx", StringComparison.OrdinalIgnoreCase));

        shellStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().BeEmpty();
        shellStart.PayloadPathIdentities.Should().ContainSingle(identity =>
            identity.Contains("BENIGN-HELPER.EXE", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_ConditionalShellExecuteFile_TracksAllReachingStores()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var shellInfoType = new TypeDefinition(
            "Test", "SHELLEXECUTEINFO", TypeAttributes.Public | TypeAttributes.SequentialLayout |
                                               TypeAttributes.Sealed | TypeAttributes.AnsiClass,
            module.ImportReference(typeof(ValueType)));
        var lpFile = new FieldDefinition("lpFile", FieldAttributes.Public, module.TypeSystem.String);
        shellInfoType.Fields.Add(lpFile);
        module.Types.Add(shellInfoType);
        var shellInfoLocal = AddLocal(method, shellInfoType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        il.Emit(OpCodes.Ldloca, shellInfoLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Stfld, lpFile);

        var launch = Instruction.Create(OpCodes.Ldloca, shellInfoLocal);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Brfalse_S, launch);
        il.Emit(OpCodes.Ldloca, shellInfoLocal);
        il.Emit(OpCodes.Ldstr, "benign-helper.exe");
        il.Emit(OpCodes.Stfld, lpFile);

        var nativeType = new TypeDefinition(
            "Test", "ShellNativeMethods", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(nativeType);
        var nativeModule = new ModuleReference("shell32.dll");
        module.ModuleReferences.Add(nativeModule);
        var shellExecute = new MethodDefinition(
            "ShellExecuteExW",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PInvokeImpl,
            module.TypeSystem.Boolean);
        shellExecute.Parameters.Add(new ParameterDefinition(new ByReferenceType(shellInfoType)));
        shellExecute.PInvokeInfo = new PInvokeInfo(
            PInvokeAttributes.CallConvWinapi, "ShellExecuteExW", nativeModule);
        nativeType.Methods.Add(shellExecute);
        il.Append(launch);
        il.Emit(OpCodes.Call, shellExecute);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var shellStart = operations.Single(operation =>
            operation.Operation.Contains("PInvoke.ShellExecuteEx", StringComparison.OrdinalIgnoreCase));

        shellStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().NotBeEmpty();
        shellStart.PayloadPathIdentities.Should().Contain(identity =>
            identity.Contains("BENIGN-HELPER.EXE", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_LocalPathAlias_PreservesConcretePayloadLink()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var aliasLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Stloc, aliasLocal);

        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, aliasLocal);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().NotBeEmpty();
        processStart.PayloadPathIdentities.Should().Contain(identity =>
            identity.Contains("PAYLOAD.EXE", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_ConditionalStartInfoAssignment_TracksAllReachingPaths()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var startInfoType = CreateTypeReference(module, "System.Diagnostics", "ProcessStartInfo");
        var startInfoLocal = AddLocal(method, startInfoType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        var constructor = CreateMethodReference(
            startInfoType, ".ctor", module.TypeSystem.Void, hasThis: true);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);

        var setFileName = CreateMethodReference(
            startInfoType, "set_FileName", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Callvirt, setFileName);

        var launch = Instruction.Create(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Brfalse_S, launch);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldstr, "benign-helper.exe");
        il.Emit(OpCodes.Callvirt, setFileName);
        il.Append(launch);
        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, startInfoType);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().NotBeEmpty();
        processStart.PayloadPathIdentities.Should().Contain(identity =>
            identity.Contains("BENIGN-HELPER.EXE", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_StoredStartInfoConstructor_ResolvesFileName()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var startInfoType = CreateTypeReference(module, "System.Diagnostics", "ProcessStartInfo");
        var startInfoLocal = AddLocal(method, startInfoType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        var constructor = CreateMethodReference(
            startInfoType, ".ctor", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);

        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, startInfoType);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().NotBeEmpty();
    }

    [Fact]
    public void IdentifyInterestingOperations_ReassignedStartInfo_IgnoresSettersOnOldObject()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var startInfoType = CreateTypeReference(module, "System.Diagnostics", "ProcessStartInfo");
        var startInfoLocal = AddLocal(method, startInfoType);
        var il = method.Body.GetILProcessor();

        EmitStoredPayloadPath(il, pathLocal);
        EmitFileWrite(il, module, pathLocal);
        var defaultConstructor = CreateMethodReference(
            startInfoType, ".ctor", module.TypeSystem.Void, hasThis: true);
        il.Emit(OpCodes.Newobj, defaultConstructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        var setFileName = CreateMethodReference(
            startInfoType, "set_FileName", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Callvirt, setFileName);

        var fileNameConstructor = CreateMethodReference(
            startInfoType, ".ctor", module.TypeSystem.Void, hasThis: true, module.TypeSystem.String);
        il.Emit(OpCodes.Ldstr, "benign-helper.exe");
        il.Emit(OpCodes.Newobj, fileNameConstructor);
        il.Emit(OpCodes.Stloc, startInfoLocal);
        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, startInfoType);
        il.Emit(OpCodes.Ldloc, startInfoLocal);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().BeEmpty();
        processStart.PayloadPathIdentities.Should().Contain(identity =>
            identity.Contains("BENIGN-HELPER.EXE", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_UnresolvedArguments_UseDistinctMethodScopedIdentities()
    {
        var method = CreateCallerMethod(out var module);
        method.Parameters.Add(new ParameterDefinition("writePath", ParameterAttributes.None, module.TypeSystem.String));
        method.Parameters.Add(new ParameterDefinition("launchPath", ParameterAttributes.None, module.TypeSystem.String));
        var il = method.Body.GetILProcessor();

        var fileType = CreateTypeReference(module, "System.IO", "File");
        var writeAllBytes = CreateMethodReference(
            fileType,
            "WriteAllBytes",
            module.TypeSystem.Void,
            hasThis: false,
            module.TypeSystem.String,
            new ArrayType(module.TypeSystem.Byte));
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Call, writeAllBytes);

        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, module.TypeSystem.String);
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        fileWrite.PayloadPathIdentities.Should().ContainSingle(identity =>
            identity.EndsWith("::argument:0", StringComparison.Ordinal));
        processStart.PayloadPathIdentities.Should().ContainSingle(identity =>
            identity.EndsWith("::argument:1", StringComparison.Ordinal));
        fileWrite.PayloadPathIdentities.Intersect(processStart.PayloadPathIdentities).Should().BeEmpty();
    }

    [Fact]
    public void IdentifyInterestingOperations_UnresolvedArgumentAlias_PreservesSourceIdentity()
    {
        var method = CreateCallerMethod(out var module);
        method.Parameters.Add(new ParameterDefinition("path", ParameterAttributes.None, module.TypeSystem.String));
        var aliasLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();

        var fileType = CreateTypeReference(module, "System.IO", "File");
        var writeAllBytes = CreateMethodReference(
            fileType,
            "WriteAllBytes",
            module.TypeSystem.Void,
            hasThis: false,
            module.TypeSystem.String,
            new ArrayType(module.TypeSystem.Byte));
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Call, writeAllBytes);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Stloc, aliasLocal);

        var processType = CreateTypeReference(module, "System.Diagnostics", "Process");
        var start = CreateMethodReference(
            processType, "Start", processType, hasThis: false, module.TypeSystem.String);
        il.Emit(OpCodes.Ldloc, aliasLocal);
        il.Emit(OpCodes.Call, start);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);
        var fileWrite = operations.Single(operation => operation.Operation.Contains("File.WriteAllBytes"));
        var processStart = operations.Single(operation => operation.Operation == "Process.Start");

        processStart.PayloadPathIdentities.Intersect(fileWrite.PayloadPathIdentities).Should().ContainSingle(identity =>
            identity.EndsWith("::argument:0", StringComparison.Ordinal));
    }

    [Fact]
    public void IdentifyInterestingOperations_ReadOnlyFileStream_IsNotAWriteSink()
    {
        var method = CreateCallerMethod(out var module);
        var pathLocal = AddLocal(method, module.TypeSystem.String);
        var il = method.Body.GetILProcessor();
        EmitStoredPayloadPath(il, pathLocal);

        var fileStreamType = CreateTypeReference(module, "System.IO", "FileStream");
        var fileModeType = CreateTypeReference(module, "System.IO", "FileMode");
        var fileAccessType = CreateTypeReference(module, "System.IO", "FileAccess");
        var constructor = CreateMethodReference(
            fileStreamType,
            ".ctor",
            module.TypeSystem.Void,
            hasThis: true,
            module.TypeSystem.String,
            fileModeType,
            fileAccessType);
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Ldc_I4_3); // FileMode.Open
        il.Emit(OpCodes.Ldc_I4_1); // FileAccess.Read
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);

        var operations = new DataFlowOperationClassifier().IdentifyInterestingOperations(method, method.Body.Instructions);

        operations.Should().NotContain(operation => operation.Operation.Contains("FileStream"));
    }

    private static MethodDefinition CreateCallerMethod(out ModuleDefinition module)
    {
        var assembly = AssemblyDefinition.CreateAssembly(
            new AssemblyNameDefinition("DataFlowOperationClassifierTests", new Version(1, 0)),
            "DataFlowOperationClassifierTests",
            ModuleKind.Dll);
        module = assembly.MainModule;
        var type = new TypeDefinition(
            "Test", "Caller", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition(
            "Run", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);
        method.Body = new MethodBody(method) { InitLocals = true };
        type.Methods.Add(method);
        return method;
    }

    private static VariableDefinition AddLocal(MethodDefinition method, TypeReference type)
    {
        var local = new VariableDefinition(type);
        method.Body.Variables.Add(local);
        return local;
    }

    private static void EmitStoredPayloadPath(ILProcessor il, VariableDefinition pathLocal)
    {
        il.Emit(OpCodes.Ldstr, "payload.exe");
        il.Emit(OpCodes.Stloc, pathLocal);
    }

    private static void EmitFileWrite(ILProcessor il, ModuleDefinition module, VariableDefinition pathLocal)
    {
        var fileType = CreateTypeReference(module, "System.IO", "File");
        var writeAllBytes = CreateMethodReference(
            fileType,
            "WriteAllBytes",
            module.TypeSystem.Void,
            hasThis: false,
            module.TypeSystem.String,
            new ArrayType(module.TypeSystem.Byte));
        il.Emit(OpCodes.Ldloc, pathLocal);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Call, writeAllBytes);
    }

    private static TypeReference CreateTypeReference(ModuleDefinition module, string @namespace, string name)
    {
        return new TypeReference(@namespace, name, module, module.TypeSystem.CoreLibrary);
    }

    private static MethodReference CreateMethodReference(
        TypeReference declaringType,
        string name,
        TypeReference returnType,
        bool hasThis,
        params TypeReference[] parameterTypes)
    {
        var method = new MethodReference(name, returnType, declaringType) { HasThis = hasThis };
        foreach (var parameterType in parameterTypes)
        {
            method.Parameters.Add(new ParameterDefinition(parameterType));
        }

        return method;
    }
}
