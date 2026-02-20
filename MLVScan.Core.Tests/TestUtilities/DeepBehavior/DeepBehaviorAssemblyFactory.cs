using Mono.Cecil;
using Mono.Cecil.Cil;
using MLVScan.Core.Tests.TestUtilities;

namespace MLVScan.Core.Tests.TestUtilities.DeepBehavior;

internal static class DeepBehaviorAssemblyFactory
{
    private static readonly List<MemoryStream> RetainedStreams = new();

    public static (AssemblyDefinition Assembly, MethodDefinition Method) CreateSwitchDispatcherAssembly(
        string assemblyName = "DeepBehaviorSwitchSample",
        int caseCount = 64)
    {
        var assembly = TestAssemblyBuilder.Create(assemblyName).Build();
        var module = assembly.MainModule;

        var type = new TypeDefinition("TestNamespace", "DispatcherType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Dispatch", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        var end = il.Create(OpCodes.Ret);

        var targets = new Instruction[caseCount];
        for (var i = 0; i < caseCount; i++)
        {
            targets[i] = il.Create(OpCodes.Nop);
        }

        il.Append(il.Create(OpCodes.Ldc_I4_0));
        il.Append(il.Create(OpCodes.Switch, targets));
        il.Append(il.Create(OpCodes.Br, end));

        foreach (var target in targets)
        {
            il.Append(target);
            il.Append(il.Create(OpCodes.Br, end));
        }

        il.Append(end);
        return RoundTripMethod(assembly, "TestNamespace.DispatcherType", method.Name);
    }

    public static (AssemblyDefinition Assembly, MethodDefinition Method) CreateLoopAssembly(
        string assemblyName = "DeepBehaviorLoopSample")
    {
        var assembly = TestAssemblyBuilder.Create(assemblyName).Build();
        var module = assembly.MainModule;

        var type = new TypeDefinition("TestNamespace", "LoopType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("Loop", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        var loopStart = il.Create(OpCodes.Nop);
        var exit = il.Create(OpCodes.Ret);

        il.Append(loopStart);
        il.Append(il.Create(OpCodes.Ldc_I4_0));
        il.Append(il.Create(OpCodes.Brtrue, exit));
        il.Append(il.Create(OpCodes.Br, loopStart));
        il.Append(exit);

        return RoundTripMethod(assembly, "TestNamespace.LoopType", method.Name);
    }

    public static (AssemblyDefinition Assembly, MethodDefinition Method) CreateFaultHandlerAssembly(
        string assemblyName = "DeepBehaviorExceptionSample")
    {
        var assembly = TestAssemblyBuilder.Create(assemblyName).Build();
        var module = assembly.MainModule;

        var type = new TypeDefinition("TestNamespace", "ExceptionType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        var method = new MethodDefinition("WithFault", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
        {
            Body = new MethodBody(null!)
        };
        method.Body = new MethodBody(method);
        type.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        var tryStart = il.Create(OpCodes.Nop);
        var leaveTarget = il.Create(OpCodes.Ret);
        var tryEnd = il.Create(OpCodes.Nop);
        var handlerStart = il.Create(OpCodes.Nop);
        var handlerEnd = il.Create(OpCodes.Endfinally);

        il.Append(tryStart);
        il.Append(il.Create(OpCodes.Leave, leaveTarget));
        il.Append(tryEnd);
        il.Append(handlerStart);
        il.Append(handlerEnd);
        il.Append(leaveTarget);

        var handler = new ExceptionHandler(ExceptionHandlerType.Fault)
        {
            TryStart = tryStart,
            TryEnd = tryEnd,
            HandlerStart = handlerStart,
            HandlerEnd = leaveTarget
        };
        method.Body.ExceptionHandlers.Add(handler);

        return RoundTripMethod(assembly, "TestNamespace.ExceptionType", method.Name);
    }

    public static AssemblyDefinition CreateMultiMethodSwitchAssembly(int methodCount = 30, int caseCount = 48)
    {
        var assembly = TestAssemblyBuilder.Create("DeepBehaviorPerfSample").Build();
        var module = assembly.MainModule;

        var type = new TypeDefinition("TestNamespace", "PerfType", TypeAttributes.Public | TypeAttributes.Class, module.TypeSystem.Object);
        module.Types.Add(type);

        for (var i = 0; i < methodCount; i++)
        {
            var method = new MethodDefinition($"Dispatch{i}", MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void)
            {
                Body = new MethodBody(null!)
            };
            method.Body = new MethodBody(method);
            type.Methods.Add(method);

            var il = method.Body.GetILProcessor();
            var end = il.Create(OpCodes.Ret);

            var targets = new Instruction[caseCount];
            for (var j = 0; j < caseCount; j++)
            {
                targets[j] = il.Create(OpCodes.Nop);
            }

            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Switch, targets));
            il.Append(il.Create(OpCodes.Br, end));

            foreach (var target in targets)
            {
                il.Append(target);
                il.Append(il.Create(OpCodes.Br, end));
            }

            il.Append(end);
        }

        return assembly;
    }

    /// <summary>
    /// Creates an assembly with methods containing encoded strings and reflection calls
    /// to trigger actual deep analysis work (not just NOP switches).
    /// </summary>
    public static AssemblyDefinition CreateDeepAnalysisWorkloadAssembly(int methodCount = 20)
    {
        var builder = TestAssemblyBuilder.Create("DeepBehaviorWorkload");
        var module = builder.Module;

        // Create a type with multiple methods that have encoded strings + reflection
        var typeBuilder = builder.AddType("TestNamespace.DeepWorkloadType");

        for (var i = 0; i < methodCount; i++)
        {
            var methodBuilder = typeBuilder.AddMethod($"ExecutePayload{i}", MethodAttributes.Public | MethodAttributes.Static);
            var method = methodBuilder.MethodDefinition;
            var il = method.Body.GetILProcessor();

            // Add encoded string that looks like ASCII codes: "83-121-115-116-101-109" = "System"
            var encodedString = "83-121-115-116-101-109-46-82-101-102-108-101-99-116-105-111-110"; // "System.Reflection"
            il.Append(il.Create(OpCodes.Ldstr, encodedString));

            // Store encoded string in local
            var strLocal = new VariableDefinition(module.TypeSystem.String);
            method.Body.Variables.Add(strLocal);
            il.Append(il.Create(OpCodes.Stloc, strLocal));

            // Load the encoded string
            il.Append(il.Create(OpCodes.Ldloc, strLocal));

            // Call Type.GetType(string) - reflection with encoded input
            var typeRef = new TypeReference("System", "Type", module, module.TypeSystem.CoreLibrary);
            var getTypeMethod = new MethodReference("GetType", typeRef, typeRef)
            {
                HasThis = false
            };
            getTypeMethod.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
            il.Append(il.Create(OpCodes.Call, getTypeMethod));

            // Store result
            var typeLocal = new VariableDefinition(typeRef);
            method.Body.Variables.Add(typeLocal);
            il.Append(il.Create(OpCodes.Stloc, typeLocal));

            // Load type and call Activator.CreateInstance
            il.Append(il.Create(OpCodes.Ldloc, typeLocal));
            var activatorRef = new TypeReference("System", "Activator", module, module.TypeSystem.CoreLibrary);
            var createInstanceMethod = new MethodReference("CreateInstance", module.TypeSystem.Object, activatorRef)
            {
                HasThis = false
            };
            createInstanceMethod.Parameters.Add(new ParameterDefinition(typeRef));
            il.Append(il.Create(OpCodes.Call, createInstanceMethod));

            // Pop result and return
            il.Append(il.Create(OpCodes.Pop));
            il.Append(il.Create(OpCodes.Ret));
        }

        return builder.Build();
    }

    private static (AssemblyDefinition Assembly, MethodDefinition Method) RoundTripMethod(
        AssemblyDefinition assembly,
        string typeFullName,
        string methodName)
    {
        var stream = new MemoryStream();
        assembly.Write(stream);
        stream.Position = 0;

        var reloaded = AssemblyDefinition.ReadAssembly(
            stream,
            new ReaderParameters
            {
                ReadingMode = ReadingMode.Immediate,
                InMemory = true
            });

        RetainedStreams.Add(stream);

        var type = reloaded.MainModule.Types.First(t => t.FullName == typeFullName);
        var method = type.Methods.First(m => m.Name == methodName);
        return (reloaded, method);
    }
}
