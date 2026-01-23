using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Core.Tests.TestUtilities;

/// <summary>
/// Fluent builder for creating synthetic Mono.Cecil assemblies for testing.
/// Allows constructing assemblies with specific IL patterns without external files.
/// </summary>
public class TestAssemblyBuilder
{
    private readonly AssemblyDefinition _assembly;
    private readonly ModuleDefinition _module;

    private TestAssemblyBuilder(string assemblyName)
    {
        var assemblyNameDef = new AssemblyNameDefinition(assemblyName, new Version(1, 0, 0, 0));
        _assembly = AssemblyDefinition.CreateAssembly(assemblyNameDef, assemblyName, ModuleKind.Dll);
        _module = _assembly.MainModule;
    }

    public static TestAssemblyBuilder Create(string assemblyName = "TestAssembly")
        => new(assemblyName);

    public ModuleDefinition Module => _module;

    public TypeBuilder AddType(string fullName, TypeAttributes attributes = TypeAttributes.Public | TypeAttributes.Class)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : "";
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;

        var typeDef = new TypeDefinition(ns, name, attributes, _module.TypeSystem.Object);
        _module.Types.Add(typeDef);

        return new TypeBuilder(this, typeDef);
    }

    public TestAssemblyBuilder AddAssemblyAttribute(string attributeTypeName, params object[] constructorArgs)
    {
        var attrType = new TypeReference("System.Reflection", attributeTypeName, _module, _module.TypeSystem.CoreLibrary);

        // For AssemblyMetadataAttribute specifically
        if (attributeTypeName == "AssemblyMetadataAttribute")
        {
            var ctor = new MethodReference(".ctor", _module.TypeSystem.Void, attrType)
            {
                HasThis = true
            };
            ctor.Parameters.Add(new ParameterDefinition(_module.TypeSystem.String));
            ctor.Parameters.Add(new ParameterDefinition(_module.TypeSystem.String));

            var attr = new CustomAttribute(ctor);
            foreach (var arg in constructorArgs)
            {
                attr.ConstructorArguments.Add(new CustomAttributeArgument(_module.TypeSystem.String, arg));
            }
            _assembly.CustomAttributes.Add(attr);
        }

        return this;
    }

    public AssemblyDefinition Build() => _assembly;

    /// <summary>
    /// Writes the assembly to a MemoryStream for scanning.
    /// </summary>
    public MemoryStream ToStream()
    {
        var stream = new MemoryStream();
        _assembly.Write(stream);
        stream.Position = 0;
        return stream;
    }
}

public class TypeBuilder
{
    private readonly TestAssemblyBuilder _parent;
    private readonly TypeDefinition _type;

    internal TypeBuilder(TestAssemblyBuilder parent, TypeDefinition type)
    {
        _parent = parent;
        _type = type;
    }

    public TypeDefinition TypeDefinition => _type;

    public MethodBuilder AddMethod(
        string name,
        MethodAttributes attributes = MethodAttributes.Public,
        TypeReference? returnType = null)
    {
        var method = new MethodDefinition(
            name,
            attributes,
            returnType ?? _parent.Module.TypeSystem.Void);

        _type.Methods.Add(method);
        return new MethodBuilder(this, method);
    }

    public MethodBuilder AddConstructor()
    {
        return AddMethod(
            ".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
            _parent.Module.TypeSystem.Void);
    }

    public TestAssemblyBuilder EndType() => _parent;
}

public class MethodBuilder
{
    private readonly TypeBuilder _parent;
    private readonly MethodDefinition _method;
    private readonly ILProcessor _il;

    internal MethodBuilder(TypeBuilder parent, MethodDefinition method)
    {
        _parent = parent;
        _method = method;
        _method.Body = new MethodBody(_method);
        _il = _method.Body.GetILProcessor();
    }

    public MethodDefinition MethodDefinition => _method;
    public ModuleDefinition Module => _parent.TypeDefinition.Module;

    /// <summary>
    /// Adds a simple instruction without operand.
    /// </summary>
    public MethodBuilder Emit(OpCode opCode)
    {
        _il.Append(_il.Create(opCode));
        return this;
    }

    /// <summary>
    /// Adds a string load instruction (ldstr).
    /// </summary>
    public MethodBuilder EmitString(string value)
    {
        _il.Append(_il.Create(OpCodes.Ldstr, value));
        return this;
    }

    /// <summary>
    /// Adds a method call instruction by specifying type and method name.
    /// </summary>
    public MethodBuilder EmitCall(string declaringTypeFullName, string methodName, TypeReference? returnType = null)
    {
        var typeRef = CreateTypeReference(declaringTypeFullName);
        var methodRef = new MethodReference(methodName, returnType ?? Module.TypeSystem.Void, typeRef)
        {
            HasThis = false
        };

        _il.Append(_il.Create(OpCodes.Call, methodRef));
        return this;
    }

    /// <summary>
    /// Adds a virtual method call instruction.
    /// </summary>
    public MethodBuilder EmitCallVirt(string declaringTypeFullName, string methodName, TypeReference? returnType = null)
    {
        var typeRef = CreateTypeReference(declaringTypeFullName);
        var methodRef = new MethodReference(methodName, returnType ?? Module.TypeSystem.Void, typeRef)
        {
            HasThis = true
        };

        _il.Append(_il.Create(OpCodes.Callvirt, methodRef));
        return this;
    }

    /// <summary>
    /// Adds an integer load instruction.
    /// </summary>
    public MethodBuilder EmitInt(int value)
    {
        _il.Append(_il.Create(OpCodes.Ldc_I4, value));
        return this;
    }

    /// <summary>
    /// Adds a local variable and returns its index.
    /// </summary>
    public MethodBuilder AddLocal(TypeReference type, out int index)
    {
        var local = new VariableDefinition(type);
        _method.Body.Variables.Add(local);
        index = _method.Body.Variables.Count - 1;
        return this;
    }

    /// <summary>
    /// Adds a local variable by type name.
    /// </summary>
    public MethodBuilder AddLocal(string typeFullName, out int index)
    {
        var typeRef = CreateTypeReference(typeFullName);
        return AddLocal(typeRef, out index);
    }

    /// <summary>
    /// Emits store to local variable.
    /// </summary>
    public MethodBuilder EmitStloc(int index)
    {
        var instr = index switch
        {
            0 => _il.Create(OpCodes.Stloc_0),
            1 => _il.Create(OpCodes.Stloc_1),
            2 => _il.Create(OpCodes.Stloc_2),
            3 => _il.Create(OpCodes.Stloc_3),
            _ => _il.Create(OpCodes.Stloc, _method.Body.Variables[index])
        };
        _il.Append(instr);
        return this;
    }

    /// <summary>
    /// Emits load from local variable.
    /// </summary>
    public MethodBuilder EmitLdloc(int index)
    {
        var instr = index switch
        {
            0 => _il.Create(OpCodes.Ldloc_0),
            1 => _il.Create(OpCodes.Ldloc_1),
            2 => _il.Create(OpCodes.Ldloc_2),
            3 => _il.Create(OpCodes.Ldloc_3),
            _ => _il.Create(OpCodes.Ldloc, _method.Body.Variables[index])
        };
        _il.Append(instr);
        return this;
    }

    /// <summary>
    /// Emits a call to another method defined in the same assembly.
    /// </summary>
    public MethodBuilder EmitCallInternal(MethodDefinition targetMethod)
    {
        _il.Append(_il.Create(OpCodes.Call, targetMethod));
        return this;
    }

    /// <summary>
    /// Adds a method call instruction with parameter types.
    /// </summary>
    public MethodBuilder EmitCallWithParams(
        string declaringTypeFullName,
        string methodName,
        TypeReference? returnType,
        params TypeReference[] parameterTypes)
    {
        var typeRef = CreateTypeReference(declaringTypeFullName);
        var methodRef = new MethodReference(methodName, returnType ?? Module.TypeSystem.Void, typeRef)
        {
            HasThis = false
        };

        foreach (var paramType in parameterTypes)
        {
            methodRef.Parameters.Add(new ParameterDefinition(paramType));
        }

        _il.Append(_il.Create(OpCodes.Call, methodRef));
        return this;
    }

    /// <summary>
    /// Adds a parameter to the method.
    /// </summary>
    public MethodBuilder AddParameter(string name, TypeReference type)
    {
        _method.Parameters.Add(new ParameterDefinition(name, ParameterAttributes.None, type));
        return this;
    }

    /// <summary>
    /// Emits load argument instruction.
    /// </summary>
    public MethodBuilder EmitLdarg(int index)
    {
        var instr = index switch
        {
            0 => _il.Create(OpCodes.Ldarg_0),
            1 => _il.Create(OpCodes.Ldarg_1),
            2 => _il.Create(OpCodes.Ldarg_2),
            3 => _il.Create(OpCodes.Ldarg_3),
            _ => _il.Create(OpCodes.Ldarg, _method.Parameters[index])
        };
        _il.Append(instr);
        return this;
    }

    /// <summary>
    /// Emits pop instruction (discards top of stack).
    /// </summary>
    public MethodBuilder EmitPop()
    {
        _il.Append(_il.Create(OpCodes.Pop));
        return this;
    }

    /// <summary>
    /// Completes method with a ret instruction and returns to parent.
    /// </summary>
    public TypeBuilder EndMethod()
    {
        _il.Append(_il.Create(OpCodes.Ret));
        return _parent;
    }

    /// <summary>
    /// Returns to parent without adding ret (for incomplete methods).
    /// </summary>
    public TypeBuilder EndMethodNoRet() => _parent;

    private TypeReference CreateTypeReference(string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        var ns = lastDot > 0 ? fullName[..lastDot] : "";
        var name = lastDot > 0 ? fullName[(lastDot + 1)..] : fullName;

        return new TypeReference(ns, name, Module, Module.TypeSystem.CoreLibrary);
    }
}
