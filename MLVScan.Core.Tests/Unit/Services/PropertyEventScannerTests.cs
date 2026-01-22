using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Services;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;

namespace MLVScan.Core.Tests.Unit.Services;

public class PropertyEventScannerTests
{
    [Fact]
    public void Constructor_WithNullMethodScanner_ThrowsArgumentNullException()
    {
        var act = () => new PropertyEventScanner(null!, new ScanConfig());

        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("methodScanner");
    }

    [Fact]
    public void Constructor_WithNullConfig_UsesDefaultConfig()
    {
        var methodScanner = CreateMethodScanner();
        
        var act = () => new PropertyEventScanner(methodScanner, null!);

        act.Should().NotThrow();
    }

    [Fact]
    public void ScanProperties_WithAnalyzePropertyAccessorsDisabled_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = false };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithProperty();

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanProperties_WithNoProperties_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();
        
        var type = assembly.MainModule.Types[0];

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanProperties_WithPropertyGetter_ScansGetter()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousPropertyGetter();

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Description.Contains("property getter"));
    }

    [Fact]
    public void ScanProperties_WithPropertySetter_ScansSetter()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousPropertySetter();

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Description.Contains("property setter"));
    }

    [Fact]
    public void ScanProperties_WithBothGetterAndSetter_ScansBoth()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousProperty();

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().HaveCountGreaterThanOrEqualTo(2);
        findings.Should().Contain(f => f.Description.Contains("property getter"));
        findings.Should().Contain(f => f.Description.Contains("property setter"));
    }

    [Fact]
    public void ScanEvents_WithAnalyzePropertyAccessorsDisabled_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = false };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithEvent();

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanEvents_WithNoEvents_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();
        
        var type = assembly.MainModule.Types[0];

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanEvents_WithEventAddHandler_ScansAddHandler()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousEventAdd();

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Description.Contains("event add"));
    }

    [Fact]
    public void ScanEvents_WithEventRemoveHandler_ScansRemoveHandler()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousEventRemove();

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Description.Contains("event remove"));
    }

    [Fact]
    public void ScanEvents_WithEventInvokeHandler_ScansInvokeHandler()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousEventInvoke();

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().NotBeEmpty();
        findings.Should().Contain(f => f.Description.Contains("event invoke"));
    }

    [Fact]
    public void ScanProperties_IncludesPropertyNameInDescription()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousPropertyGetter();

        var findings = scanner.ScanProperties(type, type.FullName).ToList();

        findings.Should().Contain(f => f.Description.Contains("TestProperty"));
    }

    [Fact]
    public void ScanEvents_IncludesEventNameInDescription()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        var type = CreateTypeWithSuspiciousEventAdd();

        var findings = scanner.ScanEvents(type, type.FullName).ToList();

        findings.Should().Contain(f => f.Description.Contains("TestEvent"));
    }

    [Fact]
    public void ScanProperties_WithException_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        
        // Pass null type to trigger exception
        var findings = scanner.ScanProperties(null!, "TestType").ToList();

        findings.Should().BeEmpty();
    }

    [Fact]
    public void ScanEvents_WithException_ReturnsEmpty()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var scanner = new PropertyEventScanner(CreateMethodScanner(), config);
        
        // Pass null type to trigger exception
        var findings = scanner.ScanEvents(null!, "TestType").ToList();

        findings.Should().BeEmpty();
    }

    private MethodScanner CreateMethodScanner()
    {
        var config = new ScanConfig { AnalyzePropertyAccessors = true };
        var rules = RuleFactory.CreateDefaultRules();
        var signalTracker = new SignalTracker(config);
        var snippetBuilder = new CodeSnippetBuilder();
        var stringPatternDetector = new StringPatternDetector();
        var reflectionDetector = new ReflectionDetector(rules, signalTracker, stringPatternDetector, snippetBuilder);
        var localVariableAnalyzer = new LocalVariableAnalyzer(rules, signalTracker, config);
        var exceptionHandlerAnalyzer = new ExceptionHandlerAnalyzer(rules, signalTracker, snippetBuilder, config);
        var instructionAnalyzer = new InstructionAnalyzer(rules, signalTracker, reflectionDetector, 
                                                          stringPatternDetector, snippetBuilder, config, null);
        
        return new MethodScanner(rules, signalTracker, instructionAnalyzer, snippetBuilder, 
                                localVariableAnalyzer, exceptionHandlerAnalyzer, config);
    }

    private TypeDefinition CreateTypeWithProperty()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var property = new PropertyDefinition("TestProperty", PropertyAttributes.None, assembly.MainModule.TypeSystem.Int32);
        
        // Add getter
        var getter = new MethodDefinition("get_TestProperty", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.Int32);
        getter.Body = new MethodBody(getter);
        getter.Body.GetILProcessor().Emit(OpCodes.Ldc_I4_0);
        getter.Body.GetILProcessor().Emit(OpCodes.Ret);
        property.GetMethod = getter;
        type.Methods.Add(getter);
        
        type.Properties.Add(property);
        return type;
    }

    private TypeDefinition CreateTypeWithSuspiciousPropertyGetter()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var property = new PropertyDefinition("TestProperty", PropertyAttributes.None, assembly.MainModule.TypeSystem.String);
        
        // Add getter with suspicious call
        var getter = new MethodDefinition("get_TestProperty", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.String);
        getter.Body = new MethodBody(getter);
        var il = getter.Body.GetILProcessor();
        
        // Add suspicious reflection call
        var getTypeMethod = new MethodReference("GetType", assembly.MainModule.TypeSystem.Object, 
            new TypeReference("System", "Type", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary));
        il.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        il.Emit(OpCodes.Call, getTypeMethod);
        il.Emit(OpCodes.Ldnull);
        il.Emit(OpCodes.Ret);
        
        property.GetMethod = getter;
        type.Methods.Add(getter);
        type.Properties.Add(property);
        
        return type;
    }

    private TypeDefinition CreateTypeWithSuspiciousPropertySetter()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var property = new PropertyDefinition("TestProperty", PropertyAttributes.None, assembly.MainModule.TypeSystem.String);
        
        // Add setter with suspicious call
        var setter = new MethodDefinition("set_TestProperty", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.Void);
        setter.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.String));
        setter.Body = new MethodBody(setter);
        var il = setter.Body.GetILProcessor();
        
        var getTypeMethod = new MethodReference("GetType", assembly.MainModule.TypeSystem.Object, 
            new TypeReference("System", "Type", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary));
        il.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        il.Emit(OpCodes.Call, getTypeMethod);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        
        property.SetMethod = setter;
        type.Methods.Add(setter);
        type.Properties.Add(property);
        
        return type;
    }

    private TypeDefinition CreateTypeWithSuspiciousProperty()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var property = new PropertyDefinition("TestProperty", PropertyAttributes.None, assembly.MainModule.TypeSystem.String);
        
        // Add getter
        var getter = new MethodDefinition("get_TestProperty", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.String);
        getter.Body = new MethodBody(getter);
        var ilGetter = getter.Body.GetILProcessor();
        var getTypeMethod = new MethodReference("GetType", assembly.MainModule.TypeSystem.Object, 
            new TypeReference("System", "Type", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary));
        ilGetter.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        ilGetter.Emit(OpCodes.Call, getTypeMethod);
        ilGetter.Emit(OpCodes.Ldnull);
        ilGetter.Emit(OpCodes.Ret);
        property.GetMethod = getter;
        type.Methods.Add(getter);
        
        // Add setter
        var setter = new MethodDefinition("set_TestProperty", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.Void);
        setter.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.String));
        setter.Body = new MethodBody(setter);
        var ilSetter = setter.Body.GetILProcessor();
        ilSetter.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        ilSetter.Emit(OpCodes.Call, getTypeMethod);
        ilSetter.Emit(OpCodes.Pop);
        ilSetter.Emit(OpCodes.Ret);
        property.SetMethod = setter;
        type.Methods.Add(setter);
        
        type.Properties.Add(property);
        return type;
    }

    private TypeDefinition CreateTypeWithEvent()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var eventHandlerType = new TypeReference("System", "EventHandler", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary);
        var evt = new EventDefinition("TestEvent", EventAttributes.None, eventHandlerType);
        
        type.Events.Add(evt);
        return type;
    }

    private TypeDefinition CreateTypeWithSuspiciousEventAdd()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var eventHandlerType = new TypeReference("System", "EventHandler", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary);
        var evt = new EventDefinition("TestEvent", EventAttributes.None, eventHandlerType);
        
        var addMethod = new MethodDefinition("add_TestEvent", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.Void);
        addMethod.Parameters.Add(new ParameterDefinition(eventHandlerType));
        addMethod.Body = new MethodBody(addMethod);
        var il = addMethod.Body.GetILProcessor();
        
        var getTypeMethod = new MethodReference("GetType", assembly.MainModule.TypeSystem.Object, 
            new TypeReference("System", "Type", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary));
        il.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        il.Emit(OpCodes.Call, getTypeMethod);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        
        evt.AddMethod = addMethod;
        type.Methods.Add(addMethod);
        type.Events.Add(evt);
        
        return type;
    }

    private TypeDefinition CreateTypeWithSuspiciousEventRemove()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var eventHandlerType = new TypeReference("System", "EventHandler", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary);
        var evt = new EventDefinition("TestEvent", EventAttributes.None, eventHandlerType);
        
        var removeMethod = new MethodDefinition("remove_TestEvent", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.Void);
        removeMethod.Parameters.Add(new ParameterDefinition(eventHandlerType));
        removeMethod.Body = new MethodBody(removeMethod);
        var il = removeMethod.Body.GetILProcessor();
        
        var getTypeMethod = new MethodReference("GetType", assembly.MainModule.TypeSystem.Object, 
            new TypeReference("System", "Type", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary));
        il.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        il.Emit(OpCodes.Call, getTypeMethod);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        
        evt.RemoveMethod = removeMethod;
        type.Methods.Add(removeMethod);
        type.Events.Add(evt);
        
        return type;
    }

    private TypeDefinition CreateTypeWithSuspiciousEventInvoke()
    {
        var assembly = TestAssemblyBuilder.Create()
            .AddType("TestClass")
            .EndType()
            .Build();

        var type = assembly.MainModule.Types[0];
        var eventHandlerType = new TypeReference("System", "EventHandler", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary);
        var evt = new EventDefinition("TestEvent", EventAttributes.None, eventHandlerType);
        
        var invokeMethod = new MethodDefinition("invoke_TestEvent", 
            MethodAttributes.Public | MethodAttributes.SpecialName, 
            assembly.MainModule.TypeSystem.Void);
        invokeMethod.Body = new MethodBody(invokeMethod);
        var il = invokeMethod.Body.GetILProcessor();
        
        var getTypeMethod = new MethodReference("GetType", assembly.MainModule.TypeSystem.Object, 
            new TypeReference("System", "Type", assembly.MainModule, assembly.MainModule.TypeSystem.CoreLibrary));
        il.Emit(OpCodes.Ldstr, "System.Reflection.Assembly");
        il.Emit(OpCodes.Call, getTypeMethod);
        il.Emit(OpCodes.Pop);
        il.Emit(OpCodes.Ret);
        
        evt.InvokeMethod = invokeMethod;
        type.Methods.Add(invokeMethod);
        type.Events.Add(evt);
        
        return type;
    }
}
