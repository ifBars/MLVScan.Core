using FluentAssertions;
using MLVScan.Core.Tests.TestUtilities;
using MLVScan.Models;
using MLVScan.Models.Rules;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Xunit;
using InstructionCollection = Mono.Collections.Generic.Collection<Mono.Cecil.Cil.Instruction>;

namespace MLVScan.Core.Tests.Unit.Rules;

public class ProcessStartRuleTests
{
    private readonly ProcessStartRule _rule = new();

    [Fact]
    public void RuleId_ReturnsProcessStartRule()
    {
        _rule.RuleId.Should().Be("ProcessStartRule");
    }

    [Fact]
    public void Severity_ReturnsCritical()
    {
        _rule.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void RequiresCompanionFinding_ReturnsFalse()
    {
        _rule.RequiresCompanionFinding.Should().BeFalse();
    }

    [Fact]
    public void DeveloperGuidance_IsProvided()
    {
        _rule.DeveloperGuidance.Should().NotBeNull();
        _rule.DeveloperGuidance!.IsRemediable.Should().BeTrue();
    }

    [Theory]
    [InlineData("System.Diagnostics.Process", "Start", true)]
    [InlineData("System.Diagnostics.ProcessStartInfo", "Start", true)] // ProcessStartInfo contains "Process"
    [InlineData("MyProcess", "Start", true)] // Contains "Process" and method is "Start"
    [InlineData("System.Diagnostics.Process", "Kill", false)]
    [InlineData("System.Diagnostics.Process", "WaitForExit", false)]
    [InlineData("System.IO.File", "Start", false)]
    public void IsSuspicious_VariousMethods_ReturnsExpected(string typeName, string methodName, bool expected)
    {
        var methodRef = MethodReferenceFactory.Create(typeName, methodName);

        var result = _rule.IsSuspicious(methodRef);

        result.Should().Be(expected);
    }

    [Fact]
    public void IsSuspicious_NullMethod_ReturnsFalse()
    {
        _rule.IsSuspicious(null!).Should().BeFalse();
    }

    [Fact]
    public void IsSuspicious_NullDeclaringType_ReturnsFalse()
    {
        var methodRef = MethodReferenceFactory.CreateWithNullType("Start");

        _rule.IsSuspicious(methodRef).Should().BeFalse();
    }

    [Fact]
    public void GetFindingDescription_WithStartInfoFileNameLiteral_IncludesTarget()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithDynamicStartInfoFileName_IncludesDynamicMarker()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldloc_0);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: <local V_0>");
    }

    [Fact]
    public void GetFindingDescription_WithPathCombineInSetFileName_ExtractsExecutableName()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:\\Tools");
        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Combine", new TypeReference("", "String", null, null), new TypeReference("System.IO", "Path", null, null))
        {
            Parameters =
            {
                new ParameterDefinition(new TypeReference("", "String", null, null)),
                new ParameterDefinition(new TypeReference("", "String", null, null))
            }
        });
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithFieldBackedFileName_ExtractsExecutableName()
    {
        var type = new TypeDefinition("Tests", "Holder", TypeAttributes.Public | TypeAttributes.Class, new TypeReference("", "Object", null, null));
        var field = new FieldDefinition("ytDlpExePath", FieldAttributes.Public | FieldAttributes.Static, new TypeReference("", "String", null, null));
        type.Fields.Add(field);

        var method = new MethodDefinition("TestMethod", MethodAttributes.Public | MethodAttributes.Static, new TypeReference("", "Void", null, null));
        type.Methods.Add(method);
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Stsfld, field);
        processor.Emit(OpCodes.Ldsfld, field);
        processor.Emit(OpCodes.Callvirt, new MethodReference("set_FileName", new TypeReference("", "Void", null, null), new TypeReference("System.Diagnostics", "ProcessStartInfo", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;
        var methodRef = new MethodReference("Start", new TypeReference("", "Boolean", null, null), new TypeReference("System.Diagnostics", "Process", null, null));

        string description = _rule.GetFindingDescription(methodRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    [Fact]
    public void GetFindingDescription_WithStartStringArguments_UsesFirstParameterAsTarget()
    {
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "yt-dlp.exe");
        processor.Emit(OpCodes.Ldstr, "--help");

        var startRef = new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null))
        {
            HasThis = false
        };
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        startRef.Parameters.Add(new ParameterDefinition(new TypeReference("", "String", null, null)));
        processor.Emit(OpCodes.Call, startRef);

        var instructions = method.Body.Instructions;
        int callIndex = instructions.Count - 1;

        string description = _rule.GetFindingDescription(startRef, instructions, callIndex);

        description.Should().Contain("Target: \"yt-dlp.exe\"");
    }

    #region ShouldSuppressFinding Tests

    [Fact]
    public void ShouldSuppressFinding_BareExplorerExe_ReturnsTrue()
    {
        // Arrange: Build IL for bare "explorer.exe" call
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\Some\\Path");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeWithPath_ReturnsFalse()
    {
        // Arrange: Build IL for "C:\\Windows\\explorer.exe" (should NOT suppress)
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:\\Windows\\explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeWithForwardSlash_ReturnsFalse()
    {
        // Arrange: Build IL for path with forward slash
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "C:/Windows/explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeWithPathCombine_ReturnsFalse()
    {
        // Arrange: Build IL for Path.Combine usage
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "SomeFolder");
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Combine", new TypeReference("", "String", null, null), new TypeReference("System.IO", "Path", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_CurrentProcessRestart_ReturnsTrue()
    {
        // Arrange: Build IL for restart pattern
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_MainModule", new TypeReference("", "ProcessModule", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_FileName", new TypeReference("", "String", null, null), new TypeReference("System.Diagnostics", "ProcessModule", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldSuppressFinding_ArbitraryExecutable_ReturnsFalse()
    {
        // Arrange: Build IL for arbitrary executable
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "malware.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_CmdExe_ReturnsFalse()
    {
        // Arrange: Build IL for cmd.exe
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "cmd.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_RestartWithStringManipulation_ReturnsFalse()
    {
        // Arrange: Build IL with restart pattern but then string manipulation
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Call, new MethodReference("GetCurrentProcess", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_MainModule", new TypeReference("", "ProcessModule", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));
        processor.Emit(OpCodes.Callvirt, new MethodReference("get_FileName", new TypeReference("", "String", null, null), new TypeReference("System.Diagnostics", "ProcessModule", null, null)));
        processor.Emit(OpCodes.Ldstr, " --arg");
        processor.Emit(OpCodes.Call, new MethodReference("Concat", new TypeReference("", "String", null, null), new TypeReference("System", "String", null, null)));
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ShouldSuppressFinding_ExplorerExeCaseInsensitive_ReturnsTrue()
    {
        // Arrange: Build IL with mixed case "Explorer.EXE"
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "Explorer.EXE");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, new MethodSignals());

        // Assert
        result.Should().BeTrue();
    }

    #endregion

    #region Security Tests - PATH Manipulation Attack

    /// <summary>
    /// SECURITY TEST: PATH manipulation attack vector
    /// If attacker modifies PATH to point to malicious explorer.exe, 
    /// Process.Start("explorer.exe") should NOT be suppressed.
    /// </summary>

    [Fact]
    public void ShouldSuppressFinding_WithEnvironmentVariableModification_ReturnsFalse()
    {
        // Arrange: Build IL that modifies PATH then calls explorer.exe
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        // Simulate: Environment.SetEnvironmentVariable("PATH", maliciousPath + ";" + currentPath)
        processor.Emit(OpCodes.Ldstr, "PATH");
        processor.Emit(OpCodes.Ldstr, "C:\\Malicious;C:\\Windows");
        processor.Emit(OpCodes.Call, new MethodReference("SetEnvironmentVariable", new TypeReference("", "Void", null, null), new TypeReference("System", "Environment", null, null)));
        
        // Now call explorer.exe (which would resolve to malicious version)
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Create MethodSignals with environment modification flag set
        var signals = new MethodSignals { HasEnvironmentVariableModification = true };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should NOT suppress because PATH was manipulated
        result.Should().BeFalse("Process.Start should NOT be suppressed when environment variables were modified (PATH manipulation attack)");
    }

    [Fact]
    public void ShouldSuppressFinding_NoEnvironmentModification_ReturnsTrue()
    {
        // Arrange: Normal explorer.exe call without PATH manipulation
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\SomePath");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // No environment modification
        var signals = new MethodSignals { HasEnvironmentVariableModification = false };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should suppress because no PATH manipulation
        result.Should().BeTrue("Process.Start should be suppressed when no environment modification detected");
    }

    #endregion

    #region Security Tests - Embedded Resource Extraction Attack

    /// <summary>
    /// SECURITY TEST: Embedded resource extraction attack vector
    /// If attacker embeds malicious explorer.exe as resource, extracts it via File.WriteAllBytes,
    /// then calls Process.Start("explorer.exe"), we should NOT suppress.
    /// Windows resolves bare filenames from current directory before PATH.
    /// </summary>

    [Fact]
    public void ShouldSuppressFinding_WithFileWrite_ReturnsFalse()
    {
        // Arrange: File write (extracting embedded resource) then Process.Start
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        // Simulate: File.WriteAllBytes("explorer.exe", maliciousBytes)
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldloc_0); // byte array from embedded resource
        processor.Emit(OpCodes.Call, new MethodReference("WriteAllBytes", new TypeReference("", "Void", null, null), new TypeReference("System.IO", "File", null, null)));
        
        // Now call explorer.exe (which would be the just-dropped malicious version)
        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // Create MethodSignals with file write flag set
        var signals = new MethodSignals { HasFileWrite = true };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should NOT suppress because file was written (could be embedded resource extraction)
        result.Should().BeFalse("Process.Start should NOT be suppressed when files were written (embedded resource attack)");
    }

    [Fact]
    public void ShouldSuppressFinding_NoFileWrite_ReturnsTrue()
    {
        // Arrange: Normal explorer.exe call without file writes
        var method = new MethodDefinition("TestMethod", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Ldstr, "C:\\SomePath");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // No file writes
        var signals = new MethodSignals { HasFileWrite = false };

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, signals);

        // Assert - Should suppress because no file writes detected
        result.Should().BeTrue("Process.Start should be suppressed when no file writes detected");
    }

    [Fact]
    public void ShouldSuppressFinding_CrossMethodFileWrite_ReturnsFalse()
    {
        // SECURITY TEST: Cross-method attack
        // Attacker writes file in MethodA, executes in MethodB
        // We should detect this via type-level signals
        var method = new MethodDefinition("Execute", MethodAttributes.Public, new TypeReference("", "Void", null, null));
        var processor = method.Body.GetILProcessor();

        processor.Emit(OpCodes.Ldstr, "explorer.exe");
        processor.Emit(OpCodes.Call, new MethodReference("Start", new TypeReference("", "Process", null, null), new TypeReference("System.Diagnostics", "Process", null, null)));

        var instructions = method.Body.Instructions;
        var callIndex = instructions.Count - 1;

        // This method has no file writes, but type-level signals show file writes in other methods
        var methodSignals = new MethodSignals { HasFileWrite = false };
        var typeSignals = new MethodSignals { HasFileWrite = true }; // File written in different method

        // Act
        var result = _rule.ShouldSuppressFinding(null!, instructions, callIndex, methodSignals, typeSignals);

        // Assert - Should NOT suppress because type has file writes (cross-method attack)
        result.Should().BeFalse("Process.Start should NOT be suppressed when type has file writes in other methods");
    }

    #endregion
}
