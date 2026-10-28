using Mono.Cecil;
using Mono.Cecil.Cil;

namespace MLVScan.Models.Rules.Helpers;

/// <summary>
/// Proves the binding between a locally written restart script and a detached encoded launcher.
/// Only a bounded, straight-line IL subset is accepted. Unsupported operations retain normal blocking.
/// </summary>
internal sealed class RestartScriptAnalyzer
{
    private sealed class DirectoryValue;

    private sealed class PathValue(string leaf)
    {
        public string Leaf { get; } = leaf;
    }

    private sealed class Utf16Bytes(string text)
    {
        public string Text { get; } = text;
    }

    private sealed class StartInfo(string fileName, string arguments)
    {
        public string FileName { get; } = fileName;
        public string Arguments { get; } = arguments;
    }
    private enum SpecialValue { CurrentProcess, CurrentPid, UnicodeEncoding }

    private readonly Stack<object> _stack = new();
    private readonly Dictionary<int, object> _locals = new();
    private object? _writtenPath;
    private string? _writtenScript;
    private string? _encodedPayload;

    internal static bool IsConstrainedRestart(MethodDefinition method, int launchIndex)
        => TryGetBoundScript(method, launchIndex, out var script) && RestartScriptPattern.Matches(script);

    internal static bool TryGetBoundScript(MethodDefinition method, int launchIndex, out string script)
    {
        script = string.Empty;
        var instructions = method.Body.Instructions;
        if (launchIndex is < 1 or > 256 || instructions.Count > 512 ||
            instructions.Take(launchIndex).Any(i => i.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw) ||
            instructions.Any(i => i.Operand is Instruction target && target.Offset <= instructions[launchIndex].Offset ||
                                  i.Operand is Instruction[] targets && targets.Any(t => t.Offset <= instructions[launchIndex].Offset)) ||
            method.Body.ExceptionHandlers.Any(h => h.HandlerStart.Offset <= instructions[launchIndex].Offset || h.FilterStart != null))
            return false;

        var analysis = new RestartScriptAnalyzer();
        for (var index = 0; index < launchIndex; index++)
        {
            if (!analysis.Evaluate(instructions[index], method))
                return false;
        }

        var bound = instructions[launchIndex].Operand is MethodReference launch &&
               IsFrameworkCall(launch, "System.Diagnostics.Process", "Start") &&
               !launch.HasThis && launch.Parameters.Count == 1 &&
               launch.Parameters[0].ParameterType.FullName == "System.Diagnostics.ProcessStartInfo" &&
               analysis._stack.Count == 1 && analysis._stack.Peek() is StartInfo
               {
                   FileName: "powershell.exe",
                   Arguments: RestartScriptPattern.LauncherPrefix + RestartScriptPattern.EncodedCommand
               } && analysis._writtenPath != null &&
               analysis._encodedPayload == RestartScriptPattern.DetachedPrefix + RestartScriptPattern.ScriptPath + RestartScriptPattern.DetachedSuffix;
        if (!bound || analysis._writtenScript == null) return false;
        script = analysis._writtenScript;
        return true;
    }

    private bool Evaluate(Instruction instruction, MethodDefinition owner)
    {
        var code = instruction.OpCode.Code;
        if (code == Code.Nop) return true;
        if (code == Code.Ldstr)
        {
            var text = (string)instruction.Operand;
            if (text.Length > 8192 || text.IndexOfAny(['\u0001', '\u0002']) >= 0) return false;
            _stack.Push(text);
            return true;
        }

        if (TryGetInteger(instruction, out var number))
        {
            _stack.Push(number);
            return true;
        }

        if (TryGetLocal(instruction, out var local, out var store))
        {
            if (store)
            {
                if (!_stack.TryPop(out var value)) return false;
                _locals[local] = value;
                return true;
            }
            if (!_locals.TryGetValue(local, out var stored)) return false;
            _stack.Push(stored);
            return true;
        }

        if (code == Code.Dup && _stack.TryPeek(out var duplicate))
        {
            _stack.Push(duplicate);
            return true;
        }

        if (code == Code.Newarr && instruction.Operand is TypeReference { FullName: "System.String" } &&
            _stack.TryPop(out var length) && length is int size and > 0 and <= 32)
        {
            _stack.Push(new object?[size]);
            return true;
        }

        if (code == Code.Stelem_Ref && _stack.Count >= 3)
        {
            var value = _stack.Pop();
            var index = _stack.Pop();
            var array = _stack.Pop();
            if (array is not object?[] items || index is not int item || item < 0 || item >= items.Length) return false;
            items[item] = value;
            return true;
        }

        return code is Code.Call or Code.Callvirt or Code.Newobj && instruction.Operand is MethodReference call &&
               EvaluateCall(call, code == Code.Newobj, owner);
    }

    private bool EvaluateCall(MethodReference call, bool constructor, MethodDefinition owner)
    {
        var count = call.Parameters.Count + (call.HasThis && !constructor ? 1 : 0);
        if (_stack.Count < count || count > 32) return false;
        var args = new object[count];
        for (var index = count - 1; index >= 0; index--) args[index] = _stack.Pop();

        object? result = null;
        if (IsFrameworkCall(call, "System.Diagnostics.Process", "GetCurrentProcess") && args.Length == 0)
            result = SpecialValue.CurrentProcess;
        else if (IsFrameworkCall(call, "System.Diagnostics.Process", "get_Id") && args is [SpecialValue.CurrentProcess])
            result = SpecialValue.CurrentPid;
        else if (IsFrameworkCall(call, "System.Int32", "ToString") && args is [SpecialValue.CurrentPid])
            result = RestartScriptPattern.CurrentPid;
        else if (IsFrameworkCall(call, "System.String", "Concat"))
        {
            var parts = args is [object?[] array] ? array : args;
            if (parts.Any(p => p is not string)) return false;
            var text = string.Concat(parts.Cast<string>());
            if (text.Length > 8192) return false;
            result = text;
        }
        else if (IsFrameworkCall(call, "System.String", "Replace") && args is [var path, "'", "''"])
            result = EscapePath(path);
        else if (IsFrameworkCall(call, "System.IO.Path", "Combine") && args is [var root, string leaf] &&
                 root is DirectoryValue or PathValue && IsLeaf(leaf))
            result = new PathValue(leaf);
        else if (IsFrameworkCall(call, "System.IO.File", "WriteAllText") && args is [var output, string script])
        {
            if (_writtenPath != null || !IsScriptPath(output)) return false;
            _writtenPath = output;
            _writtenScript = script;
            return true;
        }
        else if (IsFrameworkCall(call, "System.Text.Encoding", "get_Unicode") && args.Length == 0)
            result = SpecialValue.UnicodeEncoding;
        else if (IsFrameworkCall(call, "System.Text.Encoding", "GetBytes") && args is [SpecialValue.UnicodeEncoding, string text])
            result = new Utf16Bytes(text);
        else if (IsFrameworkCall(call, "System.Convert", "ToBase64String") && args is [Utf16Bytes bytes] && _encodedPayload == null)
        {
            _encodedPayload = bytes.Text;
            result = RestartScriptPattern.EncodedCommand;
        }
        else if (constructor && IsFrameworkCall(call, "System.Diagnostics.ProcessStartInfo", ".ctor") && args is [string target, string arguments])
            result = new StartInfo(target, arguments);
        else if ((IsFrameworkCall(call, "System.Diagnostics.ProcessStartInfo", "set_UseShellExecute") ||
                  IsFrameworkCall(call, "System.Diagnostics.ProcessStartInfo", "set_CreateNoWindow")) && args is [StartInfo, int flag] && flag is 0 or 1)
            return true;
        else if (args.Length == 0 && TryGetDirectory(call, owner, out var directory))
            result = directory;

        if (result == null) return false;
        _stack.Push(result);
        return true;
    }

    private string? EscapePath(object path)
    {
        if (_writtenPath != null && Equals(path, _writtenPath)) return RestartScriptPattern.ScriptPath;
        if (path is PathValue { Leaf: var leaf } && leaf.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
            return RestartScriptPattern.LogPath;
        return path is DirectoryValue or PathValue ? RestartScriptPattern.DirectoryPath : null;
    }

    private static bool TryGetDirectory(MethodReference call, MethodDefinition owner, out object? directory)
    {
        directory = null;
        if (call.HasThis || call.Parameters.Count != 0 || call.ReturnType.FullName != "System.String") return false;
        // External directory providers remain opaque data, only usable in escaped literal path positions.
        if (call.DeclaringType.Scope is AssemblyNameReference && call.Name.StartsWith("get_", StringComparison.Ordinal) &&
            call.Name.EndsWith("Directory", StringComparison.Ordinal))
        {
            directory = new DirectoryValue();
            return true;
        }

        if (call.DeclaringType.Scope != owner.Module || call.Resolve() is not { HasBody: true } provider) return false;
        var body = provider.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
        if (body.Length != 4 || body[0].OpCode.Code != Code.Call || body[0].Operand is not MethodReference getter ||
            getter.DeclaringType.Scope is not AssemblyNameReference || !TryGetDirectory(getter, owner, out _) ||
            body[1].OpCode.Code != Code.Ldstr || body[1].Operand is not string leaf || !IsLeaf(leaf) ||
            body[2].OpCode.Code != Code.Call || body[2].Operand is not MethodReference combine ||
            !IsFrameworkCall(combine, "System.IO.Path", "Combine") || combine.Parameters.Count != 2 || body[3].OpCode.Code != Code.Ret)
            return false;
        directory = new PathValue(leaf);
        return true;
    }

    private static bool IsLeaf(string leaf) => leaf.Length is > 0 and <= 128 && leaf is not "." and not ".." &&
        leaf.All(c => (c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9') || c is '_' or '-' or '.' or ' ');

    private static bool IsScriptPath(object path) => path switch
    {
        PathValue p => p.Leaf.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase),
        string s => s.Length is > 7 and < 260 && (s[0] is >= 'a' and <= 'z' or >= 'A' and <= 'Z') && s[1] == ':' && s[2] == '\\' &&
                    s.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) &&
                    s[3..].Split('\\').All(IsLeaf),
        _ => false
    };

    private static bool IsFrameworkCall(MethodReference call, string type, string name) =>
        InstructionValueResolver.IsTrustedFrameworkMethod(call, type, name) ||
        call.DeclaringType.FullName == type && call.Name == name &&
        call.DeclaringType.Scope is AssemblyNameReference { Name: "System.Private.CoreLib" };

    private static bool TryGetInteger(Instruction instruction, out int value)
    {
        value = instruction.OpCode.Code switch
        {
            Code.Ldc_I4_M1 => -1,
            >= Code.Ldc_I4_0 and <= Code.Ldc_I4_8 => instruction.OpCode.Code - Code.Ldc_I4_0,
            Code.Ldc_I4 => (int)instruction.Operand,
            Code.Ldc_I4_S => (sbyte)instruction.Operand,
            _ => int.MinValue
        };
        return value != int.MinValue;
    }

    private static bool TryGetLocal(Instruction instruction, out int index, out bool store)
    {
        var code = instruction.OpCode.Code;
        store = code is Code.Stloc or Code.Stloc_S or >= Code.Stloc_0 and <= Code.Stloc_3;
        index = code switch
        {
            >= Code.Ldloc_0 and <= Code.Ldloc_3 => code - Code.Ldloc_0,
            >= Code.Stloc_0 and <= Code.Stloc_3 => code - Code.Stloc_0,
            Code.Ldloc or Code.Ldloc_S or Code.Ldloca or Code.Ldloca_S or Code.Stloc or Code.Stloc_S => ((VariableDefinition)instruction.Operand).Index,
            _ => -1
        };
        return index >= 0;
    }
}
